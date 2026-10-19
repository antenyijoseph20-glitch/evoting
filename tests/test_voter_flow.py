"""End-to-end voter flow and its guard rails."""
import security as sec


def bearer(token):
    return {"Authorization": "Bearer " + token}


def cast(client, token, election="PRESIDENTIAL", party="APC"):
    return client.post("/api/v1/ballot/cast", headers=bearer(token),
                       json={"election_type": election, "party_code": party})


def test_full_flow_and_receipt(client, voter, sms, set_election, auth):
    set_election("PRESIDENTIAL", "OPEN")
    verify = client.post("/api/v1/auth/verify", json={"nin": voter["nin"], "vin": voter["vin"]})
    assert verify.status_code == 200, verify.text
    # the phone is masked in the response, never echoed in full
    assert verify.json()["phone"] != voter["phone"]
    assert voter["phone"][-3:] in verify.json()["phone"]
    assert sms["calls"] == 1
    assert sms["otp"].isdigit() and len(sms["otp"]) == 6

    token = verify.json()["session_token"]
    assert client.post("/api/v1/auth/verify-otp", headers=auth(token),
                       json={"otp_code": sms["otp"]}).status_code == 200
    face = client.post("/api/v1/biometric/verify-face", headers=auth(token),
                       files={"file": ("face.jpg", b"not-a-real-jpeg", "image/jpeg")})
    assert face.status_code == 200, face.text

    response = cast(client, token)
    assert response.status_code == 200, response.text
    receipt = response.json()["receipt"]
    assert len(receipt["block_hash"]) == 64
    assert receipt["election_type"] == "PRESIDENTIAL"

    proof = client.get("/api/v1/receipt/" + receipt["block_hash"])
    assert proof.status_code == 200
    data = proof.json()
    assert data["found"] is True
    assert data["block"]["block_index"] == receipt["block_index"]
    assert data["chain"]["valid"] is True
    # no voter identity is linked to a vote
    assert "voter_id" not in data["block"]
    assert "voter_hash" not in str(data["block"])


def test_double_voting_is_rejected(client, voter, sms, set_election, accredit):
    set_election("PRESIDENTIAL", "OPEN")
    token = accredit(voter)
    assert cast(client, token).status_code == 200
    assert cast(client, token, party="LP").status_code == 409


def test_vote_rejected_unless_election_open(client, voter, sms, set_election, accredit):
    token = accredit(voter)
    assert cast(client, token).status_code == 403  # PENDING
    set_election("PRESIDENTIAL", "CLOSED")
    assert cast(client, token).status_code == 403


def test_invalid_party_or_election(client, voter, sms, set_election, accredit):
    set_election("PRESIDENTIAL", "OPEN")
    token = accredit(voter)
    assert cast(client, token, party="XYZ").status_code == 400
    assert cast(client, token, election="NOT_REAL", party="APC").status_code == 400


def test_cannot_cast_before_accreditation(client, voter, sms, set_election, start_session, auth):
    set_election("PRESIDENTIAL", "OPEN")
    token = start_session(voter)
    assert cast(client, token).status_code == 403  # OTP not yet verified
    response = client.post("/api/v1/auth/verify-otp", headers=auth(token),
                           json={"otp_code": sms["otp"]})
    assert response.status_code == 200
    assert cast(client, token).status_code == 403  # face not yet verified


def test_face_requires_otp(client, voter, sms, start_session, auth):
    token = start_session(voter)
    response = client.post("/api/v1/biometric/verify-face", headers=auth(token),
                           files={"file": ("face.jpg", b"x", "image/jpeg")})
    assert response.status_code == 403


def test_otp_attempt_limit(client, voter, sms, start_session, auth):
    token = start_session(voter)
    for _ in range(3):
        assert client.post("/api/v1/auth/verify-otp", headers=auth(token),
                           json={"otp_code": "000000"}).status_code == 401
    # even the right OTP is refused once the attempt budget is exhausted
    response = client.post("/api/v1/auth/verify-otp", headers=auth(token),
                           json={"otp_code": sms["otp"]})
    assert response.status_code == 401
    assert "too many" in response.json()["detail"].lower()


def test_face_attempt_limit(client, voter, sms, monkeypatch, start_session, auth):
    token = start_session(voter)
    assert client.post("/api/v1/auth/verify-otp", headers=auth(token),
                       json={"otp_code": sms["otp"]}).status_code == 200
    monkeypatch.setattr(sec, "face_check", lambda data: False)
    for _ in range(3):
        assert client.post("/api/v1/biometric/verify-face", headers=auth(token),
                           files={"file": ("face.jpg", b"x", "image/jpeg")}).status_code == 422
    response = client.post("/api/v1/biometric/verify-face", headers=auth(token),
                           files={"file": ("face.jpg", b"x", "image/jpeg")})
    assert response.status_code == 422
    assert "too many" in response.json()["detail"].lower()


def test_unregistered_voter_is_rejected(client, sms):
    response = client.post("/api/v1/auth/verify",
                           json={"nin": "99999999999", "vin": "ZZ99999999"})
    assert response.status_code == 401
    assert sms["calls"] == 0


def test_sms_delivery_failure_leaves_no_usable_session(client, voter, monkeypatch):
    import db

    def boom(phone, otp):
        raise sec.SmsDeliveryError("gateway down")

    monkeypatch.setattr(sec, "send_sms", boom)
    response = client.post("/api/v1/auth/verify",
                           json={"nin": voter["nin"], "vin": voter["vin"]})
    assert response.status_code == 503
    with db.read() as c:
        sessions = c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        attempts = c.execute("SELECT COUNT(*) FROM voter_attempts").fetchone()[0]
    assert sessions == 0  # the voter can retry immediately
    assert attempts == 1  # but the attempt still counts against the hourly limit


def test_expired_session_is_rejected(client, voter, sms, set_election, accredit, auth):
    import db
    set_election("PRESIDENTIAL", "OPEN")
    token = accredit(voter)
    with db.tx() as c:
        c.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'")
    assert cast(client, token).status_code == 401


def test_verify_is_rate_limited(client):
    for _ in range(10):
        response = client.post("/api/v1/auth/verify",
                               json={"nin": "99999999999", "vin": "ZZ99999999"})
        assert response.status_code == 401
    response = client.post("/api/v1/auth/verify",
                           json={"nin": "99999999999", "vin": "ZZ99999999"})
    assert response.status_code == 429


def test_per_voter_verification_limit(client, voter, sms):
    body = {"nin": voter["nin"], "vin": voter["vin"]}
    for _ in range(5):  # each round replaces the live session but still counts
        response = client.post("/api/v1/auth/verify", json=body)
        assert response.status_code == 200, response.text
    response = client.post("/api/v1/auth/verify", json=body)
    assert response.status_code == 429
    assert "too many attempts" in response.json()["detail"].lower()


def test_receipt_lookup_validation(client):
    assert client.get("/api/v1/receipt/not-a-hash").status_code == 400
    assert client.get("/api/v1/receipt/" + "a" * 64).status_code == 404
