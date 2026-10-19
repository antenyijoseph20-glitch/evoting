"""Admin authentication and role separation."""

VOTER_BODY = {"nin": "12345678901", "vin": "NG12345678",
              "polling_unit_code": "PU-001", "phone_number": "+2348012345678"}


def test_requests_require_a_session(client, auth):
    assert client.get("/admin/me").status_code == 401
    assert client.get("/admin/me", headers=auth("not-a-real-token")).status_code == 401
    assert client.get("/admin/stats").status_code == 401


def test_login_me_and_logout(client, staff, auth):
    response = client.post("/admin/login",
                           json={"username": "alice", "password": staff["password"]})
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    assert response.json()["role"] == "ADMIN"

    me = client.get("/admin/me", headers=auth(token))
    assert me.status_code == 200
    assert me.json() == {"username": "alice", "role": "ADMIN"}

    assert client.post("/admin/logout", headers=auth(token)).status_code == 200
    assert client.get("/admin/me", headers=auth(token)).status_code == 401


def test_login_failure_is_audited(client, staff):
    assert client.post("/admin/login",
                       json={"username": "alice", "password": "wrong"}).status_code == 401
    assert client.post("/admin/login",
                       json={"username": "nobody", "password": "wrong"}).status_code == 401
    import db
    with db.read() as c:
        actions = [r["action"] for r in c.execute("SELECT action FROM admin_audit")]
    assert actions.count("LOGIN_FAILED") == 2


def test_registrar_scope(client, staff, auth):
    headers = auth(staff["tokens"]["REGISTRAR"])
    assert client.post("/admin/voters", headers=headers, json=VOTER_BODY).status_code == 200
    listed = client.get("/admin/voters", headers=headers)
    assert listed.status_code == 200
    voter = listed.json()["voters"][0]
    assert voter["polling_unit_code"] == VOTER_BODY["polling_unit_code"]
    assert len(voter["reference"]) == 12
    assert VOTER_BODY["nin"] not in str(voter)
    assert VOTER_BODY["vin"] not in str(voter)
    assert VOTER_BODY["phone_number"] not in str(voter)

    # registrar cannot change election state, read the audit trail, or review results
    assert client.post("/admin/elections/PRESIDENTIAL/open", headers=headers).status_code == 403
    assert client.get("/admin/audit", headers=headers).status_code == 403
    assert client.get("/admin/officers", headers=headers).status_code == 403


def test_auditor_can_read_but_not_write(client, staff, auth):
    headers = auth(staff["tokens"]["AUDITOR"])
    assert client.get("/admin/stats", headers=headers).status_code == 200
    assert client.get("/admin/results", headers=headers).status_code == 200
    assert client.get("/admin/audit", headers=headers).status_code == 200
    assert client.get("/admin/audit/verify-chain", headers=headers).status_code == 200

    assert client.post("/admin/voters", headers=headers, json=VOTER_BODY).status_code == 403
    assert client.post("/admin/elections/PRESIDENTIAL/open", headers=headers).status_code == 403
    assert client.post("/admin/audit/checkpoint", headers=headers).status_code == 403


def test_admin_can_open_and_close_once(client, staff, auth):
    headers = auth(staff["tokens"]["ADMIN"])
    assert client.post("/admin/elections/PRESIDENTIAL/open", headers=headers).status_code == 200
    # PENDING -> OPEN only once
    assert client.post("/admin/elections/PRESIDENTIAL/open", headers=headers).status_code == 409
    assert client.post("/admin/elections/PRESIDENTIAL/close", headers=headers).status_code == 200
    # CLOSED cannot be reopened
    assert client.post("/admin/elections/PRESIDENTIAL/open", headers=headers).status_code == 409
    assert client.post("/admin/elections/PRESIDENTIAL/close", headers=headers).status_code == 409


def test_admin_voter_registration_duplicate(client, staff, auth):
    headers = auth(staff["tokens"]["ADMIN"])
    assert client.post("/admin/voters", headers=headers, json=VOTER_BODY).status_code == 200
    assert client.post("/admin/voters", headers=headers, json=VOTER_BODY).status_code == 409


def test_officer_registration_rules(client, staff, auth):
    headers = auth(staff["tokens"]["ADMIN"])
    public_key = "ab" * 32
    base = {"officer_id": "PO-001", "name": "Presiding Officer", "role": "PRESIDING_OFFICER",
            "polling_unit_code": "PU-001", "party_code": None, "public_key": public_key}
    assert client.post("/admin/officers", headers=headers, json=base).status_code == 200
    assert client.post("/admin/officers", headers=headers, json=base).status_code == 409

    agent = dict(base, officer_id="AG-APC-1", role="PARTY_AGENT", party_code=None)
    assert client.post("/admin/officers", headers=headers, json=agent).status_code == 422
    agent["party_code"] = "APC"
    assert client.post("/admin/officers", headers=headers, json=agent).status_code == 200

    assert client.post("/admin/officers/PO-001/deactivate", headers=headers).status_code == 200
    officers = client.get("/admin/officers", headers=headers).json()["officers"]
    assert {o["officer_id"]: o["active"] for o in officers} == {"PO-001": 0, "AG-APC-1": 1}
    assert client.post("/admin/officers/PO-001/activate", headers=headers).status_code == 200


def test_expired_admin_session(client, staff, auth):
    import db
    token = staff["tokens"]["AUDITOR"]
    with db.tx() as c:
        c.execute("UPDATE admin_sessions SET expires_at='2000-01-01T00:00:00+00:00'")
    assert client.get("/admin/me", headers=auth(token)).status_code == 401
    assert client.get("/admin/stats", headers=auth(token)).status_code == 401
