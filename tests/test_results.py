"""Signed polling-unit results: submission, review, tally, proofs and export."""
import json
from datetime import datetime, timezone

import merkle
import signing as sg
import verify_offline


def bearer(token):
    return {"Authorization": "Bearer " + token}


def make_payload(pu, scores, accredited, rejected=0, election="PRESIDENTIAL"):
    return {
        "v": 1,
        "election_type": election,
        "polling_unit_code": pu,
        "accredited": accredited,
        "rejected": rejected,
        "scores": scores,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }


def submit(client, key, officer_id, payload):
    return client.post("/results/submit", json={
        "payload": payload, "officer_id": officer_id,
        "signature": sg.sign(key, sg.sheet_message(payload)),
    })


def countersign(client, key, officer_id, election, pu, payload_hash):
    return client.post(f"/results/{election}/{pu}/countersign", json={
        "officer_id": officer_id,
        "signature": sg.sign(key, sg.countersign_message(payload_hash)),
    })


def make_checkpoint(client, token):
    response = client.post("/results/checkpoint", headers=bearer(token))
    assert response.status_code == 200, response.text
    return response.json()


def test_submission_is_rejected_before_the_election_opens(client, set_election, make_officer):
    key = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    response = submit(client, key, "PO-001", make_payload("PU-001", {"APC": 5}, 10))
    assert response.status_code == 403


def test_signature_polling_unit_and_validation_guards(client, set_election, make_officer):
    set_election("PRESIDENTIAL", "OPEN")
    key = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    other = make_officer("PO-002", "PRESIDING_OFFICER", "PU-002")

    good = make_payload("PU-001", {"APC": 5, "LP": 3}, 10)
    assert submit(client, key, "PO-001", good).status_code == 200

    # duplicate polling unit + election
    assert submit(client, key, "PO-001", good).status_code == 409

    # an officer may only submit for its own polling unit
    wrong_pu = make_payload("PU-003", {"APC": 1}, 10)
    assert submit(client, key, "PO-001", wrong_pu).status_code == 403

    # forged signature: correct officer id, another officer's key
    forged = make_payload("PU-002", {"APC": 1}, 10)
    assert submit(client, key, "PO-002", forged).status_code == 401

    # malformed payloads
    assert submit(client, other, "PO-002",
                  make_payload("PU-002", {"XYZ": 1}, 10)).status_code == 422
    assert submit(client, other, "PO-002",
                  make_payload("PU-002", {"APC": -1}, 10)).status_code == 422

    # overvote is recorded and flagged, never silently dropped
    over = submit(client, other, "PO-002", make_payload("PU-002", {"APC": 8, "LP": 8}, 10))
    assert over.status_code == 200
    assert over.json()["flags"] == ["OVERVOTE"]


def test_countersignature(client, set_election, make_officer):
    set_election("PRESIDENTIAL", "OPEN")
    po = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    agent = make_officer("AG-APC-1", "PARTY_AGENT", "PU-001", "APC")
    other_agent = make_officer("AG-LP-1", "PARTY_AGENT", "PU-001", "LP")

    response = submit(client, po, "PO-001", make_payload("PU-001", {"APC": 5}, 10))
    payload_hash = response.json()["payload_hash"]

    ok = countersign(client, agent, "AG-APC-1", "PRESIDENTIAL", "PU-001", payload_hash)
    assert ok.status_code == 200
    assert ok.json()["party"] == "APC"

    dup = countersign(client, agent, "AG-APC-1", "PRESIDENTIAL", "PU-001", payload_hash)
    assert dup.status_code == 409

    bad = countersign(client, other_agent, "AG-APC-1", "PRESIDENTIAL", "PU-001", payload_hash)
    assert bad.status_code == 401

    sheet = client.get("/results/sheet/PRESIDENTIAL/PU-001")
    assert len(sheet.json()["countersignatures"]) == 1


def test_flagged_sheet_review_accept(client, set_election, make_officer, staff):
    set_election("PRESIDENTIAL", "OPEN")
    po1 = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    po2 = make_officer("PO-002", "PRESIDING_OFFICER", "PU-002")
    assert submit(client, po1, "PO-001", make_payload("PU-001", {"APC": 4, "LP": 2}, 10)).status_code == 200
    flagged = submit(client, po2, "PO-002", make_payload("PU-002", {"APC": 9, "LP": 9}, 10))
    assert flagged.json()["flags"] == ["OVERVOTE"]

    set_election("PRESIDENTIAL", "CLOSED")
    tally = client.get("/results/tally/PRESIDENTIAL").json()
    assert tally["sheets_counted"] == 1
    assert [f["polling_unit_code"] for f in tally["flagged_excluded"]] == ["PU-002"]

    headers = bearer(staff["tokens"]["ADMIN"])
    review = client.post("/admin/results/PRESIDENTIAL/PU-002/review", headers=headers,
                         json={"resolution": "ACCEPT", "note": "manual recount matched"})
    assert review.status_code == 200, review.text
    assert review.json()["review_status"] == "ACCEPTED"

    tally = client.get("/results/tally/PRESIDENTIAL").json()
    assert tally["sheets_counted"] == 2
    assert tally["totals"] == {"APC": 13, "LP": 11}
    assert [f["polling_unit_code"] for f in tally["flagged_accepted"]] == ["PU-002"]
    assert tally["flagged_excluded"] == []

    # one-shot review
    again = client.post("/admin/results/PRESIDENTIAL/PU-002/review", headers=headers,
                        json={"resolution": "VOID", "note": ""})
    assert again.status_code == 409
    # an unflagged sheet cannot be reviewed
    clean = client.post("/admin/results/PRESIDENTIAL/PU-001/review", headers=headers,
                        json={"resolution": "VOID", "note": ""})
    assert clean.status_code == 409

    audit = client.get("/admin/audit", headers=headers).json()["audit"]
    assert any(entry["action"] == "RESULT_REVIEW_ACCEPT" for entry in audit)


def test_flagged_sheet_review_void(client, set_election, make_officer, staff):
    set_election("PRESIDENTIAL", "OPEN")
    po = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    assert submit(client, po, "PO-001", make_payload("PU-001", {"APC": 20}, 10)).status_code == 200
    set_election("PRESIDENTIAL", "CLOSED")

    headers = bearer(staff["tokens"]["ADMIN"])
    assert client.post("/admin/results/PRESIDENTIAL/PU-001/review", headers=headers,
                       json={"resolution": "VOID", "note": "ballot box not accounted for"}).status_code == 200

    tally = client.get("/results/tally/PRESIDENTIAL").json()
    assert tally["sheets_counted"] == 0
    assert tally["totals"] == {}
    assert [v["polling_unit_code"] for v in tally["voided"]] == ["PU-001"]


def test_public_release_policy(client, set_election, make_officer):
    set_election("PRESIDENTIAL", "OPEN")
    po = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    assert submit(client, po, "PO-001", make_payload("PU-001", {"APC": 5}, 10)).status_code == 200

    sheet = client.get("/results/sheet/PRESIDENTIAL/PU-001").json()
    assert sheet["released"] is False
    assert sheet["sheet"]["payload"] is None
    assert client.get("/results/tally/PRESIDENTIAL").status_code == 403
    assert client.get("/results/export").status_code == 403

    status = client.get("/results/status/PRESIDENTIAL").json()
    assert status["sheets_submitted"] == 1
    assert "totals" not in status

    set_election("PRESIDENTIAL", "CLOSED")
    assert client.get("/results/sheet/PRESIDENTIAL/PU-001").json()["released"] is True
    assert client.get("/results/tally/PRESIDENTIAL").status_code == 200
    assert client.get("/results/export").status_code == 200


def test_checkpoint_and_inclusion_proof(client, set_election, make_officer, staff):
    set_election("PRESIDENTIAL", "OPEN")
    for i in (1, 2, 3):
        key = make_officer(f"PO-00{i}", "PRESIDING_OFFICER", f"PU-00{i}")
        assert submit(client, key, f"PO-00{i}",
                      make_payload(f"PU-00{i}", {"APC": i}, 10)).status_code == 200

    checkpoint = make_checkpoint(client, staff["tokens"]["ADMIN"])
    assert checkpoint["tree_size"] == 3
    assert len(checkpoint["root"]) == 64

    public_cp = client.get("/results/checkpoint").json()
    assert public_cp["checkpoint"]["root"] == checkpoint["root"]

    proof = client.get("/results/proof/PRESIDENTIAL/PU-002").json()
    assert merkle.verify_proof(bytes.fromhex(proof["leaf"]), proof["leaf_index"], proof["tree_size"],
                               [bytes.fromhex(h) for h in proof["path"]],
                               bytes.fromhex(proof["root"]))
    assert not merkle.verify_proof(b"\x00" * 32, proof["leaf_index"], proof["tree_size"],
                                   [bytes.fromhex(h) for h in proof["path"]],
                                   bytes.fromhex(proof["root"]))

    stats = client.get("/admin/stats", headers=bearer(staff["tokens"]["AUDITOR"])).json()
    assert stats["result_checkpoint"]["tree_size"] == 3
    assert stats["sheet_chain"]["valid"] is True


def test_export_and_offline_verification(client, set_election, make_officer, staff, tmp_path):
    set_election("PRESIDENTIAL", "OPEN")
    po1 = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    po2 = make_officer("PO-002", "PRESIDING_OFFICER", "PU-002")
    agent = make_officer("AG-APC-1", "PARTY_AGENT", "PU-001", "APC")
    first = submit(client, po1, "PO-001", make_payload("PU-001", {"APC": 11, "LP": 7}, 20))
    assert submit(client, po2, "PO-002", make_payload("PU-002", {"APC": 3, "LP": 12}, 20)).status_code == 200
    assert countersign(client, agent, "AG-APC-1", "PRESIDENTIAL", "PU-001",
                       first.json()["payload_hash"]).status_code == 200
    make_checkpoint(client, staff["tokens"]["ADMIN"])
    set_election("PRESIDENTIAL", "CLOSED")

    export = client.get("/results/export")
    assert export.status_code == 200
    path = tmp_path / "export.json"
    path.write_text(json.dumps(export.json()))
    assert verify_offline.main(str(path)) == 0

    tampered = export.json()
    tampered["sheets"][0]["payload"] = tampered["sheets"][0]["payload"].replace('"APC":11', '"APC":99')
    bad_path = tmp_path / "tampered.json"
    bad_path.write_text(json.dumps(tampered))
    assert verify_offline.main(str(bad_path)) == 1


def test_offline_verifier_rejects_metadata_swap(client, set_election, make_officer, tmp_path):
    set_election("PRESIDENTIAL", "OPEN")
    po = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    assert submit(client, po, "PO-001", make_payload("PU-001", {"APC": 5}, 10)).status_code == 200
    set_election("PRESIDENTIAL", "CLOSED")

    export = client.get("/results/export").json()
    # The signed payload still says PU-001; the row metadata is what the server tallies.
    export["sheets"][0]["polling_unit_code"] = "PU-999"
    path = tmp_path / "swapped.json"
    path.write_text(json.dumps(export))
    assert verify_offline.main(str(path)) == 1
