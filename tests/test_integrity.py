"""Tamper detection: checkpoints and stored sheets are verified, not merely stored."""
import json
from datetime import datetime, timezone

import db
import audit_log as alog
import ledger
import signing as sg
import verify_offline


def bearer(token):
    return {"Authorization": "Bearer " + token}


def seed_blocks(n, election="PRESIDENTIAL", pu="PU-001"):
    head = ledger.GENESIS
    with db.tx() as c:
        for i in range(n):
            party = "APC" if i % 2 == 0 else "LP"
            block = ledger.compute_hash(head, election, party, pu)
            c.execute("INSERT INTO ledger (previous_hash, election_type, party_code, "
                      "polling_unit_code, block_hash) VALUES (?,?,?,?,?)",
                      (head, election, party, pu, block))
            head = block
    return head


def make_payload(pu, scores, accredited=10):
    return {"v": 1, "election_type": "PRESIDENTIAL", "polling_unit_code": pu,
            "accredited": accredited, "rejected": 0, "scores": scores,
            "signed_at": datetime.now(timezone.utc).isoformat()}


def submit(client, key, officer_id, payload):
    return client.post("/results/submit", json={
        "payload": payload, "officer_id": officer_id,
        "signature": sg.sign(key, sg.sheet_message(payload))})


def test_audit_log_chain_is_signed(client, staff):
    headers = bearer(staff["tokens"]["ADMIN"])
    with db.tx() as c:
        for i in range(3):
            alog.append(c, "tester", "TEST_ACTION", f"n={i}")

    check = client.get("/admin/audit/verify-log", headers=headers).json()
    assert check["valid"] is True
    assert check["entries_checked"] == 3
    assert check["checkpoint"] is None
    assert check["checkpoint_signature_valid"] is None

    cp = client.post("/admin/audit/log-checkpoint", headers=headers).json()
    assert cp["height"] == 4  # the checkpoint action itself is covered
    check = client.get("/admin/audit/verify-log", headers=headers).json()
    assert check["valid"] is True
    assert check["entries_checked"] == 4
    assert check["checkpoint"]["height"] == 4
    assert check["checkpoint_signature_valid"] is True
    assert check["covered"] is True


def test_audit_log_detects_edits(client, staff):
    headers = bearer(staff["tokens"]["ADMIN"])
    with db.tx() as c:
        for i in range(3):
            alog.append(c, "tester", "TEST_ACTION", f"n={i}")
    assert client.post("/admin/audit/log-checkpoint", headers=headers).status_code == 200

    # Rewriting a covered entry breaks the link at that entry.
    with db.tx() as c:
        first = c.execute("SELECT id FROM admin_audit ORDER BY id LIMIT 1").fetchone()["id"]
        c.execute("UPDATE admin_audit SET detail='rewritten' WHERE id=?", (first,))
    check = client.get("/admin/audit/verify-log", headers=headers).json()
    assert check["valid"] is False
    assert check["first_bad_entry"] == first
    assert check["reason"] == "audit log hash chain broken"


def test_audit_log_forged_checkpoint_signature_is_rejected(client, staff):
    headers = bearer(staff["tokens"]["ADMIN"])
    with db.tx() as c:
        alog.append(c, "tester", "TEST_ACTION", "n=0")
    assert client.post("/admin/audit/log-checkpoint", headers=headers).status_code == 200

    # A well-formed but forged checkpoint signature is not trusted.
    with db.tx() as c:
        c.execute("UPDATE audit_checkpoints SET signature=?", ("00" * 64,))
    check = client.get("/admin/audit/verify-log", headers=headers).json()
    assert check["valid"] is False
    assert check["checkpoint_signature_valid"] is False
    assert check["reason"] == "audit-log checkpoint signature invalid"


def test_audit_log_detects_tail_truncation(client, staff):
    headers = bearer(staff["tokens"]["ADMIN"])
    with db.tx() as c:
        for i in range(3):
            alog.append(c, "tester", "TEST_ACTION", f"n={i}")
    cp = client.post("/admin/audit/log-checkpoint", headers=headers).json()

    # Removing the newest entry leaves a self-consistent chain; only the signed
    # height reveals that the log was shortened.
    with db.tx() as c:
        c.execute("DELETE FROM admin_audit WHERE id=(SELECT MAX(id) FROM admin_audit)")
    check = client.get("/admin/audit/verify-log", headers=headers).json()
    assert check["valid"] is False
    assert check["entries_checked"] == cp["height"] - 1
    assert check["reason"] == "audit log is shorter than the signed checkpoint"


def test_audit_log_verification_is_role_restricted(client, staff):
    registrar = bearer(staff["tokens"]["REGISTRAR"])
    auditor = bearer(staff["tokens"]["AUDITOR"])
    assert client.get("/admin/audit/verify-log", headers=registrar).status_code == 403
    assert client.get("/admin/audit/verify-log", headers=auditor).status_code == 200
    assert client.get("/admin/audit/log-export", headers=registrar).status_code == 403
    export = client.get("/admin/audit/log-export", headers=auditor).json()
    assert export["verification"]["valid"] is True
    assert len(export["authority_public_key"]) == 64
    assert client.post("/admin/audit/log-checkpoint", headers=auditor).status_code == 403
    assert client.post("/admin/audit/log-checkpoint", headers=registrar).status_code == 403


def test_ledger_checkpoint_signature_is_verified(client, staff):
    head = seed_blocks(3)
    headers = bearer(staff["tokens"]["ADMIN"])
    checkpoint = client.post("/admin/audit/checkpoint", headers=headers)
    assert checkpoint.status_code == 200
    cp = checkpoint.json()

    # A well-formed but forged signature must invalidate the whole checkpoint check.
    with db.tx() as c:
        c.execute("UPDATE ledger_checkpoints SET signature=? WHERE id=?", ("00" * 64, cp["id"]))

    check = client.get("/admin/audit/verify-chain", headers=headers).json()
    assert check["valid"] is False
    assert check["checkpoint_signature_valid"] is False
    assert check["reason"] == "ledger checkpoint signature invalid"

    # The public endpoints must not report a rewritten ledger as verified either.
    public = client.get("/api/v1/audit/ledger").json()
    assert public["chain"]["valid"] is False
    receipt = client.get("/api/v1/receipt/" + head)
    assert receipt.status_code == 200
    assert receipt.json()["chain"]["valid"] is False


def test_result_checkpoint_detects_truncation(client, set_election, make_officer, staff):
    set_election("PRESIDENTIAL", "OPEN")
    for i in (1, 2, 3):
        key = make_officer(f"PO-00{i}", "PRESIDING_OFFICER", f"PU-00{i}")
        assert submit(client, key, f"PO-00{i}",
                      make_payload(f"PU-00{i}", {"APC": i})).status_code == 200

    headers = bearer(staff["tokens"]["ADMIN"])
    assert client.post("/results/checkpoint", headers=headers).status_code == 200

    # Dropping the trailing sheet leaves a self-consistent hash chain, so only
    # re-deriving the signed Merkle root reveals the truncation.
    with db.tx() as c:
        c.execute("DELETE FROM result_sheets WHERE polling_unit_code='PU-003'")

    stats = client.get("/admin/stats", headers=headers).json()
    assert stats["sheet_chain"]["valid"] is True
    assert stats["result_checkpoint_check"]["valid"] is False
    assert stats["result_checkpoint_check"]["root_matches"] is False
    assert "no longer match" in stats["result_checkpoint_check"]["reason"]


def test_tally_excludes_tampered_stored_sheet(client, set_election, make_officer):
    set_election("PRESIDENTIAL", "OPEN")
    po1 = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    po2 = make_officer("PO-002", "PRESIDING_OFFICER", "PU-002")
    assert submit(client, po1, "PO-001", make_payload("PU-001", {"APC": 5})).status_code == 200
    assert submit(client, po2, "PO-002", make_payload("PU-002", {"APC": 7})).status_code == 200

    # Change a stored payload without changing its committed hash.
    with db.tx() as c:
        row = c.execute("SELECT payload FROM result_sheets WHERE polling_unit_code='PU-002'").fetchone()
        payload = json.loads(row["payload"])
        payload["scores"]["APC"] = 999
        c.execute("UPDATE result_sheets SET payload=? WHERE polling_unit_code='PU-002'",
                  (json.dumps(payload),))
    set_election("PRESIDENTIAL", "CLOSED")

    tally = client.get("/results/tally/PRESIDENTIAL").json()
    assert tally["sheets_counted"] == 1
    assert tally["totals"] == {"APC": 5}
    assert [s["polling_unit_code"] for s in tally["invalid_sheets"]] == ["PU-002"]
    assert "hash mismatch" in tally["invalid_sheets"][0]["reason"]


def test_offline_verifier_reports_malformed_archives(tmp_path):
    cases = [
        "not json",
        json.dumps([]),
        json.dumps({"sheets": "nope"}),
        json.dumps({"sheets": [{"payload": "not-json"}]}),
        json.dumps({"sheets": [{"payload": "{}", "block_index": "x"}],
                    "countersignatures": [{"block_index": 1}]}),
    ]
    for index, body in enumerate(cases):
        path = tmp_path / f"bad-{index}.json"
        path.write_text(body)
        assert verify_offline.main(str(path)) == 1, body


def test_offline_verifier_accepts_an_empty_released_archive(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"sheets": [], "countersignatures": [], "officers": {},
                                "checkpoint": None, "authority_public_key": None}))
    assert verify_offline.main(str(path)) == 0


def test_offline_verifier_can_pin_the_authority_key(client, set_election, make_officer,
                                                    staff, tmp_path):
    set_election("PRESIDENTIAL", "OPEN")
    po = make_officer("PO-001", "PRESIDING_OFFICER", "PU-001")
    assert submit(client, po, "PO-001", make_payload("PU-001", {"APC": 4})).status_code == 200
    headers = bearer(staff["tokens"]["ADMIN"])
    assert client.post("/results/checkpoint", headers=headers).status_code == 200
    set_election("PRESIDENTIAL", "CLOSED")

    archive = client.get("/results/export").json()
    path = tmp_path / "export.json"
    path.write_text(json.dumps(archive))
    pin = archive["authority_public_key"]
    assert verify_offline.main(str(path), authority_key=pin) == 0
    assert verify_offline.main(str(path), authority_key="00" * 32) == 1
    assert verify_offline.main(str(path), require_pinned_key=True) == 1
