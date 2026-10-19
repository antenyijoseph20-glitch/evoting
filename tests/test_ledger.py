"""Vote-ledger chain, signed head checkpoints and public publication policy."""
import db
import ledger


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


def test_chain_verification_and_signed_checkpoint(client, staff, set_election):
    seed_blocks(3)
    headers = bearer(staff["tokens"]["ADMIN"])
    check = client.get("/admin/audit/verify-chain", headers=headers).json()
    assert check["valid"] is True
    assert check["blocks_checked"] == 3

    checkpoint = client.post("/admin/audit/checkpoint", headers=headers)
    assert checkpoint.status_code == 200, checkpoint.text
    cp = checkpoint.json()
    assert cp["height"] == 3
    assert len(cp["head_hash"]) == 64

    set_election("PRESIDENTIAL", "CLOSED")
    public = client.get("/api/v1/audit/ledger").json()
    assert public["visible_blocks"] == 3
    assert public["ledger_height"] == 3
    assert public["chain"]["valid"] is True
    assert public["checkpoint"]["head_hash"] == cp["head_hash"]
    assert public["authority_public_key"] == cp["authority_public_key"]

    audit = client.get("/admin/audit", headers=headers).json()["audit"]
    assert any(e["action"] == "LEDGER_CHECKPOINT" and "height=3" in e["detail"] for e in audit)


def test_truncation_below_signed_checkpoint_is_detected(client, staff):
    seed_blocks(3)
    headers = bearer(staff["tokens"]["ADMIN"])
    client.post("/admin/audit/checkpoint", headers=headers)

    with db.tx() as c:
        c.execute("DELETE FROM ledger WHERE block_index = (SELECT MAX(block_index) FROM ledger)")

    check = client.get("/admin/audit/verify-chain", headers=headers).json()
    assert check["valid"] is False
    assert check["reason"] == "ledger shorter than signed checkpoint"
    assert check["checkpoint_height"] == 3


def test_head_mismatch_is_detected(client):
    seed_blocks(2)
    with db.read() as c:
        rows = c.execute("SELECT * FROM ledger ORDER BY block_index").fetchall()
    good = ledger.verify_chain(rows, 2, rows[-1]["block_hash"])
    assert good["valid"] is True
    bad = ledger.verify_chain(rows, 2, "0" * 64)
    assert bad["valid"] is False
    assert bad["reason"] == "ledger does not match signed checkpoint"


def test_public_ledger_hides_blocks_while_voting_is_open(client, set_election):
    seed_blocks(2)
    set_election("PRESIDENTIAL", "OPEN")
    public = client.get("/api/v1/audit/ledger").json()
    assert public["visible_blocks"] == 0
    assert public["ledger_height"] == 2

    set_election("PRESIDENTIAL", "CLOSED")
    public = client.get("/api/v1/audit/ledger").json()
    assert public["visible_blocks"] == 2
    assert len(public["blocks"]) == 2
    assert {b["party_code"] for b in public["blocks"]} == {"APC", "LP"}


def test_ledger_contains_no_voter_identity(client):
    seed_blocks(1)
    with db.read() as c:
        columns = {r["name"] for r in c.execute("PRAGMA table_info(ledger)")}
    assert columns == {"block_index", "previous_hash", "election_type",
                       "party_code", "polling_unit_code", "block_hash"}
