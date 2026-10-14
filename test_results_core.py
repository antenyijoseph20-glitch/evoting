import json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
tmp = tempfile.mkdtemp()
os.environ["EVOTING_DB"] = os.path.join(tmp, "t.db")
os.environ["EVOTING_AUTHORITY_KEY"] = os.path.join(tmp, "auth.key")

import db, merkle, results_core as rc, signing as sg, verify_offline


def mk_officer(oid, role, pu, party=None):
    pem, pub = sg.generate_keypair()
    with db.tx() as c:
        c.execute("INSERT INTO officers (officer_id,name,role,polling_unit_code,party_code,public_key) VALUES (?,?,?,?,?,?)",
                  (oid, oid, role, pu, party, pub))
    return sg.load_private(pem)


def payload(pu, scores, acc, rej=0, et="PRESIDENTIAL"):
    return {"v": 1, "election_type": et, "polling_unit_code": pu, "accredited": acc, "rejected": rej,
            "scores": scores, "signed_at": "2027-01-16T17:00:00+01:00"}


def submit(key, oid, p):
    with db.tx() as c:
        return rc.submit_sheet(c, p, oid, sg.sign(key, sg.sheet_message(p)))


def expect(status, fn):
    try:
        fn()
    except rc.ResultError as e:
        assert e.status == status, (e.status, e.message)
        return
    raise AssertionError(f"expected ResultError {status}")


def test_everything():
    db.init_db()
    keys = {f"PO-{i}": mk_officer(f"PO-{i}", "PRESIDING_OFFICER", f"PU-00{i}") for i in range(1, 6)}
    agent = mk_officer("AG-APC-1", "PARTY_AGENT", "PU-001", "APC")

    # valid sheets, one overvoted
    for i in range(1, 5):
        r = submit(keys[f"PO-{i}"], f"PO-{i}", payload(f"PU-00{i}", {"APC": 100 + i, "LP": 90}, 250, 5))
        assert r["flags"] == []
    bad = submit(keys["PO-5"], "PO-5", payload("PU-005", {"APC": 200, "LP": 100}, 250, 5))
    assert bad["flags"] == ["OVERVOTE"]

    # security properties
    p = payload("PU-001", {"APC": 1}, 10)
    expect(409, lambda: submit(keys["PO-1"], "PO-1", p))                                    # duplicate sheet
    p2 = payload("PU-002", {"APC": 1}, 10, et="SENATE")
    expect(403, lambda: submit(keys["PO-1"], "PO-1", p2))                                   # officer for wrong PU
    with db.tx() as c:                                                                      # forged signature
        try:
            rc.submit_sheet(c, p2, "PO-2", sg.sign(keys["PO-1"], sg.sheet_message(p2))); raise AssertionError
        except rc.ResultError as e:
            assert e.status == 401
    expect(422, lambda: submit(keys["PO-2"], "PO-2", payload("PU-002", {"XYZ": 1}, 10, et="SENATE")))   # bad party
    expect(422, lambda: submit(keys["PO-2"], "PO-2", payload("PU-002", {"APC": -5}, 10, et="SENATE")))   # negative
    expect(422, lambda: submit(keys["PO-2"], "PO-2", payload("PU-002", {"APC": True}, 10, et="SENATE"))) # bool is not int

    # countersign: valid, duplicate, wrong signer
    with db.tx() as c:
        ph = c.execute("SELECT payload_hash FROM result_sheets WHERE polling_unit_code='PU-001'").fetchone()[0]
        rc.countersign(c, "PRESIDENTIAL", "PU-001", "AG-APC-1", sg.sign(agent, sg.countersign_message(ph)))
    with db.tx() as c:
        try:
            rc.countersign(c, "PRESIDENTIAL", "PU-001", "AG-APC-1", sg.sign(agent, sg.countersign_message(ph))); raise AssertionError
        except rc.ResultError as e:
            assert e.status == 409

    # tally excludes flagged sheet
    with db.read() as c:
        t = rc.tally(c, "PRESIDENTIAL")
    assert t["sheets_counted"] == 4 and t["totals"]["APC"] == 410 and len(t["flagged_excluded"]) == 1

    # Merkle inclusion proofs for every sheet
    with db.tx() as c:
        cp = rc.create_checkpoint(c)
    with db.read() as c:
        for i in range(1, 6):
            pr = rc.inclusion_proof(c, "PRESIDENTIAL", f"PU-00{i}")
            assert merkle.verify_proof(bytes.fromhex(pr["leaf"]), pr["leaf_index"], pr["tree_size"],
                                       [bytes.fromhex(h) for h in pr["path"]], bytes.fromhex(pr["root"]))
            assert not merkle.verify_proof(b"x" * 32, pr["leaf_index"], pr["tree_size"],
                                           [bytes.fromhex(h) for h in pr["path"]], bytes.fromhex(pr["root"]))
        exp = rc.export_all(c)
    path = os.path.join(tmp, "export.json")
    json.dump(exp, open(path, "w"))
    assert verify_offline.main(path) == 0

    # tamper with the export: change a score -> verifier must catch it
    exp["sheets"][0]["payload"] = exp["sheets"][0]["payload"].replace('"APC":101', '"APC":901')
    tampered = os.path.join(tmp, "tampered.json"); json.dump(exp, open(tampered, "w"))
    assert verify_offline.main(tampered) == 1


def test_merkle_sizes():
    for n in range(1, 20):
        leaves = [bytes([i]) * 32 for i in range(n)]
        r = merkle.root(leaves)
        for m in range(n):
            assert merkle.verify_proof(leaves[m], m, n, merkle.proof(leaves, m), r)


if __name__ == "__main__":
    test_merkle_sizes(); test_everything(); print("ALL TESTS PASSED")
