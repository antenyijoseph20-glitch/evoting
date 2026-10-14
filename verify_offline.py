"""Independent verifier. Needs only an export file; trusts nothing on the server.
   python3 verify_offline.py export.json      (get it from GET /results/export)
Checks: officer signatures, countersignatures, hash chain, overvote flags, Merkle root and authority signature."""
import json
import sys

import merkle
import signing as sg

GENESIS = "0" * 64


def main(path: str) -> int:
    d = json.load(open(path))
    problems, prev = [], GENESIS
    for s in d["sheets"]:
        tag = f"block {s['block_index']} ({s['election_type']}/{s['polling_unit_code']})"
        payload = json.loads(s["payload"])
        off = d["officers"].get(s["officer_id"])
        if sg.sha256_hex(sg.canonical(payload)) != s["payload_hash"]:
            problems.append(f"{tag}: payload hash mismatch")
        if not off or off["role"] != "PRESIDING_OFFICER" or not sg.verify(off["public_key"], s["signature"], sg.sheet_message(payload)):
            problems.append(f"{tag}: officer signature invalid")
        expect = sg.sha256_hex(f"{prev}|{s['payload_hash']}|{s['officer_id']}|{s['signature']}".encode())
        if s["previous_hash"] != prev or s["block_hash"] != expect:
            problems.append(f"{tag}: hash chain broken")
        over = sum(payload["scores"].values()) + payload["rejected"] > payload["accredited"]
        if over != ("OVERVOTE" in s["flags"].split(",")):
            problems.append(f"{tag}: overvote flag inconsistent with figures")
        prev = s["block_hash"]
    by_block = {s["block_index"]: s for s in d["sheets"]}
    for c in d["countersignatures"]:
        s, ag = by_block.get(c["block_index"]), d["officers"].get(c["officer_id"])
        if not s or not ag or not sg.verify(ag["public_key"], c["signature"], sg.countersign_message(s["payload_hash"])):
            problems.append(f"countersignature by {c['officer_id']} on block {c['block_index']} invalid")
    cp = d["checkpoint"]
    if cp:
        leaves = [bytes.fromhex(s["block_hash"]) for s in d["sheets"]][: cp["tree_size"]]
        if len(leaves) != cp["tree_size"] or merkle.root(leaves).hex() != cp["root"]:
            problems.append("checkpoint root does not match the sheets")
        if not sg.verify(d["authority_public_key"], cp["signature"], sg.checkpoint_message(cp["tree_size"], cp["root"])):
            problems.append("checkpoint authority signature invalid")
    else:
        print("note: no signed checkpoint published yet")
    print(f"sheets: {len(d['sheets'])}, countersignatures: {len(d['countersignatures'])}")
    print("RESULT:", "ALL CHECKS PASSED" if not problems else f"{len(problems)} PROBLEM(S)")
    for p in problems:
        print(" -", p)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) == 2 else sys.exit(__doc__))
