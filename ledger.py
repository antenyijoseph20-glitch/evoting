"""Hash-chained ledger helpers."""
import hashlib
import json

GENESIS = "0" * 64


def compute_hash(prev: str, election: str, party: str, pu: str) -> str:
    payload = json.dumps([prev, election, party, pu], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_chain(rows) -> dict:
    prev = GENESIS
    for r in rows:
        if r["previous_hash"] != prev or compute_hash(prev, r["election_type"], r["party_code"],
                                                      r["polling_unit_code"]) != r["block_hash"]:
            return {"valid": False, "first_bad_block": r["block_index"]}
        prev = r["block_hash"]
    return {"valid": True, "blocks_checked": len(rows), "head": prev}
