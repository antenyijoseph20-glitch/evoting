"""Hash-chained ledger helpers."""
import hashlib
import json

GENESIS = "0" * 64


def compute_hash(prev: str, election: str, party: str, pu: str) -> str:
    payload = json.dumps([prev, election, party, pu], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def checkpoint_message(height: int, head_hash: str) -> bytes:
    """Domain-separated message for a signed head checkpoint of the vote ledger."""
    return f"LEDGER-CHECKPOINT-v1|{height}|{head_hash}".encode()


def verify_chain(rows, expected_height: int | None = None,
                 expected_head: str | None = None) -> dict:
    """Verify hash linkage and, when supplied, the latest signed checkpoint.

    A checkpoint makes truncation detectable: dropping trailing blocks would still
    leave a self-consistent chain, but it would no longer reach the signed height/head.
    """
    prev = GENESIS
    for r in rows:
        if r["previous_hash"] != prev or compute_hash(prev, r["election_type"], r["party_code"],
                                                      r["polling_unit_code"]) != r["block_hash"]:
            return {"valid": False, "first_bad_block": r["block_index"],
                    "blocks_checked": 0, "head": prev}
        prev = r["block_hash"]
    result = {"valid": True, "blocks_checked": len(rows), "head": prev}
    if expected_height is not None:
        if len(rows) < expected_height:
            return {**result, "valid": False, "reason": "ledger shorter than signed checkpoint",
                    "checkpoint_height": expected_height}
        if expected_height == 0:
            if expected_head is not None and expected_head != GENESIS:
                return {**result, "valid": False, "reason": "ledger does not match signed checkpoint",
                        "checkpoint_height": 0}
        elif expected_head is not None and rows[expected_height - 1]["block_hash"] != expected_head:
            return {**result, "valid": False, "reason": "ledger does not match signed checkpoint",
                    "checkpoint_height": expected_height}
        result["checkpoint_height"] = expected_height
        result["checkpoint_head"] = expected_head
    return result
