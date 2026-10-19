"""Independent verifier. Needs only an export file; trusts nothing on the server.

    python3 verify_offline.py export.json --authority-key <64-hex public key>

Get the export from GET /results/export. Pin --authority-key to the key published
through an independent channel; without it the verifier trusts the key embedded in
the archive (and says so). --require-pinned-key turns a missing pin into a failure.

Checks: officer signatures, countersignatures, sheet metadata against the signed
payload, hash chain, overvote flags, Merkle root, checkpoint coverage and the
authority signature.

Malformed input is reported as a problem rather than raising: an archive that
cannot be parsed is evidence of a bad export, not a reason to crash the auditor's
tool.
"""
import argparse
import json
import sys

import merkle
import signing as sg

GENESIS = "0" * 64


def _sig_ok(public_key, signature, message) -> bool:
    if not isinstance(public_key, str) or not isinstance(signature, str):
        return False
    try:
        return sg.verify(public_key, signature, message)
    except (TypeError, ValueError):
        return False


def _sheet_problems(tag: str, row: dict, payload: dict, officers: dict) -> list[str]:
    problems = []
    if (payload.get("election_type") != row.get("election_type")
            or payload.get("polling_unit_code") != row.get("polling_unit_code")):
        problems.append(f"{tag}: sheet metadata does not match the signed payload")
    try:
        payload_hash_ok = sg.sha256_hex(sg.canonical(payload)) == row.get("payload_hash")
    except (TypeError, ValueError):
        payload_hash_ok = False
    if not payload_hash_ok:
        problems.append(f"{tag}: payload hash mismatch")

    officer = officers.get(row.get("officer_id"))
    if (not isinstance(officer, dict) or officer.get("role") != "PRESIDING_OFFICER"
            or officer.get("polling_unit_code") != row.get("polling_unit_code")
            or not _sig_ok(officer.get("public_key"), row.get("signature"),
                           sg.sheet_message(payload))):
        problems.append(f"{tag}: officer signature invalid")

    scores = payload.get("scores")
    accredited, rejected = payload.get("accredited"), payload.get("rejected")
    if (not isinstance(scores, dict)
            or any(type(n) is not int or not 0 <= n <= 1_000_000 for n in scores.values())
            or type(accredited) is not int or type(rejected) is not int
            or not 0 <= accredited <= 1_000_000 or not 0 <= rejected <= 1_000_000):
        problems.append(f"{tag}: payload counts are malformed")
    else:
        over = sum(scores.values()) + rejected > accredited
        if over != ("OVERVOTE" in str(row.get("flags", "")).split(",")):
            problems.append(f"{tag}: overvote flag inconsistent with figures")
    return problems


def main(path: str, authority_key: str | None = None,
         require_pinned_key: bool = False) -> int:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as error:
        print(f"cannot read export: {error}")
        print("RESULT: 1 PROBLEM(S)")
        print(" - export is not readable JSON")
        return 1
    if not isinstance(data, dict):
        print("RESULT: 1 PROBLEM(S)")
        print(" - export root is not a JSON object")
        return 1

    problems: list[str] = []
    sheets = data.get("sheets")
    if not isinstance(sheets, list):
        problems.append("export has no sheets array")
        sheets = []
    counters = data.get("countersignatures", [])
    if not isinstance(counters, list):
        problems.append("countersignatures is not an array")
        counters = []
    officers = data.get("officers", {})
    if not isinstance(officers, dict):
        problems.append("officers is not an object")
        officers = {}
    checkpoint = data.get("checkpoint")
    if checkpoint is not None and not isinstance(checkpoint, dict):
        problems.append("checkpoint is not an object")
        checkpoint = None

    verification_key = authority_key or data.get("authority_public_key")
    if require_pinned_key and not authority_key:
        problems.append("no pinned authority public key was supplied (--authority-key)")
    if authority_key and data.get("authority_public_key") != authority_key:
        problems.append("export authority public key does not match the pinned key")
    if not authority_key:
        print("WARNING: no --authority-key supplied; this run trusts the key embedded in the export.")

    prev, by_block = GENESIS, {}
    for index, row in enumerate(sheets):
        tag = f"sheet #{index}"
        if not isinstance(row, dict):
            problems.append(f"{tag}: not an object")
            continue
        tag = f"block {row.get('block_index')} ({row.get('election_type')}/{row.get('polling_unit_code')})"
        block_index = row.get("block_index")
        if not isinstance(block_index, int) or isinstance(block_index, bool):
            problems.append(f"{tag}: block_index is not an integer")
        elif block_index in by_block:
            problems.append(f"{tag}: duplicate block_index")
        else:
            by_block[block_index] = row

        try:
            payload = json.loads(row.get("payload"))
        except (TypeError, ValueError):
            payload = None
        if isinstance(payload, dict):
            problems.extend(_sheet_problems(tag, row, payload, officers))
        else:
            problems.append(f"{tag}: payload is not a JSON object")

        expected = sg.sha256_hex(
            f"{prev}|{row.get('payload_hash')}|{row.get('officer_id')}|{row.get('signature')}".encode())
        if row.get("previous_hash") != prev or row.get("block_hash") != expected:
            problems.append(f"{tag}: hash chain broken")
        if isinstance(row.get("block_hash"), str):
            prev = row["block_hash"]

    seen = set()
    for index, counter in enumerate(counters):
        tag = f"countersignature #{index}"
        if not isinstance(counter, dict):
            problems.append(f"{tag}: not an object")
            continue
        key = (counter.get("block_index"), counter.get("officer_id"))
        if key in seen:
            problems.append(f"{tag}: duplicate countersignature by {counter.get('officer_id')} "
                            f"on block {counter.get('block_index')}")
        seen.add(key)
        sheet = by_block.get(counter.get("block_index"))
        agent = officers.get(counter.get("officer_id"))
        if not sheet:
            problems.append(f"{tag}: no sheet for block {counter.get('block_index')}")
            continue
        payload_hash = sheet.get("payload_hash")
        valid = (isinstance(payload_hash, str) and isinstance(agent, dict)
                 and agent.get("role") == "PARTY_AGENT"
                 and agent.get("polling_unit_code") == sheet.get("polling_unit_code")
                 and _sig_ok(agent.get("public_key"), counter.get("signature"),
                             sg.countersign_message(payload_hash)))
        if not valid:
            problems.append(f"{tag}: invalid countersignature by {counter.get('officer_id')} "
                            f"on block {counter.get('block_index')}")

    if checkpoint:
        tree_size, root = checkpoint.get("tree_size"), checkpoint.get("root")
        if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 0:
            problems.append("checkpoint tree_size is invalid")
        elif tree_size > len(sheets):
            problems.append("checkpoint covers more sheets than the export contains")
        else:
            if tree_size < len(sheets):
                problems.append(f"checkpoint covers only {tree_size} of {len(sheets)} sheets")
            try:
                leaves = [bytes.fromhex(row["block_hash"]) for row in sheets[:tree_size]]
            except (KeyError, TypeError, ValueError):
                problems.append("checkpoint cannot be recomputed: a sheet has an invalid block hash")
            else:
                if merkle.root(leaves).hex() != root:
                    problems.append("checkpoint root does not match the sheets")
        if not isinstance(root, str):
            problems.append("checkpoint root is missing")
        elif not _sig_ok(verification_key, checkpoint.get("signature"),
                          sg.checkpoint_message(tree_size, root)):
            problems.append("checkpoint authority signature invalid")
    elif sheets:
        problems.append("export contains sheets but no signed checkpoint")
    else:
        print("note: no signed checkpoint published yet (empty archive)")

    print(f"sheets: {len(sheets)}, countersignatures: {len(counters)}")
    print("RESULT:", "ALL CHECKS PASSED" if not problems else f"{len(problems)} PROBLEM(S)")
    for problem in problems:
        print(" -", problem)
    return 0 if not problems else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify an E2E-V export independently.")
    parser.add_argument("export", help="path to the JSON export")
    parser.add_argument("--authority-key",
                        help="expected 64-hex authority Ed25519 public key; pin this for a "
                             "check that does not trust the archive")
    parser.add_argument("--require-pinned-key", action="store_true",
                        help="fail unless --authority-key is supplied")
    args = parser.parse_args()
    sys.exit(main(args.export, args.authority_key, args.require_pinned_key))
