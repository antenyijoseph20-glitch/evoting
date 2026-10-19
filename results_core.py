"""Polling-unit result logic (EC8A-style). No web framework dependency, so it is unit-testable."""
import json
import os
import stat
from datetime import datetime, timezone

import config
import ledger
import merkle
import signing as sg

GENESIS = "0" * 64
MAX_COUNT = 1_000_000
REVIEW_RESOLUTIONS = {"ACCEPT": "ACCEPTED", "VOID": "VOID"}


class ResultError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ---------- authority key ----------
_authority = None


def authority_key():
    global _authority
    if _authority:
        return _authority
    path = (os.getenv("EVOTING_AUTHORITY_KEY") or "").strip() or "authority_ed25519.key"
    if os.path.exists(path):
        # The authority key is the root of every checkpoint signature. A
        # group/world-readable key file defeats offline key custody.
        if not config.DEV:
            mode = os.stat(path).st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise RuntimeError("Authority key file must not be accessible by group/others "
                                   "(chmod 600).")
        with open(path, "rb") as f:
            _authority = sg.load_private(f.read())
    elif config.DEV:
        pem, _ = sg.generate_keypair()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        _authority = sg.load_private(pem)
    else:
        raise RuntimeError("Authority key file missing.")
    return _authority


def authority_public_hex() -> str:
    return sg.public_hex(authority_key())


# ---------- validation ----------
def validate_payload(p: dict) -> list[str]:
    """Raises ResultError on malformed input; returns integrity flags for well-formed input."""
    need = {"v", "election_type", "polling_unit_code", "accredited", "rejected", "scores", "signed_at"}
    if (not isinstance(p, dict) or set(p) != need
            or type(p["v"]) is not int or p["v"] != 1):
        raise ResultError(422, "Payload must contain exactly: " + ", ".join(sorted(need)) + " (v=1).")
    if not isinstance(p["election_type"], str):
        raise ResultError(422, "Unknown election type.")
    parties = config.ELECTION_PARTIES.get(p["election_type"])
    if parties is None:
        raise ResultError(422, "Unknown election type.")
    if not isinstance(p["polling_unit_code"], str) or not 3 <= len(p["polling_unit_code"]) <= 32:
        raise ResultError(422, "Bad polling unit code.")
    ints = [p["accredited"], p["rejected"], *(p["scores"].values() if isinstance(p["scores"], dict) else [None])]
    if any(type(x) is not int or not 0 <= x <= MAX_COUNT for x in ints):
        raise ResultError(422, "All counts must be integers between 0 and 1,000,000.")
    if set(p["scores"]) - set(parties):
        raise ResultError(422, "Scores contain a party not valid for this election.")
    try:
        datetime.fromisoformat(p["signed_at"])
    except (TypeError, ValueError):
        raise ResultError(422, "signed_at must be an ISO-8601 timestamp.")
    flags = []
    if sum(p["scores"].values()) + p["rejected"] > p["accredited"]:
        flags.append("OVERVOTE")  # recorded and flagged, never silently dropped
    return flags


def _officer(conn, officer_id: str, role: str, pu: str):
    o = conn.execute("SELECT * FROM officers WHERE officer_id=?", (officer_id,)).fetchone()
    if not o or not o["active"] or o["role"] != role or o["polling_unit_code"] != pu:
        raise ResultError(403, f"Not an active {role} for this polling unit.")
    return o


def block_hash(prev: str, payload_hash: str, officer_id: str, signature: str) -> str:
    return sg.sha256_hex(f"{prev}|{payload_hash}|{officer_id}|{signature}".encode())


# ---------- operations (call inside db.tx) ----------
def submit_sheet(conn, payload: dict, officer_id: str, signature: str) -> dict:
    flags = validate_payload(payload)
    pu, et = payload["polling_unit_code"], payload["election_type"]
    off = _officer(conn, officer_id, "PRESIDING_OFFICER", pu)
    if not sg.verify(off["public_key"], signature, sg.sheet_message(payload)):
        raise ResultError(401, "Signature does not verify against the officer's registered key.")
    prev_row = conn.execute("SELECT block_hash FROM result_sheets ORDER BY block_index DESC LIMIT 1").fetchone()
    prev = prev_row["block_hash"] if prev_row else GENESIS
    ph = sg.sha256_hex(sg.canonical(payload))
    bh = block_hash(prev, ph, officer_id, signature)
    try:
        cur = conn.execute(
            "INSERT INTO result_sheets (election_type, polling_unit_code, payload, payload_hash, officer_id, "
            "signature, flags, previous_hash, block_hash) VALUES (?,?,?,?,?,?,?,?,?)",
            (et, pu, sg.canonical(payload).decode(), ph, officer_id, signature, ",".join(flags), prev, bh))
    except Exception as e:
        if "UNIQUE" in str(e):
            raise ResultError(409, "A result sheet for this polling unit and election already exists.")
        raise
    return {"block_index": cur.lastrowid, "payload_hash": ph, "block_hash": bh, "flags": flags}


def countersign(conn, election_type: str, pu: str, officer_id: str, signature: str) -> dict:
    sheet = conn.execute("SELECT block_index, payload_hash FROM result_sheets WHERE election_type=? AND "
                         "polling_unit_code=?", (election_type, pu)).fetchone()
    if not sheet:
        raise ResultError(404, "No result sheet for this polling unit and election.")
    ag = _officer(conn, officer_id, "PARTY_AGENT", pu)
    if not sg.verify(ag["public_key"], signature, sg.countersign_message(sheet["payload_hash"])):
        raise ResultError(401, "Countersignature does not verify.")
    try:
        conn.execute("INSERT INTO countersignatures (block_index, officer_id, signature) VALUES (?,?,?)",
                     (sheet["block_index"], officer_id, signature))
    except Exception as e:
        if "UNIQUE" in str(e) or "PRIMARY" in str(e):
            raise ResultError(409, "Already countersigned.")
        raise
    return {"block_index": sheet["block_index"], "party": ag["party_code"]}


def verify_sheet_chain(conn) -> dict:
    """Verify the result-sheet hash chain (independent of the Merkle checkpoint)."""
    rows = conn.execute("SELECT * FROM result_sheets ORDER BY block_index").fetchall()
    prev = GENESIS
    for r in rows:
        if (r["previous_hash"] != prev
                or block_hash(prev, r["payload_hash"], r["officer_id"], r["signature"]) != r["block_hash"]):
            return {"valid": False, "first_bad_block": r["block_index"], "blocks_checked": 0}
        prev = r["block_hash"]
    return {"valid": True, "blocks_checked": len(rows), "head": prev}


def _leaves(conn, size: int | None = None) -> list[bytes]:
    rows = conn.execute("SELECT block_hash FROM result_sheets ORDER BY block_index").fetchall()
    leaves = [bytes.fromhex(r["block_hash"]) for r in rows]
    return leaves if size is None else leaves[:size]


def create_checkpoint(conn) -> dict:
    leaves = _leaves(conn)
    r = merkle.root(leaves).hex()
    sig = sg.sign(authority_key(), sg.checkpoint_message(len(leaves), r))
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO checkpoints (tree_size, root, signature, created_at) VALUES (?,?,?,?)",
                 (len(leaves), r, sig, ts))
    return {"tree_size": len(leaves), "root": r, "signature": sig, "created_at": ts,
            "authority_public_key": authority_public_hex()}


def verify_checkpoint(conn) -> dict | None:
    """Re-derive the latest result-sheet checkpoint from the stored tree.

    Checking the signature alone is not enough: it proves the authority signed some
    root, not that the root is still the root of *this* database. A trailing sheet
    added after the checkpoint is a legitimate extension; a deleted or altered
    covered sheet is not.
    """
    cp = conn.execute("SELECT * FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
    if not cp:
        return None
    tree_size = cp["tree_size"]
    if (type(tree_size) is not int or tree_size < 0
            or not isinstance(cp["root"], str) or not isinstance(cp["signature"], str)):
        return {"valid": False, "root_matches": False, "signature_valid": False,
                "tree_size": tree_size, "sheets_present": None, "covered": False,
                "all_sheets_covered": False, "checkpoint": dict(cp),
                "reason": "checkpoint row is malformed"}
    total = conn.execute("SELECT COUNT(*) FROM result_sheets").fetchone()[0]
    rows = conn.execute("SELECT block_hash FROM result_sheets ORDER BY block_index LIMIT ?",
                        (tree_size,)).fetchall()
    try:
        leaves = [bytes.fromhex(r["block_hash"]) for r in rows]
        root_matches = len(rows) == tree_size and merkle.root(leaves).hex() == cp["root"]
    except (TypeError, ValueError):
        root_matches = False
    try:
        signature_valid = sg.verify(authority_public_hex(), cp["signature"],
                                    sg.checkpoint_message(tree_size, cp["root"]))
    except (TypeError, ValueError):
        signature_valid = False
    result = {"valid": bool(root_matches and signature_valid), "root_matches": bool(root_matches),
              "signature_valid": bool(signature_valid), "tree_size": tree_size,
              "sheets_present": total, "covered": total >= tree_size,
              "all_sheets_covered": total == tree_size, "checkpoint": dict(cp)}
    if not root_matches:
        result["reason"] = "stored result sheets no longer match the signed Merkle root"
    elif not signature_valid:
        result["reason"] = "result-sheet checkpoint signature invalid"
    return result


def inclusion_proof(conn, election_type: str, pu: str) -> dict:
    rows = conn.execute("SELECT block_index, block_hash FROM result_sheets ORDER BY block_index").fetchall()
    target = conn.execute("SELECT block_index, block_hash FROM result_sheets WHERE election_type=? AND "
                          "polling_unit_code=?", (election_type, pu)).fetchone()
    if not target:
        raise ResultError(404, "No result sheet found.")
    cp = conn.execute("SELECT * FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
    pos = [r["block_index"] for r in rows].index(target["block_index"])
    if not cp or pos >= cp["tree_size"]:
        raise ResultError(409, "Sheet not yet covered by a signed checkpoint.")
    leaves = _leaves(conn, cp["tree_size"])
    return {"leaf": target["block_hash"], "leaf_index": pos, "tree_size": cp["tree_size"],
            "path": [h.hex() for h in merkle.proof(leaves, pos)], "root": cp["root"],
            "checkpoint_signature": cp["signature"], "authority_public_key": authority_public_hex()}


def _stored_sheet(conn, row, election_type: str) -> tuple[dict | None, str | None]:
    """Re-validate a stored sheet before it can affect a public tally.

    The signature and the result-sheet chain are verified at submission time, but
    that says nothing about the database *now*. A row whose stored metadata,
    payload hash or signature no longer agree is excluded and reported rather than
    counted.
    """
    try:
        payload = json.loads(row["payload"])
    except (TypeError, ValueError):
        return None, "stored payload is not valid JSON"
    if not isinstance(payload, dict):
        return None, "stored payload is not an object"
    if (payload.get("election_type") != election_type
            or payload.get("polling_unit_code") != row["polling_unit_code"]):
        return None, "payload metadata does not match the stored row"
    parties = config.ELECTION_PARTIES.get(election_type)
    scores = payload.get("scores")
    if not isinstance(scores, dict):
        return None, "payload has no score map"
    if parties is None or set(scores) - set(parties):
        return None, "payload contains a party not valid for this election"
    counts = [payload.get("accredited"), payload.get("rejected"), *scores.values()]
    if any(type(x) is not int or not 0 <= x <= MAX_COUNT for x in counts):
        return None, "payload contains an invalid count"
    if sg.sha256_hex(sg.canonical(payload)) != row["payload_hash"]:
        return None, "payload hash mismatch"
    officer = conn.execute("SELECT public_key, role, polling_unit_code FROM officers "
                           "WHERE officer_id=?", (row["officer_id"],)).fetchone()
    if (not officer or officer["role"] != "PRESIDING_OFFICER"
            or officer["polling_unit_code"] != row["polling_unit_code"]
            or not sg.verify(officer["public_key"], row["signature"], sg.sheet_message(payload))):
        return None, "officer signature invalid"
    return payload, None


def tally(conn, election_type: str) -> dict:
    rows = conn.execute("SELECT polling_unit_code, payload, payload_hash, officer_id, signature, "
                        "flags, review_status FROM result_sheets WHERE election_type=?",
                        (election_type,)).fetchall()
    totals, counted, accredited = {}, 0, 0
    flagged_excluded, flagged_accepted, voided, invalid = [], [], [], []
    for r in rows:
        flags = r["flags"].split(",") if r["flags"] else []
        review = r["review_status"]
        entry = {"polling_unit_code": r["polling_unit_code"], "flags": flags,
                 "review_status": review}
        payload, problem = _stored_sheet(conn, r, election_type)
        if problem:
            invalid.append({**entry, "reason": problem})
            continue
        if review == "VOID":
            voided.append(entry)
            continue
        if flags and review == "PENDING":
            flagged_excluded.append(entry)  # excluded pending an audited review
            continue
        counted += 1
        accredited += payload["accredited"]
        for party, n in payload["scores"].items():
            totals[party] = totals.get(party, 0) + n
        if flags:  # explicitly accepted despite a flag
            flagged_accepted.append(entry)
    return {"election_type": election_type, "sheets_counted": counted, "total_accredited": accredited,
            "totals": dict(sorted(totals.items(), key=lambda kv: -kv[1])),
            "flagged_excluded": flagged_excluded, "flagged_accepted": flagged_accepted,
            "voided": voided, "invalid_sheets": invalid}


def review_sheet(conn, election_type: str, pu: str, resolution: str, actor: str,
                 note: str = "") -> dict:
    """Resolve a flagged sheet exactly once. ACCEPT counts it; VOID excludes it."""
    if resolution not in REVIEW_RESOLUTIONS:
        raise ResultError(422, "resolution must be ACCEPT or VOID.")
    sheet = conn.execute("SELECT block_index, flags, review_status FROM result_sheets "
                         "WHERE election_type=? AND polling_unit_code=?",
                         (election_type, pu)).fetchone()
    if not sheet:
        raise ResultError(404, "No result sheet for this polling unit and election.")
    if not sheet["flags"]:
        raise ResultError(409, "This sheet has no integrity flags to review.")
    if sheet["review_status"] != "PENDING":
        raise ResultError(409, f"Sheet was already reviewed ({sheet['review_status']}).")
    ts = datetime.now(timezone.utc).isoformat()
    status = REVIEW_RESOLUTIONS[resolution]
    cur = conn.execute("UPDATE result_sheets SET review_status=?, reviewed_by=?, reviewed_at=?, "
                       "review_note=? WHERE block_index=? AND review_status='PENDING'",
                       (status, actor, ts, note[:500], sheet["block_index"]))
    if cur.rowcount != 1:
        raise ResultError(409, "Sheet was reviewed concurrently. Reload and try again.")
    return {"block_index": sheet["block_index"], "review_status": status,
            "reviewed_by": actor, "reviewed_at": ts, "note": note[:500]}


def create_ledger_checkpoint(conn) -> dict:
    """Sign the current vote-ledger head. Makes truncation detectable."""
    rows = conn.execute("SELECT block_hash FROM ledger ORDER BY block_index").fetchall()
    height = len(rows)
    head = rows[-1]["block_hash"] if rows else ledger.GENESIS
    sig = sg.sign(authority_key(), ledger.checkpoint_message(height, head))
    ts = datetime.now(timezone.utc).isoformat()
    cur = conn.execute("INSERT INTO ledger_checkpoints (height, head_hash, signature, created_at) "
                       "VALUES (?,?,?,?)", (height, head, sig, ts))
    return {"id": cur.lastrowid, "height": height, "head_hash": head, "signature": sig,
            "created_at": ts, "authority_public_key": authority_public_hex()}


def latest_ledger_checkpoint(conn):
    return conn.execute("SELECT * FROM ledger_checkpoints ORDER BY id DESC LIMIT 1").fetchone()


def verify_ledger_chain(conn, rows=None) -> dict:
    """Verify ledger linkage, checkpoint coverage and the checkpoint signature.

    Without the signature check, anyone able to write a checkpoint row could make a
    rewritten or truncated ledger look consistent with "the latest checkpoint".
    """
    if rows is None:
        rows = conn.execute("SELECT * FROM ledger ORDER BY block_index").fetchall()
    cp = latest_ledger_checkpoint(conn)
    if cp and (type(cp["height"]) is not int or cp["height"] < 0
               or not isinstance(cp["head_hash"], str) or not isinstance(cp["signature"], str)):
        return {"valid": False, "blocks_checked": 0, "head": None,
                "checkpoint_signature_valid": False,
                "reason": "ledger checkpoint row is malformed"}
    check = ledger.verify_chain(rows, cp["height"] if cp else None, cp["head_hash"] if cp else None)
    if not cp:
        check["checkpoint_signature_valid"] = None
        return check
    try:
        signature_valid = sg.verify(authority_public_hex(), cp["signature"],
                                    ledger.checkpoint_message(cp["height"], cp["head_hash"]))
    except (TypeError, ValueError):
        signature_valid = False
    check["checkpoint_signature_valid"] = bool(signature_valid)
    if not signature_valid and check.get("valid"):
        check = {**check, "valid": False, "reason": "ledger checkpoint signature invalid"}
    return check


def export_all(conn) -> dict:
    sheets = [dict(r) for r in conn.execute("SELECT * FROM result_sheets ORDER BY block_index")]
    counters = [dict(r) for r in conn.execute("SELECT * FROM countersignatures")]
    officers = {r["officer_id"]: {"public_key": r["public_key"], "role": r["role"],
                                  "polling_unit_code": r["polling_unit_code"], "party_code": r["party_code"]}
                for r in conn.execute("SELECT * FROM officers")}
    cp = conn.execute("SELECT * FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
    return {"sheets": sheets, "countersignatures": counters, "officers": officers,
            "checkpoint": dict(cp) if cp else None, "authority_public_key": authority_public_hex()}
