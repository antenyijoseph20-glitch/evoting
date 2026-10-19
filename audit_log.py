"""Tamper-evident administrative audit log.

Every entry commits to the previous entry's hash. A signed checkpoint fixes a
height and head, so deleting or rewriting earlier entries is detectable even by
someone who can write to the database. The checkpoint signature is verified
against the authority key on every read; a checkpoint row alone is not trusted.
"""
from datetime import datetime, timezone

import results_core as rc
import signing as sg

GENESIS = "0" * 64


def entry_hash(prev_hash: str, ts: str, actor: str, action: str, detail: str = "") -> str:
    return sg.sha256_hex(sg.canonical({"v": 1, "prev": prev_hash, "ts": ts,
                                       "actor": actor, "action": action,
                                       "detail": detail or ""}))


def append(conn, actor: str, action: str, detail: str = "") -> dict:
    """Append one chained entry. Call inside db.tx() so prev/insert are atomic."""
    prev_row = conn.execute("SELECT entry_hash FROM admin_audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = prev_row["entry_hash"] if prev_row and prev_row["entry_hash"] else GENESIS
    ts = datetime.now(timezone.utc).isoformat()
    h = entry_hash(prev, ts, actor, action, detail)
    cur = conn.execute("INSERT INTO admin_audit (ts, actor, action, detail, prev_hash, entry_hash) "
                       "VALUES (?,?,?,?,?,?)", (ts, actor, action, detail, prev, h))
    return {"id": cur.lastrowid, "ts": ts, "prev_hash": prev, "entry_hash": h}


def checkpoint_message(height: int, head_hash: str) -> bytes:
    return f"AUDIT-CHECKPOINT-v1|{height}|{head_hash}".encode()


def latest_checkpoint(conn):
    return conn.execute("SELECT * FROM audit_checkpoints ORDER BY id DESC LIMIT 1").fetchone()


def create_checkpoint(conn) -> dict:
    rows = conn.execute("SELECT entry_hash FROM admin_audit ORDER BY id").fetchall()
    if any(r["entry_hash"] is None for r in rows):
        raise RuntimeError("audit log contains unchained entries; run db.init_db() to migrate")
    height = len(rows)
    head = rows[-1]["entry_hash"] if rows else GENESIS
    sig = sg.sign(rc.authority_key(), checkpoint_message(height, head))
    ts = datetime.now(timezone.utc).isoformat()
    cur = conn.execute("INSERT INTO audit_checkpoints (height, head_hash, signature, created_at) "
                       "VALUES (?,?,?,?)", (height, head, sig, ts))
    return {"id": cur.lastrowid, "height": height, "head_hash": head, "signature": sig,
            "created_at": ts, "authority_public_key": rc.authority_public_hex()}


def verify(conn, rows=None) -> dict:
    """Verify linkage and, when present, checkpoint coverage and signature."""
    if rows is None:
        rows = conn.execute("SELECT * FROM admin_audit ORDER BY id").fetchall()
    prev = GENESIS
    for r in rows:
        expected = entry_hash(prev, r["ts"], r["actor"], r["action"], r["detail"] or "")
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return {"valid": False, "entries_checked": 0, "head": prev,
                    "first_bad_entry": r["id"],
                    "checkpoint_signature_valid": None, "covered": False,
                    "reason": "audit log hash chain broken"}
        prev = r["entry_hash"]

    cp = latest_checkpoint(conn)
    result = {"valid": True, "entries_checked": len(rows), "head": prev,
              "checkpoint": dict(cp) if cp else None,
              "checkpoint_signature_valid": None,
              "covered": False}
    if cp is None:
        return result
    height = cp["height"]
    if (type(height) is not int or height < 0
            or not isinstance(cp["head_hash"], str) or not isinstance(cp["signature"], str)):
        return {**result, "valid": False, "covered": False,
                "reason": "audit-log checkpoint row is malformed"}
    result["covered"] = len(rows) >= height
    if len(rows) < height:
        return {**result, "valid": False,
                "reason": "audit log is shorter than the signed checkpoint"}
    expected_head = GENESIS if height == 0 else rows[height - 1]["entry_hash"]
    if expected_head != cp["head_hash"]:
        return {**result, "valid": False,
                "reason": "audit log does not match the signed checkpoint"}
    try:
        signature_valid = sg.verify(rc.authority_public_hex(), cp["signature"],
                                    checkpoint_message(height, cp["head_hash"]))
    except (TypeError, ValueError):
        signature_valid = False
    result["checkpoint_signature_valid"] = bool(signature_valid)
    if not signature_valid:
        return {**result, "valid": False,
                "reason": "audit-log checkpoint signature invalid"}
    return result
