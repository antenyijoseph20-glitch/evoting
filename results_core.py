"""Polling-unit result logic (EC8A-style). No web framework dependency, so it is unit-testable."""
import json
import os
import stat
from datetime import datetime

import config
import merkle
import signing as sg

GENESIS = "0" * 64
MAX_COUNT = 1_000_000


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
    path = os.getenv("EVOTING_AUTHORITY_KEY") or "authority_ed25519.key"
    if os.path.exists(path):
        _authority = sg.load_private(open(path, "rb").read())
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
    if not isinstance(p, dict) or set(p) != need or p["v"] != 1:
        raise ResultError(422, "Payload must contain exactly: " + ", ".join(sorted(need)) + " (v=1).")
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


def _leaves(conn, size: int | None = None) -> list[bytes]:
    rows = conn.execute("SELECT block_hash FROM result_sheets ORDER BY block_index").fetchall()
    leaves = [bytes.fromhex(r["block_hash"]) for r in rows]
    return leaves if size is None else leaves[:size]


def create_checkpoint(conn) -> dict:
    leaves = _leaves(conn)
    r = merkle.root(leaves).hex()
    sig = sg.sign(authority_key(), sg.checkpoint_message(len(leaves), r))
    ts = datetime.now().astimezone().isoformat()
    conn.execute("INSERT INTO checkpoints (tree_size, root, signature, created_at) VALUES (?,?,?,?)",
                 (len(leaves), r, sig, ts))
    return {"tree_size": len(leaves), "root": r, "signature": sig, "created_at": ts,
            "authority_public_key": authority_public_hex()}


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


def tally(conn, election_type: str) -> dict:
    rows = conn.execute("SELECT polling_unit_code, payload, flags FROM result_sheets WHERE election_type=?",
                        (election_type,)).fetchall()
    totals, counted, accredited, flagged = {}, 0, 0, []
    for r in rows:
        if r["flags"]:
            flagged.append({"polling_unit_code": r["polling_unit_code"], "flags": r["flags"].split(",")})
            continue  # flagged sheets are excluded pending review
        p = json.loads(r["payload"])
        counted += 1
        accredited += p["accredited"]
        for party, n in p["scores"].items():
            totals[party] = totals.get(party, 0) + n
    return {"election_type": election_type, "sheets_counted": counted, "total_accredited": accredited,
            "totals": dict(sorted(totals.items(), key=lambda kv: -kv[1])), "flagged_excluded": flagged}


def export_all(conn) -> dict:
    sheets = [dict(r) for r in conn.execute("SELECT * FROM result_sheets ORDER BY block_index")]
    counters = [dict(r) for r in conn.execute("SELECT * FROM countersignatures")]
    officers = {r["officer_id"]: {"public_key": r["public_key"], "role": r["role"],
                                  "polling_unit_code": r["polling_unit_code"], "party_code": r["party_code"]}
                for r in conn.execute("SELECT * FROM officers")}
    cp = conn.execute("SELECT * FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
    return {"sheets": sheets, "countersignatures": counters, "officers": officers,
            "checkpoint": dict(cp) if cp else None, "authority_public_key": authority_public_hex()}
