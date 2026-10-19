"""Authenticated, role-based admin API. JSON only (no HTML templating, so no reflected XSS)."""
import json
import sqlite3
from typing import Callable, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import config
import db
import audit_log as alog
import results_core as rc
import security as sec

router = APIRouter(prefix="/admin", tags=["admin"])

ALL_PARTIES = {p for parties in config.ELECTION_PARTIES.values() for p in parties}


class Login(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)


class VoterIn(BaseModel):
    nin: str = Field(..., pattern=r"^\d{11}$")
    vin: str = Field(..., pattern=r"^[A-Za-z0-9]{6,20}$")
    polling_unit_code: str = Field(..., pattern=r"^[A-Za-z0-9\-]{3,32}$")
    phone_number: str = Field(..., pattern=r"^\+\d{10,15}$")


class OfficerIn(BaseModel):
    officer_id: str = Field(..., pattern=r"^[A-Za-z0-9_.\-]{2,64}$")
    name: str = Field(..., min_length=1, max_length=120)
    role: Literal["PRESIDING_OFFICER", "PARTY_AGENT"]
    polling_unit_code: str = Field(..., pattern=r"^[A-Za-z0-9\-]{3,32}$")
    party_code: str | None = Field(None, max_length=16)
    public_key: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class ReviewIn(BaseModel):
    resolution: Literal["ACCEPT", "VOID"]
    note: str = Field("", max_length=500)


def audit(conn, actor: str, action: str, detail: str = "") -> None:
    """Append a hash-chained administrative audit entry (call inside db.tx)."""
    alog.append(conn, actor, action, detail)


def require_role(*roles: str) -> Callable:
    def dep(request: Request) -> dict:
        th = sec.token_hash(sec.bearer(request))
        with db.read() as c:
            row = c.execute("SELECT a.username, a.role, s.expires_at FROM admin_sessions s "
                            "JOIN admins a ON a.username=s.username WHERE s.token_hash=?", (th,)).fetchone()
        if not row or sec.is_expired(row["expires_at"]):
            raise HTTPException(401, "Invalid or expired admin session.")
        if row["role"] not in roles:
            raise HTTPException(403, "Insufficient role.")
        return {"username": row["username"], "role": row["role"]}
    return dep


@router.post("/login")
def login(payload: Login, request: Request):
    sec.rate_limit(request, "admin-login", 5, 300)
    result = None
    with db.tx() as c:
        a = c.execute("SELECT * FROM admins WHERE username=?", (payload.username,)).fetchone()
        # always run scrypt so response time doesn't reveal whether the user exists
        salt = a["pw_salt"] if a else b"\0" * 16
        pw_ok = sec.check_password(payload.password, salt, a["pw_hash"] if a else b"\0" * 32)
        if a and pw_ok:
            token = sec.new_token()
            c.execute("INSERT INTO admin_sessions (token_hash, username, expires_at) VALUES (?,?,?)",
                      (sec.token_hash(token), a["username"], sec.in_minutes(config.ADMIN_TTL_MIN)))
            audit(c, a["username"], "LOGIN")
            result = {"token": token, "role": a["role"], "expires_in_minutes": config.ADMIN_TTL_MIN}
        else:
            audit(c, payload.username[:64], "LOGIN_FAILED")
    if result is None:  # raised after commit so the failed attempt stays in the audit trail
        raise HTTPException(401, "Invalid credentials.")
    return result


@router.post("/voters")
def register_voter(v: VoterIn, who=Depends(require_role("ADMIN", "REGISTRAR"))):
    vh = sec.voter_hash(v.nin, v.vin)
    try:
        with db.tx() as c:
            c.execute("INSERT INTO voters (voter_hash, polling_unit_code, phone_number) VALUES (?,?,?)",
                      (vh, v.polling_unit_code, v.phone_number))
            audit(c, who["username"], "REGISTER_VOTER", f"pu={v.polling_unit_code}")  # never log NIN/VIN
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Voter already registered.")
    return {"status": "registered"}


@router.post("/elections/{election_type}/{action}")
def set_election_state(election_type: str, action: str, who=Depends(require_role("ADMIN"))):
    transitions = {"open": ("PENDING", "OPEN"), "close": ("OPEN", "CLOSED")}
    if action not in transitions or election_type not in config.ELECTION_PARTIES:
        raise HTTPException(404, "Unknown election or action.")
    frm, to = transitions[action]
    with db.tx() as c:
        cur = c.execute("UPDATE elections SET status=? WHERE election_type=? AND status=?", (to, election_type, frm))
        if cur.rowcount != 1:
            raise HTTPException(409, f"Election must be {frm} to {action}.")
        audit(c, who["username"], f"ELECTION_{action.upper()}", election_type)
    return {"election_type": election_type, "status": to}


@router.get("/tally")
def tally(who=Depends(require_role("ADMIN", "AUDITOR"))):
    """Results are released only for CLOSED elections, so no partial results leak during voting."""
    with db.read() as c:
        rows = c.execute("SELECT l.election_type, l.party_code, COUNT(*) AS votes FROM ledger l "
                         "JOIN elections e ON e.election_type=l.election_type AND e.status='CLOSED' "
                         "GROUP BY l.election_type, l.party_code ORDER BY l.election_type, votes DESC").fetchall()
        status = {r["election_type"]: r["status"] for r in c.execute("SELECT * FROM elections")}
    return {"election_status": status, "results": [dict(r) for r in rows]}


@router.get("/audit/export")
def export_ledger(who=Depends(require_role("ADMIN", "AUDITOR"))):
    with db.read() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM ledger ORDER BY block_index")]
    return {"total_blocks": len(rows), "ledger": rows}


@router.get("/audit/verify-chain")
def verify_chain(who=Depends(require_role("ADMIN", "AUDITOR"))):
    with db.read() as c:
        return rc.verify_ledger_chain(c)


# ---------- session / identity ----------
@router.get("/me")
def me(who=Depends(require_role("ADMIN", "REGISTRAR", "AUDITOR"))):
    return who


@router.post("/logout")
def logout(request: Request, who=Depends(require_role("ADMIN", "REGISTRAR", "AUDITOR"))):
    th = sec.token_hash(sec.bearer(request))
    with db.tx() as c:
        c.execute("DELETE FROM admin_sessions WHERE token_hash=?", (th,))
        audit(c, who["username"], "LOGOUT")
    return {"status": "logged_out"}


# ---------- oversight data ----------
@router.get("/elections")
def list_elections(who=Depends(require_role("ADMIN", "REGISTRAR", "AUDITOR"))):
    with db.read() as c:
        rows = c.execute("SELECT * FROM elections ORDER BY election_type").fetchall()
    return {"elections": [{"election_type": r["election_type"],
                           "name": config.ELECTION_NAMES.get(r["election_type"], r["election_type"]),
                           "status": r["status"]} for r in rows]}


@router.get("/voters")
def list_voters(polling_unit_code: str | None = None, limit: int = 50, offset: int = 0,
                who=Depends(require_role("ADMIN", "REGISTRAR"))):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    q, params = "SELECT id, voter_hash, polling_unit_code, phone_number FROM voters", []
    if polling_unit_code:
        q += " WHERE polling_unit_code=?"
        params.append(polling_unit_code)
    q += " ORDER BY id LIMIT ? OFFSET ?"
    params += [limit, offset]
    with db.read() as c:
        rows = c.execute(q, params).fetchall()
    # Never expose NIN/VIN (not stored) or the full keyed hash.
    return {"voters": [{"id": r["id"], "reference": r["voter_hash"][:12],
                        "polling_unit_code": r["polling_unit_code"],
                        "phone": sec.mask_phone(r["phone_number"])} for r in rows]}


@router.get("/officers")
def list_officers(who=Depends(require_role("ADMIN"))):
    with db.read() as c:
        rows = c.execute("SELECT * FROM officers ORDER BY polling_unit_code, role, officer_id").fetchall()
    return {"officers": [dict(r) for r in rows]}


@router.post("/officers")
def add_officer(o: OfficerIn, who=Depends(require_role("ADMIN"))):
    if o.role == "PARTY_AGENT":
        if not o.party_code or o.party_code not in ALL_PARTIES:
            raise HTTPException(422, "A PARTY_AGENT needs a valid party_code.")
    elif o.party_code:
        raise HTTPException(422, "A PRESIDING_OFFICER must not have a party_code.")
    try:
        with db.tx() as c:
            c.execute("INSERT INTO officers (officer_id, name, role, polling_unit_code, party_code, "
                      "public_key) VALUES (?,?,?,?,?,?)",
                      (o.officer_id, o.name, o.role, o.polling_unit_code, o.party_code, o.public_key))
            audit(c, who["username"], "REGISTER_OFFICER", f"{o.role} pu={o.polling_unit_code}")
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Officer ID already registered.")
    return {"status": "registered", "officer_id": o.officer_id}


@router.post("/officers/{officer_id}/{action}")
def set_officer_state(officer_id: str, action: str, who=Depends(require_role("ADMIN"))):
    if action not in ("activate", "deactivate"):
        raise HTTPException(404, "Unknown action.")
    active = 1 if action == "activate" else 0
    with db.tx() as c:
        cur = c.execute("UPDATE officers SET active=? WHERE officer_id=?", (active, officer_id))
        if cur.rowcount != 1:
            raise HTTPException(404, "Officer not found.")
        audit(c, who["username"], f"OFFICER_{action.upper()}", officer_id)
    return {"officer_id": officer_id, "active": bool(active)}


@router.get("/audit")
def read_audit(limit: int = 100, offset: int = 0,
               who=Depends(require_role("ADMIN", "AUDITOR"))):
    limit, offset = max(1, min(limit, 500)), max(0, offset)
    with db.read() as c:
        rows = c.execute("SELECT * FROM admin_audit ORDER BY id DESC LIMIT ? OFFSET ?",
                         (limit, offset)).fetchall()
    return {"audit": [dict(r) for r in rows]}


@router.get("/stats")
def stats(who=Depends(require_role("ADMIN", "REGISTRAR", "AUDITOR"))):
    with db.read() as c:
        voters = c.execute("SELECT COUNT(*) FROM voters").fetchone()[0]
        vote_rows = c.execute("SELECT * FROM ledger ORDER BY block_index").fetchall()
        ledger_cp = rc.latest_ledger_checkpoint(c)
        statuses = {r["election_type"]: r["status"] for r in c.execute("SELECT * FROM elections")}
        sheets = c.execute("SELECT COUNT(*) FROM result_sheets").fetchone()[0]
        pending_review = c.execute("SELECT COUNT(*) FROM result_sheets WHERE flags != '' "
                                   "AND review_status='PENDING'").fetchone()[0]
        sheet_chain = rc.verify_sheet_chain(c)
        sheet_cp = c.execute("SELECT * FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
        sheet_cp_check = rc.verify_checkpoint(c)
        check = rc.verify_ledger_chain(c, vote_rows)
        audit_cp = alog.latest_checkpoint(c)
        audit_check = alog.verify(c)
    return {"voters": voters, "votes_cast": len(vote_rows),
            "ledger_chain": check,
            "ledger_checkpoint": dict(ledger_cp) if ledger_cp else None,
            "audit_chain": audit_check,
            "audit_checkpoint": dict(audit_cp) if audit_cp else None,
            "elections": statuses,
            "open_elections": [t for t, s in statuses.items() if s == "OPEN"],
            "result_sheets": sheets, "pending_review": pending_review,
            "sheet_chain": sheet_chain,
            "result_checkpoint": dict(sheet_cp) if sheet_cp else None,
            "result_checkpoint_check": sheet_cp_check}


@router.get("/results")
def list_results(election_type: str | None = None, limit: int = 200,
                 who=Depends(require_role("ADMIN", "AUDITOR"))):
    limit = max(1, min(limit, 500))
    q, params = "SELECT * FROM result_sheets", []
    if election_type:
        q += " WHERE election_type=?"
        params.append(election_type)
    q += " ORDER BY block_index LIMIT ?"
    params.append(limit)
    with db.read() as c:
        rows = c.execute(q, params).fetchall()
        cs = {r["block_index"]: r["n"] for r in c.execute(
            "SELECT block_index, COUNT(*) AS n FROM countersignatures GROUP BY block_index")}
    sheets = []
    for r in rows:
        try:
            payload = json.loads(r["payload"])
        except (TypeError, ValueError):
            payload = None  # surface the damaged row instead of breaking the page
        sheets.append({
            "block_index": r["block_index"], "election_type": r["election_type"],
            "polling_unit_code": r["polling_unit_code"], "payload": payload,
            "payload_hash": r["payload_hash"], "officer_id": r["officer_id"],
            "flags": r["flags"].split(",") if r["flags"] else [],
            "review_status": r["review_status"], "reviewed_by": r["reviewed_by"],
            "reviewed_at": r["reviewed_at"], "review_note": r["review_note"],
            "countersignatures": cs.get(r["block_index"], 0), "block_hash": r["block_hash"],
        })
    return {"sheets": sheets}


@router.post("/results/{election_type}/{pu}/review")
def review_result(election_type: str, pu: str, body: ReviewIn, who=Depends(require_role("ADMIN"))):
    try:
        with db.tx() as c:
            result = rc.review_sheet(c, election_type, pu, body.resolution, who["username"], body.note)
            audit(c, who["username"], f"RESULT_REVIEW_{body.resolution}",
                  f"{election_type}/{pu} note={body.note[:120]}")
    except rc.ResultError as e:
        raise HTTPException(e.status, e.message)
    return result


@router.post("/audit/checkpoint")
def ledger_checkpoint(who=Depends(require_role("ADMIN"))):
    with db.tx() as c:
        cp = rc.create_ledger_checkpoint(c)
        audit(c, who["username"], "LEDGER_CHECKPOINT", f"height={cp['height']}")
    return cp


@router.post("/audit/log-checkpoint")
def audit_log_checkpoint(who=Depends(require_role("ADMIN"))):
    """Sign the admin audit-log head. The entry recording this action is covered too."""
    with db.tx() as c:
        audit(c, who["username"], "AUDIT_LOG_CHECKPOINT")
        return alog.create_checkpoint(c)


@router.get("/audit/verify-log")
def verify_audit_log(who=Depends(require_role("ADMIN", "AUDITOR"))):
    with db.read() as c:
        return alog.verify(c)


@router.get("/audit/log-export")
def export_audit_log(who=Depends(require_role("ADMIN", "AUDITOR"))):
    """Everything an independent reviewer needs to recompute the audit hash chain."""
    with db.read() as c:
        entries = [dict(r) for r in c.execute("SELECT * FROM admin_audit ORDER BY id")]
        cp = alog.latest_checkpoint(c)
        check = alog.verify(c)
    return {"entries": entries, "checkpoint": dict(cp) if cp else None,
            "authority_public_key": rc.authority_public_hex(), "verification": check}


@router.get("/results/export")
def export_results(who=Depends(require_role("ADMIN", "AUDITOR"))):
    """Internal audit export. The public /results/export stays locked while voting is open."""
    with db.read() as c:
        data = rc.export_all(c)
    return data
