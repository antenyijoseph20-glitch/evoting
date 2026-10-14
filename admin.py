"""Authenticated, role-based admin API. JSON only (no HTML templating, so no reflected XSS)."""
import sqlite3
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import config
import db
import ledger
import security as sec

router = APIRouter(prefix="/admin", tags=["admin"])


class Login(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)


class VoterIn(BaseModel):
    nin: str = Field(..., pattern=r"^\d{11}$")
    vin: str = Field(..., pattern=r"^[A-Za-z0-9]{6,20}$")
    polling_unit_code: str = Field(..., pattern=r"^[A-Za-z0-9\-]{3,32}$")
    phone_number: str = Field(..., pattern=r"^\+\d{10,15}$")


def audit(conn, actor: str, action: str, detail: str = "") -> None:
    conn.execute("INSERT INTO admin_audit (ts, actor, action, detail) VALUES (?,?,?,?)",
                 (sec.iso(sec.now_utc()), actor, action, detail))


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
        rows = c.execute("SELECT * FROM ledger ORDER BY block_index").fetchall()
    return ledger.verify_chain(rows)
