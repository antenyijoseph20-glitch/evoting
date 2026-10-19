"""Polling-unit results API. Submissions are authenticated by Ed25519 signature, not by a password."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import db
import results_core as rc
from admin import audit, require_role
import security as sec

router = APIRouter(prefix="/results", tags=["polling-unit results"])


class Submit(BaseModel):
    payload: dict
    officer_id: str = Field(..., max_length=64)
    signature: str = Field(..., pattern=r"^[0-9a-f]{128}$")


class Counter(BaseModel):
    officer_id: str = Field(..., max_length=64)
    signature: str = Field(..., pattern=r"^[0-9a-f]{128}$")


def _election_status(conn, election_type: str) -> str:
    row = conn.execute("SELECT status FROM elections WHERE election_type=?", (election_type,)).fetchone()
    if not row:
        raise HTTPException(404, "Unknown election type.")
    return row["status"]


def _require_not_pending(conn, election_type: str) -> None:
    if _election_status(conn, election_type) == "PENDING":
        raise HTTPException(403, "This election has not started.")


def _require_closed(conn, election_type: str) -> None:
    if _election_status(conn, election_type) != "CLOSED":
        raise HTTPException(403, "Results are released only after the election closes.")


def _wrap(fn, *a):
    try:
        return fn(*a)
    except rc.ResultError as e:
        raise HTTPException(e.status, e.message)


@router.post("/submit")
def submit(body: Submit, request: Request):
    sec.rate_limit(request, "results-submit", 20, 60)
    et = body.payload.get("election_type") if isinstance(body.payload, dict) else None
    if not isinstance(et, str):
        raise HTTPException(422, "Payload must include an election_type.")
    try:
        with db.tx() as c:
            _require_not_pending(c, et)
            result = rc.submit_sheet(c, body.payload, body.officer_id, body.signature)
            audit(c, f"officer:{body.officer_id}", "RESULT_SUBMIT",
                  f"{et}/{body.payload.get('polling_unit_code')}")
    except rc.ResultError as e:
        raise HTTPException(e.status, e.message)
    return result


@router.post("/{election_type}/{pu}/countersign")
def countersign(election_type: str, pu: str, body: Counter, request: Request):
    sec.rate_limit(request, "results-counter", 30, 60)
    try:
        with db.tx() as c:
            _require_not_pending(c, election_type)
            result = rc.countersign(c, election_type, pu, body.officer_id, body.signature)
            audit(c, f"officer:{body.officer_id}", "RESULT_COUNTERSIGN", f"{election_type}/{pu}")
    except rc.ResultError as e:
        raise HTTPException(e.status, e.message)
    return result


@router.get("/sheet/{election_type}/{pu}")
def get_sheet(election_type: str, pu: str):
    """Public commitment for any election; the figures themselves only after close."""
    with db.read() as c:
        s = c.execute("SELECT * FROM result_sheets WHERE election_type=? AND polling_unit_code=?",
                      (election_type, pu)).fetchone()
        if not s:
            raise HTTPException(404, "No result sheet found.")
        closed = _election_status(c, election_type) == "CLOSED"
        cs = [dict(r) for r in c.execute("SELECT officer_id, signature FROM countersignatures WHERE block_index=?",
                                         (s["block_index"],))]
    sheet = dict(s)
    if not closed:
        sheet["payload"] = None  # withhold polling-unit figures until release
    return {"sheet": sheet, "countersignatures": cs, "released": closed}


@router.get("/status/{election_type}")
def submission_status(election_type: str):
    """Live operational counts only: never vote totals or per-party figures."""
    with db.read() as c:
        status = _election_status(c, election_type)
        total = c.execute("SELECT COUNT(*) FROM result_sheets WHERE election_type=?",
                          (election_type,)).fetchone()[0]
        flagged = c.execute("SELECT COUNT(*) FROM result_sheets WHERE election_type=? AND flags != ''",
                            (election_type,)).fetchone()[0]
        pending = c.execute("SELECT COUNT(*) FROM result_sheets WHERE election_type=? AND flags != '' "
                            "AND review_status='PENDING'", (election_type,)).fetchone()[0]
    return {"election_type": election_type, "status": status, "sheets_submitted": total,
            "flagged": flagged, "pending_review": pending,
            "results_released": status == "CLOSED"}


@router.get("/tally/{election_type}")
def public_tally(election_type: str):
    with db.read() as c:
        _require_closed(c, election_type)
        return rc.tally(c, election_type)


@router.get("/proof/{election_type}/{pu}")
def proof(election_type: str, pu: str):
    with db.read() as c:
        return _wrap(rc.inclusion_proof, c, election_type, pu)


@router.get("/checkpoint")
def latest_checkpoint():
    with db.read() as c:
        row = c.execute("SELECT * FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
    return {"checkpoint": dict(row) if row else None, "authority_public_key": rc.authority_public_hex()}


@router.post("/checkpoint")
def make_checkpoint(who=Depends(require_role("ADMIN"))):
    with db.tx() as c:
        cp = rc.create_checkpoint(c)
        audit(c, who["username"], "RESULT_CHECKPOINT", f"size={cp['tree_size']}")
    return cp


@router.get("/export")
def export():
    """Full signed archive for independent verification, released once no election is open."""
    with db.read() as c:
        open_count = c.execute("SELECT COUNT(*) FROM elections WHERE status='OPEN'").fetchone()[0]
        if open_count:
            raise HTTPException(403, "Detailed results are locked while an election is open.")
        return rc.export_all(c)
