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


def _wrap(fn, *a):
    try:
        return fn(*a)
    except rc.ResultError as e:
        raise HTTPException(e.status, e.message)


@router.post("/submit")
def submit(body: Submit, request: Request):
    sec.rate_limit(request, "results-submit", 20, 60)
    with db.tx() as c:
        return _wrap(rc.submit_sheet, c, body.payload, body.officer_id, body.signature)


@router.post("/{election_type}/{pu}/countersign")
def countersign(election_type: str, pu: str, body: Counter, request: Request):
    sec.rate_limit(request, "results-counter", 30, 60)
    with db.tx() as c:
        return _wrap(rc.countersign, c, election_type, pu, body.officer_id, body.signature)


@router.get("/sheet/{election_type}/{pu}")
def get_sheet(election_type: str, pu: str):
    with db.read() as c:
        s = c.execute("SELECT * FROM result_sheets WHERE election_type=? AND polling_unit_code=?",
                      (election_type, pu)).fetchone()
        if not s:
            raise HTTPException(404, "No result sheet found.")
        cs = [dict(r) for r in c.execute("SELECT officer_id, signature FROM countersignatures WHERE block_index=?",
                                         (s["block_index"],))]
    return {"sheet": dict(s), "countersignatures": cs}


@router.get("/tally/{election_type}")
def public_tally(election_type: str):
    with db.read() as c:
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
        audit(c, who["username"], "CHECKPOINT", f"size={cp['tree_size']}")
    return cp


@router.get("/export")
def export():
    with db.read() as c:
        return rc.export_all(c)
