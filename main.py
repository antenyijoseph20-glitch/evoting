"""Voter-facing API. Every step is enforced server-side."""
import re
import sqlite3
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import config
import db
import ledger
import results_core as rc
import security as sec
from admin import router as admin_router
from results import router as results_router

HEX64 = re.compile(r"^[0-9a-f]{64}$")
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not config.DEV:
        blockers = config.production_blockers()
        if blockers:
            raise RuntimeError("Refusing to start in production:\n - " + "\n - ".join(blockers))
        try:
            sec.load_face_matcher()
        except Exception as e:
            raise RuntimeError(f"EVOTING_FACE_MATCHER could not be loaded: {e}")
    db.init_db()
    rc.authority_key()  # load or create once, fail early if missing in production
    yield


app = FastAPI(title="E2E-V Voting System (research prototype)", version="3.0.0", lifespan=lifespan,
              docs_url="/docs" if config.DEV else None, redoc_url=None)
app.include_router(admin_router)
app.include_router(results_router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Permissions-Policy"] = "camera=(self)"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
        "connect-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; "
        "form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'")
    if not config.DEV:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# ---------- schemas ----------
class VerifyRequest(BaseModel):
    nin: str = Field(..., pattern=r"^\d{11}$")
    vin: str = Field(..., pattern=r"^[A-Za-z0-9]{6,20}$")


class OTPVerify(BaseModel):
    otp_code: str = Field(..., pattern=r"^\d{6}$")


class BallotRequest(BaseModel):
    election_type: str
    party_code: str


# ---------- session helper (call inside a tx) ----------
def load_session(conn, token: str):
    row = conn.execute("SELECT s.*, v.polling_unit_code FROM sessions s JOIN voters v ON v.id=s.voter_id "
                       "WHERE s.token_hash=?", (sec.token_hash(token),)).fetchone()
    if not row or sec.is_expired(row["expires_at"]):
        raise HTTPException(401, "Invalid or expired session.")
    return row


# ---------- routes ----------
@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/admin")
def admin_page():
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/results")
def results_page():
    return FileResponse(STATIC_DIR / "results.html")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    try:
        with db.read() as c:
            c.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        raise HTTPException(503, "Database unavailable.")
    return {"status": "ready"}


@app.get("/api/v1/elections")
def public_elections():
    with db.read() as c:
        status = {r["election_type"]: r["status"] for r in c.execute("SELECT * FROM elections")}
    return {"elections": [
        {"election_type": t, "name": config.ELECTION_NAMES.get(t, t),
         "status": status.get(t, "PENDING"),
         "parties": [{"code": p, "name": config.PARTY_NAMES.get(p, p)} for p in parties]}
        for t, parties in config.ELECTION_PARTIES.items()]}


@app.get("/api/v1/receipt/{block_hash}")
def verify_receipt(block_hash: str):
    """Public proof that a cast-ballot receipt exists in the chain. No voter data is stored."""
    block_hash = block_hash.lower()
    if not HEX64.match(block_hash):
        raise HTTPException(400, "Receipt hash must be 64 lowercase hex characters.")
    with db.read() as c:
        block = c.execute("SELECT * FROM ledger WHERE block_hash=?", (block_hash,)).fetchone()
        if not block:
            raise HTTPException(404, "No ledger block matches this receipt.")
        rows = c.execute("SELECT * FROM ledger ORDER BY block_index").fetchall()
        cp = rc.latest_ledger_checkpoint(c)
        check = rc.verify_ledger_chain(c, rows)
    return {"found": True, "block": dict(block), "chain": check,
            "latest_checkpoint": dict(cp) if cp else None,
            "authority_public_key": rc.authority_public_hex() if cp else None}


@app.get("/api/v1/audit/ledger")
def public_ledger():
    """Publish vote blocks only for CLOSED elections, so partial results cannot be tallied early."""
    with db.read() as c:
        closed = {r["election_type"] for r in
                  c.execute("SELECT election_type FROM elections WHERE status='CLOSED'")}
        rows = c.execute("SELECT * FROM ledger ORDER BY block_index").fetchall()
        cp = rc.latest_ledger_checkpoint(c)
        check = rc.verify_ledger_chain(c, rows)
    visible = [dict(r) for r in rows if r["election_type"] in closed]
    return {"blocks": visible, "visible_blocks": len(visible), "ledger_height": len(rows),
            "chain": check, "checkpoint": dict(cp) if cp else None,
            "authority_public_key": rc.authority_public_hex() if cp else None,
            "note": "Only blocks from CLOSED elections are published."}



@app.post("/api/v1/auth/verify")
def verify(payload: VerifyRequest, request: Request):
    """Step 1: voter must already be on the register. No auto-enrolment."""
    sec.rate_limit(request, "verify", 10, 60)
    vh = sec.voter_hash(payload.nin, payload.vin)
    token, otp = sec.new_token(), sec.new_otp()
    th = sec.token_hash(token)
    with db.tx() as c:
        v = c.execute("SELECT id, phone_number FROM voters WHERE voter_hash=?", (vh,)).fetchone()
        if not v:
            raise HTTPException(401, "Voter not found on the register.")
        now = sec.now_utc()
        c.execute("DELETE FROM sessions WHERE expires_at <= ?", (sec.iso(now),))
        cutoff = sec.iso(now.replace(microsecond=0) - timedelta(hours=1))
        c.execute("DELETE FROM voter_attempts WHERE created_at <= ?", (cutoff,))
        recent = c.execute("SELECT COUNT(*) FROM voter_attempts WHERE voter_id=?",
                           (v["id"],)).fetchone()[0]
        if recent >= config.MAX_SESSIONS_PER_VOTER_PER_HOUR:
            raise HTTPException(429, "Too many attempts for this voter. Contact the polling officer.")
        c.execute("INSERT INTO voter_attempts (voter_id, created_at) VALUES (?,?)",
                  (v["id"], sec.iso(now)))
        c.execute("DELETE FROM sessions WHERE voter_id=?", (v["id"],))  # one live session per voter
        c.execute("INSERT INTO sessions (token_hash, voter_id, created_at, expires_at, otp_hash, otp_expires_at) "
                  "VALUES (?,?,?,?,?,?)",
                  (th, v["id"], sec.iso(now), sec.in_minutes(config.SESSION_TTL_MIN),
                   sec.otp_hash(th, otp), sec.in_minutes(config.OTP_TTL_MIN)))
    try:
        sec.send_sms(v["phone_number"], otp)
    except sec.SmsDeliveryError:
        # Do not leave a live session the voter cannot complete; they may retry immediately.
        with db.tx() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (th,))
        raise HTTPException(503, "Could not send the one-time code. Please try again.")
    return {"status": "otp_sent", "session_token": token, "phone": sec.mask_phone(v["phone_number"]),
            "otp_expires_in_seconds": config.OTP_TTL_MIN * 60}


@app.post("/api/v1/auth/verify-otp")
def verify_otp(payload: OTPVerify, request: Request):
    sec.rate_limit(request, "otp", 15, 60)
    token = sec.bearer(request)
    ok, reason = False, None
    with db.tx() as c:
        s = load_session(c, token)
        if s["otp_attempts"] >= config.OTP_MAX_ATTEMPTS or sec.is_expired(s["otp_expires_at"]):
            reason = "OTP expired or too many attempts. Restart verification."
        elif sec.hmac.compare_digest(s["otp_hash"], sec.otp_hash(s["token_hash"], payload.otp_code)):
            c.execute("UPDATE sessions SET otp_verified=1 WHERE token_hash=?", (s["token_hash"],))
            ok = True
        else:
            c.execute("UPDATE sessions SET otp_attempts=otp_attempts+1 WHERE token_hash=?", (s["token_hash"],))
            reason = "Incorrect OTP."
    if not ok:  # raised after commit so the attempt counter persists
        raise HTTPException(401, reason)
    return {"status": "otp_verified"}


@app.post("/api/v1/biometric/verify-face")
def verify_face(request: Request, file: UploadFile = File(...)):
    sec.rate_limit(request, "face", 15, 60)
    token = sec.bearer(request)
    data = file.file.read(config.MAX_UPLOAD_BYTES + 1)
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Image too large.")
    ok, reason = False, None
    with db.tx() as c:
        s = load_session(c, token)
        if not s["otp_verified"]:
            raise HTTPException(403, "Complete OTP verification first.")
        if s["face_attempts"] >= config.FACE_MAX_ATTEMPTS:
            reason = "Too many failed attempts. See the polling officer."
        else:
            c.execute("UPDATE sessions SET face_attempts=face_attempts+1 WHERE token_hash=?", (s["token_hash"],))
            if sec.face_check(data):
                c.execute("UPDATE sessions SET face_verified=1 WHERE token_hash=?", (s["token_hash"],))
                ok = True
            else:
                reason = "No single clear face detected. Try again."
    if not ok:
        raise HTTPException(422, reason)
    return {"status": "face_verified", "mode": "DETECTION_ONLY_DEV" if config.DEV else "MATCHER"}


@app.post("/api/v1/ballot/cast")
def cast_ballot(payload: BallotRequest, request: Request):
    sec.rate_limit(request, "cast", 10, 60)
    token = sec.bearer(request)
    if payload.party_code not in config.ELECTION_PARTIES.get(payload.election_type, []):
        raise HTTPException(400, "Invalid election type or party.")
    with db.tx() as c:  # BEGIN IMMEDIATE: check-and-write is atomic across workers
        s = load_session(c, token)
        if not (s["otp_verified"] and s["face_verified"]):
            raise HTTPException(403, "Accreditation incomplete.")
        status = c.execute("SELECT status FROM elections WHERE election_type=?", (payload.election_type,)).fetchone()
        if not status or status["status"] != "OPEN":
            raise HTTPException(403, "This election is not open for voting.")
        try:
            c.execute("INSERT INTO votes_cast (voter_id, election_type) VALUES (?,?)",
                      (s["voter_id"], payload.election_type))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "You have already voted in this election.")
        last = c.execute("SELECT block_hash FROM ledger ORDER BY block_index DESC LIMIT 1").fetchone()
        prev = last["block_hash"] if last else ledger.GENESIS
        pu = s["polling_unit_code"]  # taken from the register, never from the client
        bh = ledger.compute_hash(prev, payload.election_type, payload.party_code, pu)
        cur = c.execute("INSERT INTO ledger (previous_hash, election_type, party_code, polling_unit_code, block_hash) "
                        "VALUES (?,?,?,?,?)", (prev, payload.election_type, payload.party_code, pu, bh))
        idx = cur.lastrowid
    return {"status": "success", "receipt": {"block_index": idx, "block_hash": bh,
                                              "election_type": payload.election_type}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)  # pass the object: no module re-import, one init
