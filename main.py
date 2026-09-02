"""
main.py - Persistent E-Voting Core Server with Public Tally & Zero-Knowledge Audit Engine
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import json
import logging
import secrets
import sqlite3
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EVotingCore")

DB_FILE = "evoting.db"

# =====================================================================
# DATABASE SETUP & INITIALIZATION
# =====================================================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS issued_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vin TEXT UNIQUE NOT NULL,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ballot_box (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate TEXT NOT NULL,
            nonce TEXT UNIQUE NOT NULL,
            signature TEXT UNIQUE NOT NULL,
            recorded_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# =====================================================================
# MOCK REGISTRY & SESSION STORE
# =====================================================================

MOCK_INEC_REGISTRY = {
    "9012345678901234567": {
        "nin": "12345678901",
        "name": "Antenyi Joseph Ochohepo",
        "state": "Benue",
        "lga": "Otukpo",
        "polling_unit": "PU 004, Ojoo Hall",
        "is_eligible": True
    }
}

class SessionStore:
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def set_session(self, token: str, data: dict):
        self.sessions[token] = data

    def get_session(self, token: str) -> Optional[dict]:
        return self.sessions.get(token)

    def mark_spent(self, token: str):
        if token in self.sessions:
            self.sessions[token]["is_spent"] = True

session_store = SessionStore()

# =====================================================================
# CRYPTO ENGINE
# =====================================================================

class CryptoEngine:
    def __init__(self):
        self.e = 17
        self.d = 2753
        self.n = 3233

    def sign_blinded_message(self, m_prime: int) -> int:
        return pow(m_prime, self.d, self.n)

    def verify_ballot_signature(self, candidate: str, nonce: str, signature: int) -> bool:
        raw_bytes = f"{candidate}:{nonce}".encode("utf-8")
        expected_m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % self.n
        recovered_m = pow(signature, self.e, self.n)
        return expected_m == recovered_m

crypto_engine = CryptoEngine()

# =====================================================================
# FASTAPI LIFESPAN
# =====================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing SQLite database tables...")
    init_db()
    yield
    logger.info("Shutting down core engine...")

app = FastAPI(title="E-Voting Core Engine with Public Audit", lifespan=lifespan)

# =====================================================================
# MODELS
# =====================================================================

class AuthRequest(BaseModel):
    vin: str = Field(..., min_length=19, max_length=19, json_schema_extra={"example": "9012345678901234567"})
    nin: str = Field(..., min_length=11, max_length=11, json_schema_extra={"example": "12345678901"})

class BlindSignRequest(BaseModel):
    session_token: str
    blinded_message: int

class SubmitVoteRequest(BaseModel):
    candidate: str = Field(..., json_schema_extra={"example": "LP"})
    nonce: str = Field(..., json_schema_extra={"example": "8fca7b64f46c042b624f1ef4646cd4b6"})
    signature: int

class ReceiptVerificationResponse(BaseModel):
    status: str
    verified: bool
    candidate: str
    nonce: str
    signature: int
    recorded_at: str

class TallyResultsResponse(BaseModel):
    status: str
    total_votes_cast: int
    tally: Dict[str, int]

class AuditReportResponse(BaseModel):
    status: str
    total_ballots_audited: int
    valid_ballots_count: int
    invalid_ballots_count: int
    integrity_verified: bool
    audit_timestamp: str

# =====================================================================
# ROUTE CONTROLLERS
# =====================================================================

@app.post("/api/v1/auth/verify")
async def verify_voter(payload: AuthRequest):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT vin FROM issued_signatures WHERE vin = ?", (payload.vin,))
    row = cursor.fetchone()
    conn.close()

    if row:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Voter has already been issued a ballot token."
        )

    voter = MOCK_INEC_REGISTRY.get(payload.vin)
    if not voter or voter["nin"] != payload.nin or not voter["is_eligible"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="INEC Registry lookup failed or invalid credentials."
        )

    session_token = f"sess_{secrets.token_hex(16)}"
    session_store.set_session(session_token, {"voter_vin": payload.vin, "is_spent": False})

    return {
        "status": "SUCCESS",
        "voter_name": voter["name"],
        "session_token": session_token
    }

@app.post("/api/v1/authority/blind-sign")
async def blind_sign(payload: BlindSignRequest):
    session = session_store.get_session(payload.session_token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired session token."
        )

    if session.get("is_spent"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session token has already been used for blind signing."
        )

    voter_vin = session["voter_vin"]

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Use UNIQUE index constraint check directly to prevent race conditions
    try:
        cursor.execute("INSERT INTO issued_signatures (vin) VALUES (?)", (voter_vin,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Voter has already requested a blind signature."
        )
    conn.close()

    blinded_sig = crypto_engine.sign_blinded_message(payload.blinded_message)
    session_store.mark_spent(payload.session_token)

    return {
        "status": "SUCCESS",
        "blinded_signature": blinded_sig
    }

@app.post("/api/v1/ballotbox/submit-vote")
async def submit_vote(payload: SubmitVoteRequest):
    if not crypto_engine.verify_ballot_signature(payload.candidate, payload.nonce, payload.signature):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="INVALID SIGNATURE: Ballot cryptographic signature verification failed."
        )

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        # Store signature as string to prevent int64 overflow
        cursor.execute(
            "INSERT INTO ballot_box (candidate, nonce, signature, recorded_at) VALUES (?, ?, ?, ?)",
            (payload.candidate, payload.nonce, str(payload.signature), timestamp)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="REPLAY DETECTED: This ballot nonce or signature has already been cast."
        )
    conn.close()

    return {"status": "SUCCESS", "message": "Ballot verified and recorded successfully."}

@app.get("/api/v1/ballotbox/verify-receipt/{nonce}", response_model=ReceiptVerificationResponse)
async def verify_receipt(nonce: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT candidate, nonce, signature, recorded_at FROM ballot_box WHERE nonce = ?", (nonce,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="BALLOT NOT FOUND: No record matching this receipt nonce exists in the ballot box."
        )

    candidate, db_nonce, signature_str, recorded_at = row
    signature = int(signature_str)
    is_valid = crypto_engine.verify_ballot_signature(candidate, db_nonce, signature)

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="BALLOT TAMPERED: Cryptographic signature failure detected on stored ballot."
        )

    return {
        "status": "RECORDED_AND_VERIFIED",
        "verified": True,
        "candidate": candidate,
        "nonce": db_nonce,
        "signature": signature,
        "recorded_at": recorded_at
    }

@app.get("/api/v1/tally/results", response_model=TallyResultsResponse)
async def get_election_results():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT candidate, COUNT(*) FROM ballot_box GROUP BY candidate")
    rows = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM ballot_box")
    total_votes = cursor.fetchone()[0]
    conn.close()

    tally = {candidate: count for candidate, count in rows}

    return {
        "status": "SUCCESS",
        "total_votes_cast": total_votes,
        "tally": tally
    }

@app.get("/api/v1/tally/audit", response_model=AuditReportResponse)
async def run_global_audit():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT candidate, nonce, signature FROM ballot_box")
    ballots = cursor.fetchall()
    conn.close()

    total_ballots = len(ballots)
    valid_count = 0
    invalid_count = 0

    for candidate, nonce, signature_str in ballots:
        signature = int(signature_str)
        is_valid = crypto_engine.verify_ballot_signature(candidate, nonce, signature)
        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1

    integrity_verified = (total_ballots > 0) and (invalid_count == 0) and (valid_count == total_ballots)

    return {
        "status": "AUDIT_COMPLETE",
        "total_ballots_audited": total_ballots,
        "valid_ballots_count": valid_count,
        "invalid_ballots_count": invalid_count,
        "integrity_verified": integrity_verified,
        "audit_timestamp": datetime.now(timezone.utc).isoformat()
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)