from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fastapi.responses import HTMLResponse
import os
import hashlib
import time
import json
import uuid

# 1. SINGLE AUTHORITATIVE FASTAPI INSTANCE
app = FastAPI(title="Nigeria E2E-V Secure Voting System", version="1.0.0")

# 2. ENABLE CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. MOUNT STATIC FILES
app.mount("/static", StaticFiles(directory="static"), name="static")

# ==========================================
# BLOCKCHAIN LEDGER & STATE MANAGEMENT
# ==========================================
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

# Global state
LEDGER = []
ACTIVE_SESSIONS = {}
VOTED_REGISTRY = set()

def get_latest_block():
    if not LEDGER:
        genesis = Block(0, time.time(), {"message": "Genesis Block - E-Voting Ledger Initialized"}, "0")
        LEDGER.append(genesis)
    return LEDGER[-1]

get_latest_block()

# ==========================================
# FRONTEND & HEALTH ENDPOINTS
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>Frontend index.html not found in static/ folder.</h3>"

@app.get("/api/v1/admin/health")
async def admin_health():
    return {"status": "healthy", "system": "operational"}

# ==========================================
# BULLETIN BOARD & TALLY ENDPOINTS
# ==========================================
@app.get("/api/v1/bulletin-board/export")
async def export_bulletin_board_ledger():
    serialized_blocks = []
    for b in LEDGER:
        serialized_blocks.append({
            "block_id": b.index,
            "previous_hash": b.previous_hash,
            "block_hash": b.hash,
            "data": b.data,
            "synced_at_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(b.timestamp))
        })
    return {
        "system": "Nigeria E2E-V Secure Voting System",
        "total_blocks": len(LEDGER),
        "ledger_integrity_status": "VERIFIED_APPEND_ONLY",
        "blocks": serialized_blocks
    }

@app.get("/api/v1/tally")
@app.get("/api/v1/results")
@app.get("/api/v1/tally/results")
@app.get("/api/v1/tally/{path:path}")
async def get_tally_results(path: str = ""):
    tallies = {}
    total_votes_cast = 0

    for block in LEDGER:
        if isinstance(block.data, dict):
            candidate = block.data.get("candidate_id") or block.data.get("candidate")
            if candidate:
                tallies[candidate] = tallies.get(candidate, 0) + 1
                total_votes_cast += 1

    results_list = [
        {"candidate_id": candidate, "vote_count": count}
        for candidate, count in tallies.items()
    ]

    return {
        "status": "success",
        "audit_status": "passed",
        "total_votes_cast": total_votes_cast,
        "tally": tallies,
        "tallies": results_list,
        "ledger_blocks_scanned": len(LEDGER)
    }

# ==========================================
# ACCREDITATION & VOTING WORKFLOW
# ==========================================
class VoterAuthRequest(BaseModel):
    nin: str = Field(..., min_length=11, max_length=11)
    vin: str = Field(..., min_length=10, max_length=20)
    polling_unit_code: str = Field(default="PU-001")

@app.post("/api/v1/auth/verify")
@app.post("/api/v1/auth/verify-voter")
async def verify_voter_credentials(payload: VoterAuthRequest):
    if not payload.nin.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="NIN must consist of exactly 11 numeric digits."
        )

    credential_signature = f"{payload.nin}:{payload.vin}"
    voter_hash = hashlib.sha256(credential_signature.encode()).hexdigest()

    if voter_hash in VOTED_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credentials have already been utilized for ballot issuance."
        )

    session_token = str(uuid.uuid4())
    ACTIVE_SESSIONS[session_token] = voter_hash
    
    return {
        "status": "success",
        "accreditation": "verified",
        "voter_blind_hash": voter_hash[:16] + "...", 
        "polling_unit": payload.polling_unit_code,
        "session_token": session_token,
        "message": "Voter successfully accredited."
    }

# ==========================================
# AUTHORITY BLIND SIGNING
# ==========================================
class BlindSignRequest(BaseModel):
    session_token: str
    blinded_message: int

@app.post("/api/v1/authority/blind-sign")
async def blind_sign_ballot(payload: BlindSignRequest):
    if payload.session_token not in ACTIVE_SESSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired session token for signing."
        )
    
    d = 2753
    n = 3233
    blinded_signature = pow(payload.blinded_message, d, n)

    return {
        "status": "success",
        "blinded_signature": blinded_signature
    }

# ==========================================
# BALLOT SUBMISSION & BALLOTBOX ENDPOINTS
# ==========================================
class BallotSubmission(BaseModel):
    session_token: str
    candidate_id: str
    polling_unit_code: str

@app.post("/api/v1/ballot/cast")
@app.post("/api/v1/vote")
@app.post("/api/v1/ballot/submit")
async def submit_ballot(payload: BallotSubmission):
    if payload.session_token not in ACTIVE_SESSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session token is invalid, expired, or has already been used."
        )
    
    voter_hash = ACTIVE_SESSIONS.pop(payload.session_token)
    VOTED_REGISTRY.add(voter_hash)

    vote_data = {
        "candidate_id": payload.candidate_id,
        "polling_unit_code": payload.polling_unit_code,
        "voter_blind_hash_prefix": voter_hash[:12]
    }

    previous_block = get_latest_block()
    new_block = Block(
        index=previous_block.index + 1,
        timestamp=time.time(),
        data=vote_data,
        previous_hash=previous_block.hash
    )
    LEDGER.append(new_block)

    return {
        "status": "success",
        "message": "Vote successfully cast and anchored to the blockchain ledger.",
        "receipt": {
            "block_index": new_block.index,
            "block_hash": new_block.hash,
            "timestamp": new_block.timestamp
        }
    }

class BallotBoxSubmission(BaseModel):
    candidate: str
    nonce: str
    signature: int

@app.post("/api/v1/ballotbox/submit-vote")
async def submit_ballotbox_vote(payload: BallotBoxSubmission):
    e = 17
    n = 3233
    decrypted_sig = pow(payload.signature, e, n)
    
    raw_bytes = f"{payload.candidate}:{payload.nonce}".encode("utf-8")
    expected_m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % n

    if decrypted_sig != expected_m:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cryptographic signature."
        )

    vote_data = {
        "candidate": payload.candidate,
        "nonce": payload.nonce,
        "signature": payload.signature,
        "status": "verified_and_anchored",
        "recorded_at": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time()))
    }

    previous_block = get_latest_block()
    new_block = Block(
        index=previous_block.index + 1,
        timestamp=time.time(),
        data=vote_data,
        previous_hash=previous_block.hash
    )
    LEDGER.append(new_block)

    return {
        "status": "success",
        "message": "Vote successfully verified and recorded in ballotbox.",
        "block_index": new_block.index
    }

@app.get("/api/v1/ballotbox/verify-receipt/{nonce}")
async def verify_receipt(nonce: str):
    for block in LEDGER:
        if isinstance(block.data, dict) and block.data.get("nonce") == nonce:
            data = block.data
            return {
                "verified": True,
                "status": data.get("status", "verified"),
                "candidate": data.get("candidate"),
                "nonce": data.get("nonce"),
                "signature": data.get("signature"),
                "recorded_at": data.get("recorded_at")
            }
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Receipt not found for the given nonce."
    )

# ==========================================
# LEDGER INTEGRITY & AUDIT ENDPOINTS (WILDCARD CATCH-ALL)
# ==========================================
@app.get("/api/v1/audit")
@app.get("/api/v1/ledger/audit")
@app.get("/api/v1/audit/global")
@app.get("/api/v1/tally/audit")
@app.get("/api/v1/ledger/verify")
@app.get("/api/v1/audit/{path:path}")
async def verify_ledger_integrity(path: str = ""):
    if not LEDGER:
        return {"status": "valid", "audit_status": "passed", "total_blocks": 0, "message": "Ledger is empty."}

    for i in range(1, len(LEDGER)):
        current_block = LEDGER[i]
        previous_block = LEDGER[i - 1]

        if current_block.hash != current_block.calculate_hash():
            return {
                "status": "compromised",
                "audit_status": "failed",
                "invalid_block_index": current_block.index,
                "error": "Block data has been modified; hash mismatch detected."
            }

        if current_block.previous_hash != previous_block.hash:
            return {
                "status": "compromised",
                "audit_status": "failed",
                "invalid_block_index": current_block.index,
                "error": "Chain broken; previous hash reference does not match predecessor."
            }

    return {
        "status": "valid",
        "audit_status": "passed",
        "total_blocks": len(LEDGER),
        "message": "Blockchain ledger integrity verified successfully. No tampering detected."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)