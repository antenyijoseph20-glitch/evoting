from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import os
import hashlib
import uuid
import time
import json

# Mount static files (ensure you have a folder named 'static' containing css/js files)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>Frontend index.html not found in static/ folder.</h3>"
app = FastAPI(title="Nigeria E2E-V Secure Voting System")
# Simulated in-memory ledger storage (replace with your actual database or blockchain manager instance)
blockchain_ledger = {
    "system": "Nigeria E2E-V Secure Voting System",
    "total_blocks": 0,
    "ledger_integrity_status": "VERIFIED_APPEND_ONLY",
    "blocks": []
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup: Initialize Genesis Block if ledger is empty ---
    if len(blockchain_ledger["blocks"]) == 0:
        import hashlib
        from datetime import datetime

        genesis_data = "GENESIS_BLOCK_NIGERIA_E2EV_VOTING_SYSTEM"
        genesis_hash = hashlib.sha256(genesis_data.encode()).hexdigest()

        genesis_block = {
            "block_id": 0,
            "receipt_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "block_hash": genesis_hash,
            "previous_hash": "0",
            "synced_at_timestamp": datetime.utcnow().isoformat() + "Z"
        }

        blockchain_ledger["blocks"].append(genesis_block)
        blockchain_ledger["total_blocks"] = 1
        print("🚀 [Startup] Genesis block initialized successfully.")

    yield
    
    # --- Shutdown (Optional cleanup) ---
    print("🛑 [Shutdown] E2E-V Voting server shutting down safely.")

# Pass the lifespan handler to your FastAPI app instance
app = FastAPI(title="Nigeria E2E-V Secure Voting System", lifespan=lifespan)

# Example endpoint matching your export route
@app.get("/api/v1/bulletin-board/export")
async def export_bulletin_board():
    return blockchain_ledger

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the static directory so FastAPI serves static/js/app.js properly
app.mount("/static", StaticFiles(directory="static"), name="static")

# Mock ledger data for testing
LEDGER = [
    {
        "block_id": 1,
        "previous_hash": "GENESIS",
        "block_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "receipt_hash": "rcpt_001_alpha",
        "synced_at_timestamp": "2026-09-02T21:00:00Z"
    },
    {
        "block_id": 2,
        "previous_hash": "a1b2c3d4e5f67890123456789abcdef0",
        "block_hash": "f6e5d4c3b2a109876543210fedcba9876543210fedcba9876543210fedcba987",
        "receipt_hash": "rcpt_002_beta",
        "synced_at_timestamp": "2026-09-02T21:30:00Z"
    }
]

@app.get("/api/v1/admin/health")
async def admin_health():
    return {"status": "healthy", "system": "operational"}

@app.get("/api/v1/tally/results")
async def get_tally_results():
    tallies = {}
    total_votes_cast = 0

    # Iterate through the ledger blocks
    for block in LEDGER:
        # Check if block data is a dictionary and represents a cast ballot (contains candidate_id)
        if isinstance(block.data, dict) and "candidate_id" in block.data:
            candidate = block.data["candidate_id"]
            tallies[candidate] = tallies.get(candidate, 0) + 1
            total_votes_cast += 1

    # Format the aggregated results for frontend presentation or public auditing
    results_list = [
        {"candidate_id": candidate, "vote_count": count}
        for candidate, count in tallies.items()
    ]

    return {
        "status": "success",
        "total_votes_cast": total_votes_cast,
        "tallies": results_list,
        "ledger_blocks_scanned": len(LEDGER)
    }
@app.get("/api/v1/bulletin-board/export")
async def export_bulletin_board_ledger():
    # Returning a standard dictionary prevents all h11 Content-Length protocol errors
    return {
        "system": "Nigeria E2E-V Secure Voting System",
        "total_blocks": len(LEDGER),
        "ledger_integrity_status": "VERIFIED_APPEND_ONLY",
        "blocks": LEDGER
    }

# Request model for voter authentication
class VoterAuthRequest(BaseModel):
    nin: str = Field(..., min_length=11, max_length=11, description="11-digit National Identification Number")
    vin: str = Field(..., min_length=10, max_length=20, description="Voter Identification Number")
    polling_unit_code: str = Field(..., description="INEC assigned polling unit code")

# In-memory mock registry of already voted hashes to prevent double voting
VOTED_REGISTRY = set()

@app.post("/api/v1/auth/verify-voter")
async def verify_voter_credentials(payload: VoterAuthRequest):
    # 1. Basic format validation (NIN must be strictly numeric digits)
    if not payload.nin.isdigit():
        return {
            "status": "error",
            "error_code": "INVALID_NIN_FORMAT",
            "message": "NIN must consist of exactly 11 numeric digits."
        }

    # 2. Generate a secure cryptographic blind hash of the NIN/VIN pair for anonymity
    credential_signature = f"{payload.nin}:{payload.vin}"
    voter_hash = hashlib.sha256(credential_signature.encode()).hexdigest()

    # 3. Check for double voting / prior accreditation
    if voter_hash in VOTED_REGISTRY:
        return {
            "status": "rejected",
            "error_code": "ALREADY_VOTED",
            "message": "Credentials have already been utilized for ballot issuance."
        }

    # 4. Successful accreditation response (issues temporary secure ballot token)
    session_token = str(uuid.uuid4())
    
    return {
        "status": "success",
        "accreditation": "verified",
        "voter_blind_hash": voter_hash[:16] + "...", # Masked for privacy
        "polling_unit": payload.polling_unit_code,
        "session_token": session_token,
        "message": "Voter successfully accredited. Proceed to tiered balloting."
    }
ACTIVE_SESSIONS = {} 
LEDGER = []

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

def get_latest_block():
    if not LEDGER:
        # Initialize Genesis Block if ledger is empty
        genesis = Block(0, time.time(), {"message": "Genesis Block - E-Voting Ledger Initialized"}, "0")
        LEDGER.append(genesis)
    return LEDGER[-1]

# Request model for casting a ballot
class BallotSubmission(BaseModel):
    session_token: str
    candidate_id: str
    polling_unit_code: str

@app.post("/api/v1/ballot/submit")
async def submit_ballot(payload: BallotSubmission):
    # 1. Verify session token exists and is valid
    if payload.session_token not in ACTIVE_SESSIONS:
        return {
            "status": "error",
            "error_code": "INVALID_OR_EXPIRED_SESSION",
            "message": "Session token is invalid, expired, or has already been used."
        }
    
    # Retrieve and immediately consume/pop the token to prevent replay attacks
    voter_hash = ACTIVE_SESSIONS.pop(payload.session_token)

    # 2. Mark voter hash in the global registry to block double voting
    VOTED_REGISTRY.add(voter_hash)

    # 3. Construct ballot data (stripped of any direct PII, tracked via blind hash)
    vote_data = {
        "candidate_id": payload.candidate_id,
        "polling_unit_code": payload.polling_unit_code,
        "voter_blind_hash_prefix": voter_hash[:12]
    }

    # 4. Append new block to the immutable ledger
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
@app.get("/api/v1/ledger/verify")
async def verify_ledger_integrity():
    if not LEDGER:
        return {"status": "valid", "total_blocks": 0, "message": "Ledger is empty."}

    # Iterate through the chain starting from block 1 (skipping genesis)
    for i in range(1, len(LEDGER)):
        current_block = LEDGER[i]
        previous_block = LEDGER[i - 1]

        # 1. Check if the stored hash matches the recomputed hash
        if current_block.hash != current_block.calculate_hash():
            return {
                "status": "compromised",
                "invalid_block_index": current_block.index,
                "error": "Block data has been modified; hash mismatch detected."
            }

        # 2. Check if the previous_hash link is valid
        if current_block.previous_hash != previous_block.hash:
            return {
                "status": "compromised",
                "invalid_block_index": current_block.index,
                "error": "Chain broken; previous hash reference does not match predecessor."
            }

    return {
        "status": "valid",
        "total_blocks": len(LEDGER),
        "message": "Blockchain ledger integrity verified successfully. No tampering detected."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)