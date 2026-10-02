"""
FASTAPI EVOTING API - STEP 6
Production-style REST API for the Nigerian e-voting system.
Implements secure routes for voter registration, authentication, OTP, biometric
verification, ballot issuance, vote casting, verification, and tally queries.
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import sqlite3
import os
import json

from auth_module import (
    VoterRegistrationRequest,
    VoterAuthenticationRequest,
    initialize_auth_system,
)
from biometric_otp_module import BiometricOTPManager
from ballot_security import BallotSecurityManager
from voting_engine import VotingEngine

app = FastAPI(
    title="Nigeria Secure E-Voting API",
    version="1.0.0",
    description="Secure, auditable, mobile-first election platform for Nigerian voters",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core systems
engine = VotingEngine(db_path="evoting.db")
backend_auth = initialize_auth_system("evoting.db")
otp_manager = BiometricOTPManager("evoting.db")
ballot_manager = BallotSecurityManager("evoting.db")


# -----------------------------
# Pydantic Models
# -----------------------------

class RegisterVoterPayload(BaseModel):
    nin: str = Field(..., min_length=11, max_length=11)
    vin: str = Field(..., min_length=8, max_length=10)
    full_name: str = Field(..., min_length=2, max_length=150)
    phone_number: str = Field(...)
    state_code: str = Field(...)
    polling_unit_code: str = Field(...)
    email: Optional[str] = None


class AuthPayload(BaseModel):
    nin: str = Field(..., min_length=11, max_length=11)
    vin: str = Field(..., min_length=8, max_length=10)
    polling_unit_code: str = Field(...)
    state_code: str = Field(...)


class OTPRequestPayload(BaseModel):
    voter_hash: str = Field(...)
    phone_number: str = Field(...)


class VerifyOTPPayload(BaseModel):
    voter_hash: str = Field(...)
    otp_code: str = Field(..., min_length=6, max_length=6)


class CastVotePayload(BaseModel):
    voter_hash: str = Field(...)
    session_token: str = Field(...)
    election_type: str = Field(...)
    party_code: str = Field(...)
    polling_unit_code: str = Field(...)
    ballot_id: str = Field(...)


class ReceiptVerifyPayload(BaseModel):
    ballot_id: str = Field(...)
    voter_hash: str = Field(...)


# -----------------------------
# Health Check
# -----------------------------

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "Nigeria Secure E-Voting API",
        "version": "1.0.0",
    }


# -----------------------------
# Voter Registration Routes
# -----------------------------

@app.post("/api/v1/voter/register")
def register_voter(payload: RegisterVoterPayload):
    try:
        result = engine.auth_manager.register_voter(
            VoterRegistrationRequest(
                nin=payload.nin,
                vin=payload.vin,
                full_name=payload.full_name,
                phone_number=payload.phone_number,
                state_code=payload.state_code,
                polling_unit_code=payload.polling_unit_code,
                email=payload.email,
            )
        )
        return JSONResponse(status_code=200 if result.get("status") == "success" else 400, content=result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/auth/verify")
def verify_voter(payload: AuthPayload):
    valid, response = backend_auth.authenticate_voter(
        VoterAuthenticationRequest(
            nin=payload.nin,
            vin=payload.vin,
            polling_unit_code=payload.polling_unit_code,
            state_code=payload.state_code,
        )
    )

    if not valid:
        return JSONResponse(status_code=401, content=response)

    voter_hash = hashlib_sha256(payload.nin, payload.vin)
    otp_result = otp_manager.issue_otp(voter_hash, payload.phone_number if hasattr(payload, 'phone_number') else '+2347012572796')

    response["voter_hash"] = voter_hash
    response["otp"] = otp_result
    return response


@app.post("/api/v1/auth/send-otp")
def send_otp(payload: OTPRequestPayload):
    try:
        result = otp_manager.issue_otp(payload.voter_hash, payload.phone_number)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/auth/verify-otp")
def verify_otp(payload: VerifyOTPPayload):
    try:
        result = otp_manager.verify_otp(payload.voter_hash, payload.otp_code)
        return {
            "status": "success" if result.is_valid else "failed",
            "message": result.message,
            "voter_hash": result.voter_hash,
            "expires_at": result.expires_at,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# -----------------------------
# Biometric Verification Routes
# -----------------------------

@app.post("/api/v1/biometric/verify-face")
async def verify_biometric(file: UploadFile = File(...), voter_hash: str = Form(...)):
    try:
        image_bytes = await file.read()
        result = otp_manager.verify_biometric_liveness(voter_hash, image_bytes=image_bytes)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# -----------------------------
# Ballot Routes
# -----------------------------

@app.post("/api/v1/ballot/issue")
def issue_ballot(voter_hash: str, election_type: str, polling_unit_code: str, party_code: str):
    try:
        result = ballot_manager.issue_ballot(
            voter_hash=voter_hash,
            election_type=election_type,
            polling_unit_code=polling_unit_code,
            party_code=party_code,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/ballot/cast")
def cast_ballot(payload: CastVotePayload):
    try:
        result = engine.cast_vote(
            voter_hash=payload.voter_hash,
            session_token=payload.session_token,
            election_type=payload.election_type,
            party_code=payload.party_code,
            polling_unit_code=payload.polling_unit_code,
            ballot_id=payload.ballot_id,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/ballot/verify-receipt")
def verify_receipt(payload: ReceiptVerifyPayload):
    try:
        result = ballot_manager.verify_ballot_receipt(payload.ballot_id, payload.voter_hash)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# -----------------------------
# Tally and Results Routes
# -----------------------------

@app.get("/api/v1/tally/polling-unit/{polling_unit_code}/{election_type}")
def polling_unit_tally(polling_unit_code: str, election_type: str):
    return engine.get_polling_unit_tally(polling_unit_code, election_type)


@app.get("/api/v1/tally/state/{state_code}/{election_type}")
def state_tally(state_code: str, election_type: str):
    return engine.get_state_results(state_code, election_type)


@app.get("/api/v1/tally/national/{election_type}")
def national_tally(election_type: str):
    return engine.get_national_results(election_type)


# -----------------------------
# Admin and Dispute Routes
# -----------------------------

@app.post("/api/v1/admin/election/create")
def create_election(election_code: str, election_name: str, election_date: str, election_type: str):
    return engine.create_election(election_code, election_name, election_date, election_type)


@app.post("/api/v1/admin/polling-unit/register")
def register_polling_unit(
    polling_unit_code: str,
    polling_unit_name: str,
    state_code: str,
    lga_code: str,
    ward_code: str,
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
):
    return engine.register_polling_unit(
        polling_unit_code,
        polling_unit_name,
        state_code,
        lga_code,
        ward_code,
        latitude,
        longitude,
    )


@app.post("/api/v1/admin/dispute/report")
def report_dispute(polling_unit_code: str, election_type: str, reported_by: str, issue_description: str):
    return engine.report_dispute(polling_unit_code, election_type, reported_by, issue_description)


@app.get("/api/v1/admin/audit/{polling_unit_code}")
def audit_trail(polling_unit_code: str):
    return engine.get_audit_trail(polling_unit_code)


# -----------------------------
# Utility
# -----------------------------

def hashlib_sha256(nin: str, vin: str):
    import hashlib
    return hashlib.sha256(f"{nin.strip()}{vin.strip().upper()}".encode()).hexdigest()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_main:app", host="0.0.0.0", port=8000, reload=True)
