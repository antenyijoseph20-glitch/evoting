"""
SECURITY FLOW INTEGRATION - STEP 3
This module connects the voter identity layer, biometric verification, and OTP
into a single secure accreditation flow for the e-voting app.

It is designed to be imported into the main FastAPI app and used by the
frontend/backend routes without rewriting the entire application.
"""

import hashlib
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from auth_module import (
    VoterAuthenticationRequest,
    VoterRegistrationRequest,
    initialize_auth_system,
)
from biometric_otp_module import BiometricOTPManager


class SecureElectionFlow:
    """
    Encapsulates the voting security pipeline:
    1. Register voter
    2. Authenticate NIN/VIN
    3. Issue OTP
    4. Verify OTP
    5. Liveness/biometric validation
    6. Grant secure voting session
    """

    def __init__(self, db_path: str = "evoting.db"):
        self.db_path = db_path
        self.auth_manager = initialize_auth_system(db_path)
        self.otp_manager = BiometricOTPManager(db_path)

    def _hash_voter(self, nin: str, vin: str) -> str:
        return hashlib.sha256(f"{nin.strip()}{vin.strip().upper()}".encode()).hexdigest()

    def register_voter(self, nin: str, vin: str, full_name: str,
                      phone_number: str, state_code: str,
                      polling_unit_code: str, email: Optional[str] = None) -> Dict:
        """Register a voter using the secure auth module."""
        request = VoterRegistrationRequest(
            nin=nin,
            vin=vin,
            full_name=full_name,
            phone_number=phone_number,
            state_code=state_code,
            polling_unit_code=polling_unit_code,
            email=email,
        )
        return self.auth_manager.register_voter(request)

    def authenticate_voter(self, nin: str, vin: str,
                           state_code: str, polling_unit_code: str,
                           ip_address: str = "0.0.0.0") -> Dict:
        """Authenticate the voter and issue an accreditation session."""
        request = VoterAuthenticationRequest(
            nin=nin,
            vin=vin,
            polling_unit_code=polling_unit_code,
            state_code=state_code,
        )
        is_valid, response = self.auth_manager.authenticate_voter(request, ip_address=ip_address)

        if not is_valid:
            return {
                "status": "failed",
                "message": response.get("message", "Authentication failed"),
                "session_token": None,
                "voter_hash": None,
            }

        voter_hash = self._hash_voter(nin, vin)
        otp_payload = self.otp_manager.issue_otp(voter_hash, phone_number="+2347012572796")

        return {
            "status": "success",
            "message": "Voter authenticated and OTP issued for secure verification.",
            "session_token": response.get("session_token"),
            "voter_hash": voter_hash,
            "expires_at": response.get("expires_at"),
            "otp": otp_payload,
        }

    def verify_otp_for_voter(self, voter_hash: str, otp_code: str) -> Dict:
        """Verify the voter OTP before biometric approval."""
        result = self.otp_manager.verify_otp(voter_hash, otp_code)
        if not result.is_valid:
            return {
                "status": "failed",
                "message": result.message,
            }
        return {
            "status": "success",
            "message": result.message,
            "voter_hash": voter_hash,
            "expires_at": result.expires_at,
        }

    def verify_biometric(self, voter_hash: str, image_bytes: Optional[bytes] = None) -> Dict:
        """Secure biometric verification (OpenCV or simulated secure fallback)."""
        return self.otp_manager.verify_biometric_liveness(voter_hash, image_bytes=image_bytes)

    def full_secure_voter_flow(self, nin: str, vin: str,
                              full_name: str, phone_number: str,
                              state_code: str, polling_unit_code: str,
                              otp_code: str, image_bytes: Optional[bytes] = None,
                              ip_address: str = "0.0.0.0") -> Dict:
        """
        End-to-end secure accreditation flow.
        This is the exact sequence a Nigerian election-grade system should follow.
        """
        register_result = self.register_voter(
            nin=nin,
            vin=vin,
            full_name=full_name,
            phone_number=phone_number,
            state_code=state_code,
            polling_unit_code=polling_unit_code,
        )

        if register_result.get("status") == "failed":
            return {
                "status": "failed",
                "message": register_result.get("message", "Voter registration failed"),
            }

        auth_result = self.authenticate_voter(
            nin=nin,
            vin=vin,
            state_code=state_code,
            polling_unit_code=polling_unit_code,
            ip_address=ip_address,
        )

        if auth_result.get("status") != "success":
            return auth_result

        voter_hash = auth_result.get("voter_hash")
        otp_result = self.verify_otp_for_voter(voter_hash, otp_code)
        if otp_result.get("status") != "success":
            return otp_result

        biometric_result = self.verify_biometric(voter_hash, image_bytes=image_bytes)
        if biometric_result.get("status") != "success":
            return biometric_result

        return {
            "status": "success",
            "message": "Voter fully accredited for ballot casting.",
            "voter_hash": voter_hash,
            "session_token": auth_result.get("session_token"),
            "otp_status": otp_result,
            "biometric_status": biometric_result,
            "expires_at": auth_result.get("expires_at"),
        }


# Example usage for manual testing
if __name__ == "__main__":
    flow = SecureElectionFlow()
    result = flow.full_secure_voter_flow(
        nin="12345678901",
        vin="LG12345678",
        full_name="Antenyi Joseph Ochohepo",
        phone_number="+2347012572796",
        state_code="BENUE",
        polling_unit_code="PU-004",
        otp_code="123456",
        image_bytes=b"demo-image-bytes",
    )
    print(result)
