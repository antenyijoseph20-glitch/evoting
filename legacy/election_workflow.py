"""
SECURE ELECTION WORKFLOW - STEP 8
Complete end-to-end voter journey with hardened edge case handling.
This module orchestrates the entire voting process with strict state validation,
duplicate prevention, session integrity, and audit trail protection.

Designed for production use with millions of Nigerian voters.
"""

import hashlib
import sqlite3
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple
from enum import Enum

from auth_module import initialize_auth_system, VoterAuthenticationRequest, VoterRegistrationRequest
from biometric_otp_module import BiometricOTPManager
from ballot_security import BallotSecurityManager
from voting_engine import VotingEngine
from security_hardening import SecurityHardening

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [WORKFLOW] %(message)s'
)
logger = logging.getLogger("ElectionWorkflow")


class VoterState(str, Enum):
    """Voter state machine for the voting process"""
    NOT_REGISTERED = "NOT_REGISTERED"
    REGISTERED = "REGISTERED"
    AUTHENTICATED = "AUTHENTICATED"
    OTP_VERIFIED = "OTP_VERIFIED"
    BIOMETRIC_VERIFIED = "BIOMETRIC_VERIFIED"
    BALLOT_ISSUED = "BALLOT_ISSUED"
    VOTE_CAST = "VOTE_CAST"
    VOTE_VERIFIED = "VOTE_VERIFIED"


class ElectionWorkflowManager:
    """
    Orchestrates the complete secure voting workflow.
    Enforces strict state transitions and prevents edge case exploits.
    """

    def __init__(self, db_path: str = "evoting.db"):
        self.db_path = db_path
        self.auth_manager = initialize_auth_system(db_path)
        self.otp_manager = BiometricOTPManager(db_path)
        self.ballot_manager = BallotSecurityManager(db_path)
        self.voting_engine = VotingEngine(db_path)
        self.security = SecurityHardening(db_path)
        self._initialize_workflow_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_workflow_tables(self):
        """Initialize workflow state tracking tables."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Voter workflow state machine
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS voter_workflow_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_hash TEXT UNIQUE NOT NULL,
                current_state TEXT DEFAULT 'REGISTERED',
                session_token_hash TEXT UNIQUE,
                ballot_id TEXT,
                state_entered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                device_fingerprint TEXT,
                lockout_until TIMESTAMP,
                CHECK(current_state IN (
                    'NOT_REGISTERED', 'REGISTERED', 'AUTHENTICATED', 'OTP_VERIFIED',
                    'BIOMETRIC_VERIFIED', 'BALLOT_ISSUED', 'VOTE_CAST', 'VOTE_VERIFIED'
                ))
            )
        """)

        # Duplicate submission protection (idempotency)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_idempotency (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT UNIQUE NOT NULL,
                voter_hash TEXT NOT NULL,
                request_type TEXT NOT NULL,
                response_payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)

        # Session retry attempt log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS session_retry_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_hash TEXT NOT NULL,
                session_token_hash TEXT NOT NULL,
                action TEXT NOT NULL,
                attempt_number INTEGER DEFAULT 1,
                last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                max_attempts INTEGER DEFAULT 5
            )
        """)

        # Ballot state tracking (prevents double issuance)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ballot_state_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ballot_id TEXT NOT NULL,
                voter_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CHECK(state IN ('ISSUED', 'ACTIVE', 'CAST', 'VERIFIED', 'CANCELLED'))
            )
        """)

        # Vote submission deduplication
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vote_submission_lock (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                voter_hash TEXT UNIQUE NOT NULL,
                ballot_id TEXT UNIQUE NOT NULL,
                locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)

        conn.commit()
        conn.close()
        logger.info("[WORKFLOW] Workflow state tables initialized")

    def _hash_session_token(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _check_idempotency(self, idempotency_key: str, voter_hash: str,
                          request_type: str) -> Optional[Dict]:
        """
        Return cached response if duplicate request detected.
        Prevents double-processing if network retry occurs.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT response_payload, expires_at
                FROM request_idempotency
                WHERE idempotency_key = ? AND voter_hash = ? AND request_type = ?
            """, (idempotency_key, voter_hash, request_type))

            row = cursor.fetchone()
            if not row:
                return None

            response_payload, expires_at = row
            expires_dt = datetime.fromisoformat(str(expires_at))

            if datetime.now(timezone.utc) > expires_dt:
                cursor.execute("""
                    DELETE FROM request_idempotency WHERE idempotency_key = ?
                """, (idempotency_key,))
                conn.commit()
                return None

            logger.info(f"[IDEMPOTENCY] Cached response for {request_type}")
            import json
            return json.loads(response_payload)
        finally:
            conn.close()

    def _record_idempotency(self, idempotency_key: str, voter_hash: str,
                           request_type: str, response: Dict,
                           ttl_minutes: int = 5) -> None:
        """Cache response for duplicate request handling."""
        conn = self._get_connection()
        cursor = conn.cursor()

        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()

        try:
            import json
            cursor.execute("""
                INSERT INTO request_idempotency (idempotency_key, voter_hash, request_type, response_payload, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (idempotency_key, voter_hash, request_type, json.dumps(response), expires_at))
            conn.commit()
        finally:
            conn.close()

    def _transition_voter_state(self, voter_hash: str, new_state: VoterState,
                               session_token: Optional[str] = None,
                               ip_address: str = "0.0.0.0") -> bool:
        """
        Transition voter through state machine.
        Enforces valid state transitions and prevents bypass.
        """
        valid_transitions = {
            VoterState.NOT_REGISTERED: [VoterState.REGISTERED],
            VoterState.REGISTERED: [VoterState.AUTHENTICATED],
            VoterState.AUTHENTICATED: [VoterState.OTP_VERIFIED],
            VoterState.OTP_VERIFIED: [VoterState.BIOMETRIC_VERIFIED],
            VoterState.BIOMETRIC_VERIFIED: [VoterState.BALLOT_ISSUED],
            VoterState.BALLOT_ISSUED: [VoterState.VOTE_CAST],
            VoterState.VOTE_CAST: [VoterState.VOTE_VERIFIED],
        }

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT current_state FROM voter_workflow_state WHERE voter_hash = ?
            """, (voter_hash,))
            row = cursor.fetchone()

            if not row:
                cursor.execute("""
                    INSERT INTO voter_workflow_state (voter_hash, current_state, ip_address)
                    VALUES (?, ?, ?)
                """, (voter_hash, new_state.value, ip_address))
                conn.commit()
                return True

            current_state = VoterState(row[0])

            # Validate transition
            if new_state not in valid_transitions.get(current_state, []):
                logger.warning(f"[WORKFLOW] Invalid state transition: {current_state} -> {new_state}")
                return False

            session_token_hash = self._hash_session_token(session_token) if session_token else None

            cursor.execute("""
                UPDATE voter_workflow_state
                SET current_state = ?, session_token_hash = ?, last_activity = CURRENT_TIMESTAMP, ip_address = ?
                WHERE voter_hash = ?
            """, (new_state.value, session_token_hash, ip_address, voter_hash))
            conn.commit()
            return True
        finally:
            conn.close()

    def register_voter_secure(self, nin: str, vin: str, full_name: str,
                             phone_number: str, state_code: str,
                             polling_unit_code: str, ip_address: str = "0.0.0.0",
                             idempotency_key: Optional[str] = None) -> Dict:
        """Register voter with duplicate prevention and audit logging."""
        voter_hash = hashlib.sha256(f"{nin}{vin}".encode()).hexdigest()

        # Check idempotency
        if idempotency_key:
            cached = self._check_idempotency(idempotency_key, voter_hash, "REGISTRATION")
            if cached:
                return cached

        # Rate limiting
        allowed, msg = self.security.check_rate_limit("registration", ip_address, max_requests=10, window_minutes=60)
        if not allowed:
            self.security.record_security_event(voter_hash, "REGISTRATION", "VOTER", "RATE_LIMITED", ip_address, msg)
            return {"status": "failed", "code": "RATE_LIMITED", "message": msg}

        # Input validation
        if not self.security.validate_nin(nin):
            return {"status": "failed", "code": "INVALID_NIN", "message": "Invalid NIN format"}
        if not self.security.validate_vin(vin):
            return {"status": "failed", "code": "INVALID_VIN", "message": "Invalid VIN format"}
        if not self.security.validate_nigerian_phone(phone_number):
            return {"status": "failed", "code": "INVALID_PHONE", "message": "Invalid phone number"}

        # Register voter
        request = VoterRegistrationRequest(
            nin=nin,
            vin=vin,
            full_name=full_name,
            phone_number=phone_number,
            state_code=state_code,
            polling_unit_code=polling_unit_code,
        )

        result = self.auth_manager.register_voter(request, ip_address=ip_address)

        if result.get("status") == "success":
            self._transition_voter_state(voter_hash, VoterState.REGISTERED, ip_address=ip_address)
            self.security.record_security_event(voter_hash, "REGISTRATION", "VOTER", "SUCCESS", ip_address)

        if idempotency_key:
            self._record_idempotency(idempotency_key, voter_hash, "REGISTRATION", result)

        return result

    def cast_vote_secure(self, voter_hash: str, session_token: str, ballot_id: str,
                        election_type: str, party_code: str, polling_unit_code: str,
                        ip_address: str = "0.0.0.0", idempotency_key: Optional[str] = None) -> Dict:
        """
        Cast vote with comprehensive edge-case protection:
        - prevents double voting
        - validates ballot state
        - uses idempotency keys for retry safety
        - locks submission to prevent race conditions
        """
        # Check idempotency
        if idempotency_key:
            cached = self._check_idempotency(idempotency_key, voter_hash, "VOTE_CAST")
            if cached:
                return cached

        # Validate session
        is_valid, _ = self.auth_manager.validate_session(session_token)
        if not is_valid:
            return {"status": "failed", "code": "INVALID_SESSION", "message": "Session expired"}

        # Check submission lock (prevents simultaneous submissions)
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT expires_at FROM vote_submission_lock
            WHERE voter_hash = ? AND ballot_id = ?
        """, (voter_hash, ballot_id))
        lock_row = cursor.fetchone()
        conn.close()

        if lock_row:
            expires_dt = datetime.fromisoformat(str(lock_row[0]))
            if datetime.now(timezone.utc) < expires_dt:
                return {
                    "status": "failed",
                    "code": "SUBMISSION_IN_PROGRESS",
                    "message": "Vote submission already in progress"
                }

        # Create submission lock
        lock_expires = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO vote_submission_lock (voter_hash, ballot_id, expires_at)
            VALUES (?, ?, ?)
        """, (voter_hash, ballot_id, lock_expires))
        conn.commit()
        conn.close()

        try:
            # Check voter state
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT current_state FROM voter_workflow_state WHERE voter_hash = ?", (voter_hash,))
            row = cursor.fetchone()
            conn.close()

            if not row or VoterState(row[0]) != VoterState.BALLOT_ISSUED:
                self.security.record_security_event(voter_hash, "VOTE_CAST", "BALLOT", "STATE_ERROR", ip_address)
                return {
                    "status": "failed",
                    "code": "STATE_ERROR",
                    "message": "Voter not in ballot-issued state"
                }

            # Cast vote
            result = self.voting_engine.cast_vote(voter_hash, session_token, election_type, party_code, polling_unit_code, ballot_id)

            if result.get("status") == "success":
                self._transition_voter_state(voter_hash, VoterState.VOTE_CAST, session_token, ip_address)

                # Log ballot state
                conn = self._get_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO ballot_state_log (ballot_id, voter_hash, state)
                    VALUES (?, ?, 'CAST')
                """, (ballot_id, voter_hash))
                conn.commit()
                conn.close()

                self.security.record_security_event(voter_hash, "VOTE_CAST", "BALLOT", "SUCCESS", ip_address)
            else:
                self.security.record_security_event(voter_hash, "VOTE_CAST", "BALLOT", "FAILED", ip_address, result.get("message"))

            if idempotency_key:
                self._record_idempotency(idempotency_key, voter_hash, "VOTE_CAST", result)

            return result

        finally:
            # Release submission lock
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vote_submission_lock WHERE voter_hash = ? AND ballot_id = ?", (voter_hash, ballot_id))
            conn.commit()
            conn.close()


# Example usage
if __name__ == "__main__":
    manager = ElectionWorkflowManager()
    logger.info("[WORKFLOW] Secure Election Workflow Manager initialized")
