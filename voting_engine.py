"""
NIGERIAN E-VOTING ENGINE - STEP 5
Complete voting system integration with admin dashboard and real-time tally.
Designed for millions of Nigerian voters using basic mobile phones.

This module brings together:
- voter registration and authentication
- OTP and biometric verification
- secure ballot issuance and recording
- real-time results aggregation
- audit trail and dispute resolution
- admin oversight and election management
"""

import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum

from auth_module import initialize_auth_system
from biometric_otp_module import BiometricOTPManager
from ballot_security import BallotSecurityManager


class ElectionStatus(str, Enum):
    """Election lifecycle status"""
    SETUP = "SETUP"
    ACCREDITATION = "ACCREDITATION"
    VOTING = "VOTING"
    CLOSED = "CLOSED"
    COUNTING = "COUNTING"
    RESULTS_PUBLISHED = "RESULTS_PUBLISHED"


class PollingUnitStatus(str, Enum):
    """Individual polling unit status"""
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    SUSPENDED = "SUSPENDED"


class VotingEngine:
    """
    Complete voting system engine.
    Orchestrates voter journey from registration through vote casting and tally.
    Designed for Nigerian voters using mobile phones.
    """

    def __init__(self, db_path: str = "evoting.db"):
        self.db_path = db_path
        self.auth_manager = initialize_auth_system(db_path)
        self.otp_manager = BiometricOTPManager(db_path)
        self.ballot_manager = BallotSecurityManager(db_path)
        self._initialize_voting_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_voting_tables(self):
        """Initialize core voting and election management tables."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Election master table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS elections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                election_code TEXT UNIQUE NOT NULL,
                election_name TEXT NOT NULL,
                election_date TEXT NOT NULL,
                election_type TEXT NOT NULL,
                status TEXT DEFAULT 'SETUP',
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CHECK(status IN ('SETUP', 'ACCREDITATION', 'VOTING', 'CLOSED', 'COUNTING', 'RESULTS_PUBLISHED'))
            )
        """)

        # Polling unit configuration
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS polling_units (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                polling_unit_code TEXT UNIQUE NOT NULL,
                polling_unit_name TEXT NOT NULL,
                state_code TEXT NOT NULL,
                lga_code TEXT NOT NULL,
                ward_code TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                status TEXT DEFAULT 'OPEN',
                accredited_count INTEGER DEFAULT 0,
                voted_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CHECK(status IN ('OPEN', 'CLOSED', 'SUSPENDED'))
            )
        """)

        # Real-time vote tally table (aggregated by polling unit)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS polling_unit_tally (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                polling_unit_code TEXT NOT NULL,
                election_type TEXT NOT NULL,
                party_code TEXT NOT NULL,
                vote_count INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(polling_unit_code, election_type, party_code),
                FOREIGN KEY(polling_unit_code) REFERENCES polling_units(polling_unit_code)
            )
        """)

        # State-level aggregation for rapid result computation
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS state_tally (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                state_code TEXT NOT NULL,
                election_type TEXT NOT NULL,
                party_code TEXT NOT NULL,
                vote_count INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(state_code, election_type, party_code)
            )
        """)

        # National results (final aggregation)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS national_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                election_type TEXT NOT NULL,  -- was UNIQUE, which allowed only ONE party per election
                party_code TEXT NOT NULL,
                total_votes INTEGER DEFAULT 0,
                percentage REAL DEFAULT 0.0,
                published_at TIMESTAMP,
                UNIQUE(election_type, party_code)
            )
        """)

        # Dispute/audit flag system
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS election_disputes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                polling_unit_code TEXT NOT NULL,
                election_type TEXT NOT NULL,
                reported_by TEXT NOT NULL,
                issue_description TEXT NOT NULL,
                status TEXT DEFAULT 'OPEN',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                resolution_notes TEXT,
                FOREIGN KEY(polling_unit_code) REFERENCES polling_units(polling_unit_code)
            )
        """)

        # Admin audit log for oversight
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_polling_unit ON polling_units(polling_unit_code)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tally_pu ON polling_unit_tally(polling_unit_code)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tally_state ON state_tally(state_code)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dispute_pu ON election_disputes(polling_unit_code)")

        conn.commit()
        conn.close()

    def create_election(self, election_code: str, election_name: str,
                       election_date: str, election_type: str) -> Dict:
        """
        Create a new election (INEC admin function).
        Example: INEC creates 2027 Presidential Election
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO elections (election_code, election_name, election_date, election_type, status)
                VALUES (?, ?, ?, ?, ?)
            """, (election_code, election_name, election_date, election_type, "SETUP"))
            conn.commit()

            return {
                "status": "success",
                "message": f"Election {election_name} created successfully.",
                "election_code": election_code,
            }
        except sqlite3.IntegrityError:
            return {
                "status": "failed",
                "message": "Election with this code already exists.",
            }
        finally:
            conn.close()

    def register_polling_unit(self, polling_unit_code: str, polling_unit_name: str,
                             state_code: str, lga_code: str, ward_code: str,
                             latitude: Optional[float] = None,
                             longitude: Optional[float] = None) -> Dict:
        """Register a polling unit (INEC setup phase)."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO polling_units (
                    polling_unit_code, polling_unit_name, state_code, lga_code, ward_code,
                    latitude, longitude, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN')
            """, (polling_unit_code, polling_unit_name, state_code, lga_code, ward_code, latitude, longitude))
            conn.commit()

            return {
                "status": "success",
                "message": f"Polling unit {polling_unit_code} registered.",
                "polling_unit_code": polling_unit_code,
            }
        except sqlite3.IntegrityError:
            return {"status": "failed", "message": "Polling unit already registered."}
        finally:
            conn.close()

    def cast_vote(self, voter_hash: str, session_token: str, election_type: str,
                 party_code: str, polling_unit_code: str, ballot_id: str) -> Dict:
        """
        Main voting function - called when voter submits their ballot.
        Security checks are enforced here.
        """
        # Validate session is still active
        is_valid, _ = self.auth_manager.validate_session(session_token)
        if not is_valid:
            return {
                "status": "failed",
                "code": "INVALID_SESSION",
                "message": "Voting session expired or invalid. Please re-authenticate.",
            }

        # Record vote in secure ballot ledger
        ballot_result = self.ballot_manager.cast_ballot(
            ballot_id=ballot_id,
            voter_hash=voter_hash,
            election_type=election_type,
            party_code=party_code,
            polling_unit_code=polling_unit_code,
        )

        if ballot_result.get("status") != "success":
            return ballot_result

        # Update tally in real-time
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Increment polling unit tally
            cursor.execute("""
                INSERT INTO polling_unit_tally (polling_unit_code, election_type, party_code, vote_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(polling_unit_code, election_type, party_code)
                DO UPDATE SET vote_count = vote_count + 1, last_updated = CURRENT_TIMESTAMP
            """, (polling_unit_code, election_type, party_code))

            # Increment state tally
            cursor.execute("""
                SELECT state_code FROM polling_units WHERE polling_unit_code = ?
            """, (polling_unit_code,))
            state_row = cursor.fetchone()
            if state_row:
                state_code = state_row[0]
                cursor.execute("""
                    INSERT INTO state_tally (state_code, election_type, party_code, vote_count)
                    VALUES (?, ?, ?, 1)
                    ON CONFLICT(state_code, election_type, party_code)
                    DO UPDATE SET vote_count = vote_count + 1, last_updated = CURRENT_TIMESTAMP
                """, (state_code, election_type, party_code))

            # Mark voter as voted
            cursor.execute("""
                UPDATE inec_voters SET has_voted = 1 WHERE voter_hash = ?
            """, (voter_hash,))

            # Update polling unit voted count
            cursor.execute("""
                UPDATE polling_units SET voted_count = voted_count + 1 WHERE polling_unit_code = ?
            """, (polling_unit_code,))

            conn.commit()

            return {
                "status": "success",
                "message": "Vote successfully cast and recorded.",
                "receipt": {
                    "ballot_id": ballot_id,
                    "receipt_hash": ballot_result.get("receipt_hash"),
                    "current_hash": ballot_result.get("current_hash"),
                    "timestamp": ballot_result.get("timestamp"),
                    "signature": ballot_result.get("signature"),
                },
                "can_verify_at": "/api/v1/verify-receipt",
            }
        finally:
            conn.close()

    def get_polling_unit_tally(self, polling_unit_code: str, election_type: str) -> Dict:
        """Get real-time vote tally for a polling unit (for election observers)."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT party_code, vote_count
                FROM polling_unit_tally
                WHERE polling_unit_code = ? AND election_type = ?
                ORDER BY vote_count DESC
            """, (polling_unit_code, election_type))

            rows = cursor.fetchall()
            tally = {row[0]: row[1] for row in rows}

            return {
                "status": "success",
                "polling_unit_code": polling_unit_code,
                "election_type": election_type,
                "tally": tally,
                "total_votes": sum(tally.values()),
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
        finally:
            conn.close()

    def get_state_results(self, state_code: str, election_type: str) -> Dict:
        """Get aggregated state results (for INEC dashboard)."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT party_code, vote_count
                FROM state_tally
                WHERE state_code = ? AND election_type = ?
                ORDER BY vote_count DESC
            """, (state_code, election_type))

            rows = cursor.fetchall()
            results = {row[0]: row[1] for row in rows}
            total = sum(results.values())

            return {
                "status": "success",
                "state_code": state_code,
                "election_type": election_type,
                "results": results,
                "total_votes": total,
            }
        finally:
            conn.close()

    def get_national_results(self, election_type: str) -> Dict:
        """Get final national results (published after counting closes)."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT party_code, total_votes, percentage
                FROM national_results
                WHERE election_type = ?
                ORDER BY total_votes DESC
            """, (election_type,))

            rows = cursor.fetchall()
            results = [
                {"party": row[0], "votes": row[1], "percentage": row[2]}
                for row in rows
            ]

            return {
                "status": "success",
                "election_type": election_type,
                "results": results,
            }
        finally:
            conn.close()

    def report_dispute(self, polling_unit_code: str, election_type: str,
                      observer_id: str, issue_description: str) -> Dict:
        """
        Report an election dispute or irregularity (for election observers/INEC).
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO election_disputes (
                    polling_unit_code, election_type, reported_by, issue_description, status
                ) VALUES (?, ?, ?, ?, 'OPEN')
            """, (polling_unit_code, election_type, observer_id, issue_description))
            conn.commit()

            return {
                "status": "success",
                "message": "Dispute reported successfully. INEC will review.",
                "dispute_id": cursor.lastrowid,
            }
        finally:
            conn.close()

    def get_audit_trail(self, polling_unit_code: str) -> Dict:
        """
        Export complete audit trail for a polling unit (for dispute resolution/verification).
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT ballot_id, voter_hash, election_type, party_code, 
                       receipt_hash, created_at
                FROM ballot_ledger
                WHERE polling_unit_code = ?
                ORDER BY created_at ASC
            """, (polling_unit_code,))

            rows = cursor.fetchall()
            audit_trail = [
                {
                    "ballot_id": row[0],
                    "voter_hash": row[1][:16] + "...",  # Anonymize voter hash
                    "election_type": row[2],
                    "party_code": row[3],
                    "receipt_hash": row[4][:16] + "...",
                    "timestamp": row[5],
                }
                for row in rows
            ]

            return {
                "status": "success",
                "polling_unit_code": polling_unit_code,
                "total_votes": len(audit_trail),
                "audit_trail": audit_trail,
            }
        finally:
            conn.close()

    def close_polling_unit(self, polling_unit_code: str) -> Dict:
        """Close a polling unit at end of voting day."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE polling_units
                SET status = 'CLOSED'
                WHERE polling_unit_code = ?
            """, (polling_unit_code,))
            conn.commit()

            return {
                "status": "success",
                "message": f"Polling unit {polling_unit_code} closed.",
            }
        finally:
            conn.close()


# Example usage
if __name__ == "__main__":
    engine = VotingEngine()

    # INEC setup
    engine.create_election("PRES-2027", "2027 Presidential Election", "2027-02-25", "PRESIDENTIAL")
    engine.register_polling_unit("PU-004", "Otukpo Ward 1", "BENUE", "OTUKPO", "OTK-001")

    # Voter casting vote
    vote_result = engine.cast_vote(
        voter_hash="demo_voter_hash_123",
        session_token="demo_session_token",
        election_type="PRESIDENTIAL",
        party_code="APC",
        polling_unit_code="PU-004",
        ballot_id="ballot-uuid-123",
    )
    print("Vote Result:", vote_result)

    # Get tally
    tally = engine.get_polling_unit_tally("PU-004", "PRESIDENTIAL")
    print("Tally:", tally)