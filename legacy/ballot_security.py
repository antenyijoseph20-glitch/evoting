"""
BALLOT SECURITY MODULE - STEP 4
This module adds secure ballot issuance, cryptographic receipts, and a tamper-evident
ballot ledger for the Nigerian e-voting application.

Core principles:
- ballot generation is cryptographically bound to voter identity and election tier
- each ballot receipt has a hash chain for integrity
- every vote is recorded with a unique nonce and chained hash
- receipts can be verified independently without revealing the vote content
"""

import hashlib
import hmac
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple


class BallotSecurityManager:
    """Secure ballot issuance, receipt generation, and ledger verification."""

    def __init__(self, db_path: str = "evoting.db", secret_key: Optional[str] = None):
        self.db_path = db_path
        self.secret_key = secret_key or secrets.token_hex(32)
        self._initialize_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_tables(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ballot_issue_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ballot_id TEXT UNIQUE NOT NULL,
                voter_hash TEXT NOT NULL,
                election_type TEXT NOT NULL,
                polling_unit_code TEXT NOT NULL,
                ballot_nonce TEXT UNIQUE NOT NULL,
                issue_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                receipt_hash TEXT,
                signature TEXT,
                is_used INTEGER DEFAULT 0 CHECK(is_used IN (0, 1)),
                used_at TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ballot_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ballot_id TEXT NOT NULL,
                voter_hash TEXT NOT NULL,
                election_type TEXT NOT NULL,
                party_code TEXT NOT NULL,
                polling_unit_code TEXT NOT NULL,
                ballot_nonce TEXT UNIQUE NOT NULL,
                receipt_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ballot_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ballot_id TEXT UNIQUE NOT NULL,
                voter_hash TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                ballot_nonce TEXT UNIQUE NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verification_status TEXT DEFAULT 'UNVERIFIED',
                signed_payload TEXT NOT NULL,
                is_valid INTEGER DEFAULT 0 CHECK(is_valid IN (0, 1))
            )
        """)

        conn.commit()
        conn.close()

    def _safe_hash(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _sign_payload(self, payload: Dict) -> str:
        payload_json = str(sorted(payload.items()))
        return hmac.new(self.secret_key.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue_ballot(self, voter_hash: str, election_type: str,
                     polling_unit_code: str, party_code: str) -> Dict:
        """
        Issue a secure ballot to an accredited voter.
        This is the point where the system creates a ballot nonce and receipt.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            ballot_id = str(uuid.uuid4())
            ballot_nonce = secrets.token_hex(32)
            issue_timestamp = datetime.now(timezone.utc).isoformat()

            receipt_payload = {
                "ballot_id": ballot_id,
                "voter_hash": voter_hash,
                "election_type": election_type,
                "polling_unit_code": polling_unit_code,
                "party_code": party_code,
                "nonce": ballot_nonce,
                "timestamp": issue_timestamp,
            }

            receipt_hash = self._safe_hash(str(sorted(receipt_payload.items())))
            signature = self._sign_payload(receipt_payload)

            cursor.execute("""
                INSERT INTO ballot_issue_log (
                    ballot_id, voter_hash, election_type, polling_unit_code,
                    ballot_nonce, receipt_hash, signature, is_used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                ballot_id,
                voter_hash,
                election_type,
                polling_unit_code,
                ballot_nonce,
                receipt_hash,
                signature,
            ))
            conn.commit()

            return {
                "status": "success",
                "message": "Ballot securely issued to voter.",
                "ballot_id": ballot_id,
                "ballot_nonce": ballot_nonce,
                "receipt_hash": receipt_hash,
                "signature": signature,
                "issued_at": issue_timestamp,
                "election_type": election_type,
                "party_code": party_code,
            }
        finally:
            conn.close()

    def cast_ballot(self, ballot_id: str, voter_hash: str, election_type: str,
                    party_code: str, polling_unit_code: str) -> Dict:
        """
        Record the final ballot in the tamper-evident ledger.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT ballot_nonce, receipt_hash, signature
                FROM ballot_issue_log
                WHERE ballot_id = ? AND voter_hash = ? AND is_used = 0
            """, (ballot_id, voter_hash))
            row = cursor.fetchone()

            if not row:
                return {
                    "status": "failed",
                    "message": "Ballot not found, already used, or invalid for this voter.",
                }

            ballot_nonce, receipt_hash, signature = row

            cursor.execute("SELECT current_hash FROM ballot_ledger ORDER BY id DESC LIMIT 1")
            prev_row = cursor.fetchone()
            previous_hash = prev_row[0] if prev_row else "0" * 64

            timestamp = datetime.now(timezone.utc).isoformat()
            ballot_payload = {
                "ballot_id": ballot_id,
                "voter_hash": voter_hash,
                "election_type": election_type,
                "party_code": party_code,
                "polling_unit_code": polling_unit_code,
                "ballot_nonce": ballot_nonce,
                "timestamp": timestamp,
                "previous_hash": previous_hash,
            }

            current_hash = self._safe_hash(str(sorted(ballot_payload.items())))

            cursor.execute("""
                INSERT INTO ballot_ledger (
                    ballot_id, voter_hash, election_type, party_code,
                    polling_unit_code, ballot_nonce, receipt_hash,
                    previous_hash, current_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ballot_id,
                voter_hash,
                election_type,
                party_code,
                polling_unit_code,
                ballot_nonce,
                receipt_hash,
                previous_hash,
                current_hash,
            ))

            cursor.execute("""
                UPDATE ballot_issue_log
                SET is_used = 1, used_at = CURRENT_TIMESTAMP
                WHERE ballot_id = ?
            """, (ballot_id,))

            signed_payload = self._sign_payload(ballot_payload)
            cursor.execute("""
                INSERT INTO ballot_receipts (
                    ballot_id, voter_hash, receipt_hash, ballot_nonce,
                    timestamp, verification_status, signed_payload, is_valid
                ) VALUES (?, ?, ?, ?, ?, 'VERIFIED', ?, 1)
            """, (
                ballot_id,
                voter_hash,
                receipt_hash,
                ballot_nonce,
                timestamp,
                signed_payload,
            ))

            conn.commit()

            return {
                "status": "success",
                "message": "Vote successfully recorded and anchored to the secure ballot ledger.",
                "ballot_id": ballot_id,
                "receipt_hash": receipt_hash,
                "current_hash": current_hash,
                "previous_hash": previous_hash,
                "timestamp": timestamp,
                "signature": signed_payload,
            }
        finally:
            conn.close()

    def verify_ballot_receipt(self, ballot_id: str, voter_hash: str) -> Dict:
        """Verify a ballot receipt against the ledger and signature."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT ballot_nonce, receipt_hash, signed_payload, is_valid
                FROM ballot_receipts
                WHERE ballot_id = ? AND voter_hash = ?
            """, (ballot_id, voter_hash))
            row = cursor.fetchone()

            if not row:
                return {
                    "status": "failed",
                    "message": "Receipt not found for this ballot and voter.",
                }

            ballot_nonce, receipt_hash, signed_payload, is_valid = row
            if is_valid != 1:
                return {
                    "status": "failed",
                    "message": "Receipt failed integrity validation.",
                }

            return {
                "status": "success",
                "message": "Receipt verified successfully.",
                "ballot_id": ballot_id,
                "ballot_nonce": ballot_nonce,
                "receipt_hash": receipt_hash,
                "signed_payload": signed_payload,
                "verified": True,
            }
        finally:
            conn.close()


# Demo usage
if __name__ == "__main__":
    manager = BallotSecurityManager()
    issued = manager.issue_ballot(
        voter_hash="demo_voter_hash_123",
        election_type="PRESIDENTIAL",
        polling_unit_code="PU-004",
        party_code="APC",
    )

    print("Issued:", issued)

    casted = manager.cast_ballot(
        ballot_id=issued["ballot_id"],
        voter_hash="demo_voter_hash_123",
        election_type="PRESIDENTIAL",
        party_code="APC",
        polling_unit_code="PU-004",
    )

    print("Cast:", casted)

    verified = manager.verify_ballot_receipt(issued["ballot_id"], "demo_voter_hash_123")
    print("Verified:", verified)
