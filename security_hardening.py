"""
SECURITY HARDENING MODULE - STEP 7
Production-grade security protections for the Nigerian e-voting platform.
Protects the system against brute-force attempts, injection, session hijack,
CSRF, unauthorized admin access, data leakage, and vote tampering.
"""

import hashlib
import sqlite3
import time
import secrets
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, List


class SecurityHardening:
    """
    Central security layer for the election platform.
    Includes:
    - rate limiting
    - request validation
    - session integrity checks
    - CSRF token management
    - admin RBAC
    - audit log protection
    - anti-exploitation controls
    """

    def __init__(self, db_path: str = "evoting.db"):
        self.db_path = db_path
        self._initialize_security_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_security_tables(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_name TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                request_count INTEGER DEFAULT 1,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(key_name, entity_key)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_csrf_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                user_key TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_admin_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id TEXT NOT NULL,
                session_token_hash TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                ip_address TEXT,
                expires_at TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                status TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    @staticmethod
    def sanitize_string(value: str) -> str:
        """Basic sanitization for dangerous input."""
        if value is None:
            return ""
        value = str(value).strip()
        value = value.replace("<", "&lt;")
        value = value.replace(">", "&gt;")
        value = value.replace("'", "&#x27;")
        value = value.replace('"', "&quot;")
        return value

    @staticmethod
    def validate_nigerian_phone(phone: str) -> bool:
        if not phone:
            return False
        phone = phone.replace(" ", "").replace("-", "")
        pattern = r'^(?:\+234|234|0)[789]\d{9}$'
        return bool(re.match(pattern, phone))

    @staticmethod
    def validate_nin(nin: str) -> bool:
        if not nin:
            return False
        return bool(re.fullmatch(r'\d{11}', nin))

    @staticmethod
    def validate_vin(vin: str) -> bool:
        if not vin:
            return False
        return bool(re.fullmatch(r'^[A-Z]{2}\d{6,8}$', vin.upper()))

    def record_security_event(self, actor: str, action: str, resource: str,
                             status: str, ip_address: str = "0.0.0.0",
                             details: str = "") -> None:
        """Record audit log without exposing sensitive data."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_audit_log (actor, action, resource, status, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (actor, action, resource, status, ip_address, details[:500]))
        conn.commit()
        conn.close()

    def check_rate_limit(self, key_name: str, entity_key: str,
                        max_requests: int = 20,
                        window_minutes: int = 5) -> Tuple[bool, str]:
        """
        Returns: (allowed, message)
        Prevents brute-force and DoS against auth routes and admin endpoints.
        """
        window_seconds = window_minutes * 60
        now = datetime.now(timezone.utc)

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT request_count, window_start, last_request
                FROM security_rate_limits
                WHERE key_name = ? AND entity_key = ?
            """, (key_name, entity_key))
            row = cursor.fetchone()

            if row is None:
                cursor.execute("""
                    INSERT INTO security_rate_limits (key_name, entity_key, request_count, window_start, last_request)
                    VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, (key_name, entity_key))
                conn.commit()
                return True, "Allowed"

            request_count, window_start, last_request = row
            window_start_dt = datetime.fromisoformat(str(window_start))
            last_request_dt = datetime.fromisoformat(str(last_request))

            if (now - window_start_dt).total_seconds() > window_seconds:
                cursor.execute("""
                    UPDATE security_rate_limits
                    SET request_count = 1, window_start = CURRENT_TIMESTAMP, last_request = CURRENT_TIMESTAMP
                    WHERE key_name = ? AND entity_key = ?
                """, (key_name, entity_key))
                conn.commit()
                return True, "Window reset"

            if request_count >= max_requests:
                return False, f"Rate limit exceeded for {key_name}. Please try again later."

            cursor.execute("""
                UPDATE security_rate_limits
                SET request_count = request_count + 1, last_request = CURRENT_TIMESTAMP
                WHERE key_name = ? AND entity_key = ?
            """, (key_name, entity_key))
            conn.commit()
            return True, "Allowed"
        finally:
            conn.close()

    def generate_csrf_token(self, user_key: str) -> str:
        """Generate a secure CSRF token."""
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_csrf_tokens (token_hash, user_key, expires_at)
            VALUES (?, ?, ?)
        """, (token_hash, user_key, expires_at))
        conn.commit()
        conn.close()
        return token

    def validate_csrf_token(self, user_key: str, submitted_token: str) -> bool:
        """Validate a CSRF token."""
        if not submitted_token:
            return False
        token_hash = hashlib.sha256(submitted_token.encode()).hexdigest()

        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT expires_at FROM security_csrf_tokens
                WHERE token_hash = ? AND user_key = ?
            """, (token_hash, user_key))
            row = cursor.fetchone()
            if row is None:
                return False
            expires_at = datetime.fromisoformat(str(row[0]))
            if datetime.now(timezone.utc) > expires_at:
                cursor.execute("DELETE FROM security_csrf_tokens WHERE token_hash = ?", (token_hash,))
                conn.commit()
                return False
            cursor.execute("DELETE FROM security_csrf_tokens WHERE token_hash = ?", (token_hash,))
            conn.commit()
            return True
        finally:
            conn.close()

    def generate_admin_session(self, admin_id: str, role: str, ip_address: str) -> str:
        """Generate session token for admin access."""
        token = secrets.token_urlsafe(64)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_admin_sessions (admin_id, session_token_hash, role, ip_address, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (admin_id, token_hash, role, ip_address, expires_at))
        conn.commit()
        conn.close()
        return token

    def validate_admin_session(self, session_token: str, role_required: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Validate admin session and role."""
        if not session_token:
            return False, None
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()

        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT admin_id, role, expires_at, is_active
                FROM security_admin_sessions
                WHERE session_token_hash = ?
            """, (token_hash,))
            row = cursor.fetchone()
            if row is None:
                return False, None

            admin_id, role, expires_at, is_active = row
            if is_active != 1:
                return False, None
            if datetime.now(timezone.utc) > datetime.fromisoformat(str(expires_at)):
                cursor.execute("UPDATE security_admin_sessions SET is_active = 0 WHERE session_token_hash = ?", (token_hash,))
                conn.commit()
                return False, None
            if role_required and role != role_required:
                return False, None
            return True, admin_id
        finally:
            conn.close()

    def admin_logout(self, session_token: str) -> bool:
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE security_admin_sessions SET is_active = 0 WHERE session_token_hash = ?", (token_hash,))
            conn.commit()
            return True
        finally:
            conn.close()

    def strong_password_check(self, password: str) -> bool:
        """Validate a strong password (for admin credentials)."""
        if len(password) < 12:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[^A-Za-z0-9]', password):
            return False
        return True

    def secure_compare(self, a: str, b: str) -> bool:
        """Use constant-time comparison to avoid timing attacks."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a.encode(), b.encode()):
            result |= x ^ y
        return result == 0

    def hash_sensitive_value(self, value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()


# Demo example
if __name__ == "__main__":
    security = SecurityHardening()
    print("Rate limit check:", security.check_rate_limit("login", "test-user", max_requests=3, window_minutes=1))
    print("CSRF token:", security.generate_csrf_token("admin-001"))
    print("Strong password:", security.strong_password_check("StrongPass!2026"))
