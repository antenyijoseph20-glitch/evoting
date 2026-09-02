"""
session_manager.py - Session Lifecycle and Expiration Management
"""
import time
import threading
from typing import Dict, Tuple
from config import SESSION_TTL_SECONDS


class SessionManager:
    """Manages active voter session state with thread safety and automatic TTL expiration."""

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS):
        self._sessions: Dict[str, dict] = {}
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()

    def create_session(self, token: str, vin: str) -> None:
        with self._lock:
            self._cleanup_expired_unlocked()
            self._sessions[token] = {
                "vin": vin,
                "created_at": time.time(),
                "used_for_signing": False
            }

    def validate_session(self, token: str) -> Tuple[bool, str]:
        """Returns (is_valid, reason_if_invalid)."""
        with self._lock:
            self._cleanup_expired_unlocked()
            session = self._sessions.get(token)

            if not session:
                return False, "Session token is invalid or expired."

            if session["used_for_signing"]:
                return False, "Session token has already been spent."

            return True, "Session active."

    def mark_spent(self, token: str) -> None:
        with self._lock:
            if token in self._sessions:
                self._sessions[token]["used_for_signing"] = True

    def _cleanup_expired_unlocked(self):
        """Evicts expired sessions to avoid RAM memory leaks."""
        now = time.time()
        expired = [t for t, s in self._sessions.items() if now - s["created_at"] > self.ttl_seconds]
        for token in expired:
            del self._sessions[token]