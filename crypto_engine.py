"""
crypto_engine.py - Thread-Safe Blind Signature & Anonymous Ballot Box Engine
"""
import hashlib
import secrets
import threading
from typing import Dict, Tuple, Set, Optional
from pydantic import BaseModel, Field
from config import ALLOWED_CANDIDATES


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def compute_ballot_hash(candidate: str, nonce: str, n: int) -> int:
    """Centralized function to compute m = H(candidate || nonce) mod n."""
    raw = f"{candidate.strip().upper()}:{nonce.strip()}".encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    m = int.from_bytes(digest, byteorder="big") % n
    if m == 0:
        raise ValueError("Hash generated a zero-value modular residue.")
    return m


class BlindVotePayload(BaseModel):
    candidate: str = Field(..., description="Political party code")
    nonce: str = Field(..., min_length=16, description="Entropy nonce preventing replay attacks")
    signature: int = Field(..., gt=0, description="Unblinded signature 's'")


class BlindSignatureAuthority:
    """Thread-safe Blind Signature Authority with atomic token tracking."""

    def __init__(self):
        # 64-bit demonstration prime set
        self.p = 61
        self.q = 53
        self.n = self.p * self.q  # 3233
        self.phi = (self.p - 1) * (self.q - 1)  # 3120
        self.e = 17
        self.d = modinv(self.e, self.phi)

        self.public_key: Tuple[int, int] = (self.e, self.n)
        self._used_tokens: Set[str] = set()
        self._lock = threading.Lock()

    def issue_blind_signature(self, session_token: str, blinded_message: int) -> int:
        if not (0 < blinded_message < self.n):
            raise ValueError(f"Blinded message must be in range (0, {self.n}).")

        with self._lock:  # Thread-safe atomic check-and-set
            if session_token in self._used_tokens:
                raise ValueError("Session token has already been used for blind signing.")
            self._used_tokens.add(session_token)

        # Compute Blind Signature: s' = (m')^d mod n
        return pow(blinded_message, self.d, self.n)


class BallotBox:
    """Thread-safe Anonymous Ballot Box with double-voting prevention."""

    def __init__(self, authority_public_key: Tuple[int, int]):
        self.e, self.n = authority_public_key
        self._cast_nonces: Set[str] = set()
        self._tally: Dict[str, int] = {c: 0 for c in ALLOWED_CANDIDATES}
        self._lock = threading.Lock()

    def cast_ballot(self, payload: BlindVotePayload) -> Tuple[bool, str]:
        candidate = payload.candidate.upper().strip()
        if candidate not in ALLOWED_CANDIDATES:
            return False, f"Invalid choice '{candidate}'. Must be one of {sorted(ALLOWED_CANDIDATES)}"

        with self._lock:
            # 1. Edge Case: Anti-Replay / Double Cast Check
            if payload.nonce in self._cast_nonces:
                return False, "REPLAY DETECTED: This ballot nonce has already been cast."

            # 2. Re-compute hash m using centralized function
            try:
                m = compute_ballot_hash(candidate, payload.nonce, self.n)
            except ValueError as e:
                return False, str(e)

            # 3. Verify RSA Signature: s^e mod n == m
            m_verified = pow(payload.signature, self.e, self.n)
            if m_verified != m:
                return False, "INVALID SIGNATURE: Ballot cryptographic signature verification failed."

            # 4. Commit Vote Atomically
            self._tally[candidate] += 1
            self._cast_nonces.add(payload.nonce)

        return True, "Ballot successfully verified and cast anonymously."

    def get_tally(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._tally)