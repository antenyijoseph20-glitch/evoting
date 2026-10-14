"""Hashing, tokens, OTP, rate limiting, biometric and SMS adapters."""
import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta

import cv2
import numpy as np
from fastapi import HTTPException, Request

import config


# ---------- time / tokens ----------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def in_minutes(m: int) -> str:
    return iso(now_utc() + timedelta(minutes=m))


def is_expired(iso_ts: str) -> bool:
    return datetime.fromisoformat(iso_ts) <= now_utc()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def bearer(request: Request) -> str:
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer ") or len(h) < 20:
        raise HTTPException(401, "Missing or invalid credentials.")
    return h[7:]


# ---------- voter identity ----------
def voter_hash(nin: str, vin: str) -> str:
    """Keyed hash with an unambiguous delimiter. NINs can't be brute-forced without the secret."""
    msg = f"{nin.strip()}|{vin.strip().upper()}".encode()
    return hmac.new(config.HMAC_SECRET, msg, hashlib.sha256).hexdigest()


def mask_phone(p: str) -> str:
    return p[:4] + "*" * max(0, len(p) - 7) + p[-3:]


# ---------- OTP ----------
def new_otp() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(6))


def otp_hash(session_token_hash: str, otp: str) -> str:
    return hmac.new(config.HMAC_SECRET, f"{session_token_hash}|{otp}".encode(), hashlib.sha256).hexdigest()


def send_sms(phone: str, otp: str) -> None:
    gateway = os.getenv("EVOTING_SMS_GATEWAY_URL")
    if gateway:
        raise NotImplementedError("Implement the SMS gateway client here.")
    if config.DEV:
        print(f"[DEV-SMS] OTP for {mask_phone(phone)}: {otp}")
        return
    raise RuntimeError("SMS gateway not configured.")


# ---------- admin passwords ----------
def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(16)
    return salt, hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def check_password(password: str, salt: bytes, expected: bytes) -> bool:
    _, h = hash_password(password, salt)
    return hmac.compare_digest(h, expected)


# ---------- rate limiting (in-memory; use Redis behind multiple workers) ----------
_hits: dict = defaultdict(deque)


def rate_limit(request: Request, bucket: str, limit: int, window_s: int) -> None:
    key = (request.client.host if request.client else "?", bucket)
    now, q = time.monotonic(), _hits[key]
    while q and now - q[0] > window_s:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many requests. Try again later.")
    q.append(now)


# ---------- biometrics ----------
_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")


def face_check(image_bytes: bytes) -> bool:
    """DEV ONLY: confirms exactly one face is present. This is detection, NOT identity matching.
    Replace with an embedding matcher (e.g. ArcFace) against the enrolled template, plus liveness."""
    if not config.DEV:
        raise HTTPException(501, "Biometric matcher not configured.")
    if _cascade.empty():
        raise HTTPException(503, "Face model unavailable.")
    img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_GRAYSCALE)
    if img is None or min(img.shape) < 80:
        return False
    faces = _cascade.detectMultiScale(img, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))
    return len(faces) == 1
