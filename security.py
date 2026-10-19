"""Hashing, tokens, OTP, rate limiting, biometric and SMS adapters."""
import hashlib
import hmac
import importlib
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta

import cv2
import numpy as np
import requests
from fastapi import HTTPException, Request

import config


class SmsDeliveryError(Exception):
    """Raised when an OTP could not be handed to the SMS gateway."""


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
    """Deliver an OTP through the configured generic SMS webhook.

    The gateway contract is deliberately provider-neutral: POST JSON
    {"to": ..., "message": ..., "sender": ...} and return 2xx on acceptance.
    Set EVOTING_SMS_GATEWAY_URL plus EVOTING_SMS_API_KEY (and optionally
    EVOTING_SMS_AUTH_HEADER / EVOTING_SMS_AUTH_SCHEME / EVOTING_SMS_SENDER).
    """
    s = config.sms_settings()
    message = s["template"].format(otp=otp, minutes=config.OTP_TTL_MIN)
    if s["url"]:
        headers = {"Content-Type": "application/json"}
        if s["api_key"]:
            headers[s["auth_header"]] = (f"{s['auth_scheme']} {s['api_key']}".strip()
                                         if s["auth_scheme"] else s["api_key"])
        body = {"to": phone, "message": message, "sender": s["sender"]}
        last_error = None
        for attempt in range(max(0, s["retries"]) + 1):
            try:
                r = requests.post(s["url"], json=body, headers=headers, timeout=s["timeout_s"])
                if 200 <= r.status_code < 300:
                    return
                last_error = f"gateway returned HTTP {r.status_code}"
                # Retry transient server/rate-limit responses, fail fast on other 4xx.
                if r.status_code < 500 and r.status_code != 429:
                    break
            except requests.RequestException as e:
                last_error = type(e).__name__
            if attempt < s["retries"]:
                time.sleep(min(0.5 * (2 ** attempt), 4))
        raise SmsDeliveryError(last_error or "unknown gateway error")
    if config.DEV:
        print(f"[DEV-SMS] OTP for {mask_phone(phone)}: {otp}")
        return
    raise SmsDeliveryError("SMS gateway not configured")



# ---------- admin passwords ----------
def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(16)
    return salt, hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def check_password(password: str, salt: bytes, expected: bytes) -> bool:
    _, h = hash_password(password, salt)
    return hmac.compare_digest(h, expected)


# ---------- rate limiting (in-memory; use Redis behind multiple workers) ----------
_hits: dict = defaultdict(deque)


def client_ip(request: Request) -> str:
    """Real client IP when explicitly running behind a trusted proxy."""
    if config.TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "?"


def rate_limit(request: Request, bucket: str, limit: int, window_s: int) -> None:
    key = (client_ip(request), bucket)
    now, q = time.monotonic(), _hits[key]
    while q and now - q[0] > window_s:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many requests. Try again later.")
    q.append(now)


# ---------- biometrics ----------
# Development fallback: Haar cascade detection (exactly one face). It does NOT
# identify anyone. Production requires EVOTING_FACE_MATCHER to point at the
# operator's own matcher: "package.module:callable", where the callable accepts
# image bytes and returns True only when the enrolled voter is matched with a
# liveness check.
_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
_matcher = None
_matcher_spec = None


def load_face_matcher():
    """Load (and cache) the configured matcher. Returns None when unset."""
    global _matcher, _matcher_spec
    spec = os.getenv("EVOTING_FACE_MATCHER", "").strip()
    if not spec:
        return None
    if _matcher is not None and _matcher_spec == spec:
        return _matcher
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise RuntimeError("EVOTING_FACE_MATCHER must be 'module:callable'.")
    module = importlib.import_module(module_name)
    matcher = getattr(module, attr)
    if not callable(matcher):
        raise RuntimeError("EVOTING_FACE_MATCHER does not name a callable.")
    _matcher, _matcher_spec = matcher, spec
    return matcher


def face_check(image_bytes: bytes) -> bool:
    """Verify a voter's face.

    In development, confirms exactly one face is present. In production the
    configured matcher is used; startup fails if it cannot be loaded.
    """
    try:
        matcher = load_face_matcher()
    except Exception:
        raise HTTPException(503, "Biometric matcher unavailable.")
    if matcher is not None:
        try:
            return bool(matcher(image_bytes))
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, "Biometric matcher failed.")
    if not config.DEV:
        raise HTTPException(501, "Biometric matcher not configured.")
    if _cascade.empty():
        raise HTTPException(503, "Face model unavailable.")
    img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_GRAYSCALE)
    if img is None or min(img.shape) < 80:
        return False
    faces = _cascade.detectMultiScale(img, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))
    return len(faces) == 1
