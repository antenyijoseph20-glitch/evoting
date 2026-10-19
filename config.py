"""Central configuration. Fails closed in production."""
import os

ENV = os.getenv("EVOTING_ENV", "development")
DEV = ENV != "production"
DB_PATH = os.getenv("EVOTING_DB", "evoting.db")

SESSION_TTL_MIN = 15
OTP_TTL_MIN = 5
OTP_MAX_ATTEMPTS = 3
FACE_MAX_ATTEMPTS = 3
ADMIN_TTL_MIN = 30
MAX_SESSIONS_PER_VOTER_PER_HOUR = 5
MAX_UPLOAD_BYTES = 2 * 1024 * 1024

# Honour X-Forwarded-For only when the app is behind a trusted reverse proxy.
TRUST_PROXY = os.getenv("EVOTING_TRUST_PROXY", "0").lower() in ("1", "true", "yes")

ELECTION_PARTIES = {
    t: ["APC", "PDP", "LP", "NNPP", "APGA", "AAC", "ADC", "PRP"]
    for t in ("PRESIDENTIAL", "SENATE", "HOUSE_OF_REPS", "GOVERNOR", "HOUSE_OF_ASSEMBLY")
}

ELECTION_NAMES = {
    "PRESIDENTIAL": "Presidential",
    "SENATE": "Senatorial",
    "HOUSE_OF_REPS": "House of Representatives",
    "GOVERNOR": "Governorship",
    "HOUSE_OF_ASSEMBLY": "House of Assembly",
}

PARTY_NAMES = {
    "APC": "All Progressives Congress",
    "PDP": "Peoples Democratic Party",
    "LP": "Labour Party",
    "NNPP": "New Nigeria Peoples Party",
    "APGA": "All Progressives Grand Alliance",
    "AAC": "African Action Congress",
    "ADC": "African Democratic Congress",
    "PRP": "Peoples Redemption Party",
}


def sms_settings() -> dict:
    """Read at call time so tests and operators can change delivery without a restart."""
    return {
        "url": (os.getenv("EVOTING_SMS_GATEWAY_URL") or "").strip() or None,
        "api_key": (os.getenv("EVOTING_SMS_API_KEY") or "").strip() or None,
        "auth_header": os.getenv("EVOTING_SMS_AUTH_HEADER", "Authorization"),
        "auth_scheme": os.getenv("EVOTING_SMS_AUTH_SCHEME", "Bearer"),
        "sender": os.getenv("EVOTING_SMS_SENDER", "E2E-V"),
        "timeout_s": float(os.getenv("EVOTING_SMS_TIMEOUT_S", "10")),
        "retries": int(os.getenv("EVOTING_SMS_RETRIES", "2")),
        "template": os.getenv("EVOTING_SMS_TEMPLATE",
                              "Your E2E-V code is {otp}. It expires in {minutes} minutes. Never share it."),
    }


def _hmac_secret() -> bytes:
    s = (os.getenv("EVOTING_HMAC_SECRET") or "").strip()
    if s:
        if not DEV and len(s) < 32:
            raise RuntimeError("EVOTING_HMAC_SECRET must be at least 32 characters in production.")
        return s.encode()
    if not DEV:
        raise RuntimeError("EVOTING_HMAC_SECRET must be set in production.")
    return b"dev-only-insecure-secret"


HMAC_SECRET = _hmac_secret()


def production_blockers() -> list[str]:
    """Things that are still stubs. Production startup is refused while any exist."""
    blockers = []
    if not sms_settings()["url"]:
        blockers.append("No SMS gateway configured (EVOTING_SMS_GATEWAY_URL); OTP delivery is a dev stub.")
    if not (os.getenv("EVOTING_FACE_MATCHER") or "").strip():
        blockers.append("No face-recognition matcher with liveness configured "
                        "(Haar cascade only detects a face, it does not identify one).")
    if not (os.getenv("EVOTING_AUTHORITY_KEY") or "").strip():
        blockers.append("No authority signing key file configured (EVOTING_AUTHORITY_KEY).")
    return blockers
