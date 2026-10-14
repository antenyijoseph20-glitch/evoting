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

ELECTION_PARTIES = {
    t: ["APC", "PDP", "LP", "NNPP", "APGA", "AAC", "ADC", "PRP"]
    for t in ("PRESIDENTIAL", "SENATE", "HOUSE_OF_REPS", "GOVERNOR", "HOUSE_OF_ASSEMBLY")
}


def _hmac_secret() -> bytes:
    s = os.getenv("EVOTING_HMAC_SECRET")
    if s:
        return s.encode()
    if not DEV:
        raise RuntimeError("EVOTING_HMAC_SECRET must be set in production.")
    return b"dev-only-insecure-secret"


HMAC_SECRET = _hmac_secret()


def production_blockers() -> list[str]:
    """Things that are still stubs. Production startup is refused while any exist."""
    blockers = []
    if not os.getenv("EVOTING_SMS_GATEWAY_URL"):
        blockers.append("No SMS gateway configured (OTP delivery is a dev stub).")
    if not os.getenv("EVOTING_FACE_MATCHER"):
        blockers.append("No face-recognition matcher with liveness configured "
                        "(Haar cascade only detects a face, it does not identify one).")
    if not os.getenv("EVOTING_AUTHORITY_KEY"):
        blockers.append("No authority signing key file configured (EVOTING_AUTHORITY_KEY).")
    return blockers
