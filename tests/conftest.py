"""Shared test fixtures.

Environment variables are set before the application modules are imported, because
config reads them at import time. Each test gets its own SQLite file and a fresh
in-memory rate-limit table.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

_BOOTSTRAP = tempfile.mkdtemp(prefix="evoting-tests-")
os.environ["EVOTING_ENV"] = "development"
os.environ["EVOTING_DB"] = os.path.join(_BOOTSTRAP, "bootstrap.db")
os.environ["EVOTING_HMAC_SECRET"] = "test-only-hmac-secret"
os.environ["EVOTING_AUTHORITY_KEY"] = os.path.join(_BOOTSTRAP, "authority.key")
os.environ.pop("EVOTING_SMS_GATEWAY_URL", None)
os.environ.pop("EVOTING_FACE_MATCHER", None)
os.environ["EVOTING_TRUST_PROXY"] = "0"

import pytest
from fastapi.testclient import TestClient

import db
import security as sec
import signing as sg
from main import app

PASSWORD = "correct-horse-battery-staple"
VOTER = {"nin": "12345678901", "vin": "NG12345678", "pu": "PU-001",
         "phone": "+2348012345678"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient backed by a brand-new database."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "evoting.db"))
    sec._hits.clear()
    db.init_db()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def sms(monkeypatch):
    """Capture the OTP instead of talking to a gateway, and accept any face image."""
    box = {"otp": None, "calls": 0}

    def fake_send(phone, otp):
        box["otp"] = otp
        box["phone"] = phone
        box["calls"] += 1

    monkeypatch.setattr(sec, "send_sms", fake_send)
    monkeypatch.setattr(sec, "face_check", lambda data: True)
    return box


@pytest.fixture
def voter(client):
    """A voter already on the register (NIN/VIN are never stored)."""
    with db.tx() as c:
        c.execute("INSERT INTO voters (voter_hash, polling_unit_code, phone_number) VALUES (?,?,?)",
                  (sec.voter_hash(VOTER["nin"], VOTER["vin"]), VOTER["pu"], VOTER["phone"]))
    return dict(VOTER)


@pytest.fixture
def set_election(client):
    def _set(election_type, status):
        with db.tx() as c:
            cur = c.execute("UPDATE elections SET status=? WHERE election_type=?", (status, election_type))
            assert cur.rowcount == 1, "unknown election type"
    return _set


@pytest.fixture
def staff(client):
    """One account per role, with bearer tokens minted directly (login has its own test)."""
    accounts = {"alice": "ADMIN", "rita": "REGISTRAR", "audrey": "AUDITOR"}
    tokens = {}
    with db.tx() as c:
        for username, role in accounts.items():
            salt, pw_hash = sec.hash_password(PASSWORD)
            c.execute("INSERT INTO admins (username, pw_salt, pw_hash, role) VALUES (?,?,?,?)",
                      (username, salt, pw_hash, role))
            token = sec.new_token()
            c.execute("INSERT INTO admin_sessions (token_hash, username, expires_at) VALUES (?,?,?)",
                      (sec.token_hash(token), username, sec.in_minutes(30)))
            tokens[role] = token
    return {"accounts": accounts, "tokens": tokens, "password": PASSWORD}


@pytest.fixture
def make_officer(client):
    """Register an officer with a locally generated key; return its private key."""
    def _make(officer_id, role, polling_unit, party=None):
        pem, public = sg.generate_keypair()
        with db.tx() as c:
            c.execute("INSERT INTO officers (officer_id, name, role, polling_unit_code, party_code, "
                      "public_key) VALUES (?,?,?,?,?,?)",
                      (officer_id, officer_id, role, polling_unit, party, public))
        return sg.load_private(pem)
    return _make


def _bearer(token):
    return {"Authorization": "Bearer " + token}


@pytest.fixture
def auth():
    """Return a helper that builds a bearer-token header."""
    return _bearer


@pytest.fixture
def start_session(client, sms):
    """Run identity + OTP steps and return the session token."""
    def _start(voter):
        response = client.post("/api/v1/auth/verify",
                               json={"nin": voter["nin"], "vin": voter["vin"]})
        assert response.status_code == 200, response.text
        return response.json()["session_token"]
    return _start


@pytest.fixture
def pass_face(client):
    def _pass(token):
        response = client.post("/api/v1/biometric/verify-face", headers=_bearer(token),
                               files={"file": ("face.jpg", b"not-a-real-jpeg", "image/jpeg")})
        assert response.status_code == 200, response.text
    return _pass


@pytest.fixture
def accredit(client, sms, start_session, pass_face):
    """Complete verify + OTP + face; return the session token ready to vote."""
    def _accredit(voter):
        token = start_session(voter)
        response = client.post("/api/v1/auth/verify-otp", headers=_bearer(token),
                               json={"otp_code": sms["otp"]})
        assert response.status_code == 200, response.text
        pass_face(token)
        return token
    return _accredit
