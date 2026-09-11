import os
import pytest
from fastapi.testclient import TestClient
from main import app, init_db, DB_NAME

@pytest.fixture(autouse=True)
def clean_test_env():
    """Setup a clean test database before each test execution."""
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
    init_db()
    yield
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)

client = TestClient(app)


def test_read_main_portal():
    """Verify that the frontend voting portal loads successfully."""
    response = client.get("/")
    assert response.status_code == 200
    assert "Nigeria E2E-V Portal" in response.text


def test_voter_identity_lookup():
    """Test successful voter accreditation and session token generation."""
    payload = {
        "nin": "12345678901",
        "vin": "NG12345678",
        "polling_unit_code": "PU-001",
        "phone_number": "+2347012572796"
    }
    response = client.post("/api/v1/auth/verify", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "session_token" in data
    assert len(data["session_token"]) > 0


def test_biometric_face_verification():
    """Test the biometric facial verification endpoint with a mock image upload."""
    files = {"file": ("snapshot.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF", "image/jpeg")}
    response = client.post("/api/v1/biometric/verify-face", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "confidence_score" in data


def test_admin_tally_dashboard():
    """Verify that the live election tally dashboard renders properly."""
    response = client.get("/admin/tally")
    assert response.status_code == 200
    assert "Live Election Results Tally" in response.text


def test_audit_ledger_export():
    """Verify that the audit ledger export endpoint returns valid JSON structure."""
    response = client.get("/admin/audit/export")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "total_blocks" in data
    assert isinstance(data["ledger"], list)