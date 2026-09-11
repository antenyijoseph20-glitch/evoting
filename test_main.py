import os
import sqlite3
import hashlib
import numpy as np
import cv2
import pytest
from fastapi.testclient import TestClient

# Import the FastAPI app from your main module (adjust 'main' if your file is named differently, e.g., 'app.py')
from main import app, DB_NAME, init_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensure a clean test state or initialize default records before tests run."""
    init_db()
    yield

def generate_dummy_face_image():
    """Generates a valid JPEG image with a simulated face-like rectangle for OpenCV testing."""
    # Create a 200x200 blank grayscale-convertible image
    img = np.zeros((300, 300, 3), dtype=np.uint8) * 255
    # Draw a simulated face rectangle/circle so Haar Cascade might pick it up, 
    # or test the fallback error response if no face is detected.
    cv2.rectangle(img, (100, 100), (200, 220), (255, 255, 255), -1)
    success, encoded_img = cv2.imencode(".jpg", img)
    return encoded_img.tobytes()


def test_read_main_portal():
    """Test that the root endpoint serves the frontend HTML or handles missing files gracefully."""
    response = client.get("/")
    assert response.status_code == 200


def test_admin_register_voter():
    """Test registering a new voter via the admin endpoint."""
    response = client.post(
        "/admin/register",
        data={
            "nin": "99887766554",
            "vin": "NG99887766",
            "polling_unit": "PU-002",
            "phone_number": "+2347012572796"
        }
    )
    assert response.status_code == 200
    assert "Register Test Voter" in response.text


def test_voter_verification_flow():
    """Test the complete verification and token-issuance workflow for an eligible voter."""
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
    assert "voter_identifier" in data


def test_otp_dispatch_and_verification():
    """Test requesting and verifying an SMS OTP code."""
    voter_id = "test_voter_identifier_123"
    phone = "+2347012572796"
    
    # 1. Send OTP
    send_response = client.post(
        "/api/v1/auth/send-otp",
        json={"voter_identifier": voter_id, "phone_number": phone}
    )
    assert send_response.status_code == 200
    assert send_response.json()["status"] == "success"
    
    # Extract the stored OTP directly from the test sqlite database for verification testing
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT otp_code FROM otp_store WHERE voter_identifier = ?", (voter_id,))
    row = cursor.fetchone()
    conn.close()
    
    assert row is not None
    active_otp = row[0]
    
    # 2. Verify OTP with correct code
    verify_response = client.post(
        " /api/v1/auth/verify-otp".strip(),
        json={"voter_identifier": voter_id, "otp_code": active_otp}
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["status"] == "verified"


def test_biometric_face_verification():
    """Test the facial recognition endpoint with a generated multipart file upload."""
    image_bytes = generate_dummy_face_image()
    response = client.post(
        "/api/v1/biometric/verify-face",
        files={"file": ("snapshot.jpg", image_bytes, "image/jpeg")}
    )
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


def test_cryptographic_blind_sign_and_ballot_cast():
    """Test the zero-knowledge blind signing and secure ballot casting lifecycle."""
    # Step A: Verify voter to acquire a valid session token
    verify_payload = {
        "nin": "55443322110",
        "vin": "NG55443322",
        "polling_unit_code": "PU-003",
        "phone_number": "+2347012572796"
    }
    v_resp = client.post("/api/v1/auth/verify", json=verify_payload)
    assert v_resp.status_code == 200
    session_token = v_resp.json()["session_token"]
    
    # Step B: Request Blind Signature
    blind_payload = {
        "session_token": session_token,
        "blinded_message": 123456789
    }
    b_resp = client.post("/api/v1/authority/blind-sign", json=blind_payload)
    assert b_resp.status_code == 200
    b_data = b_resp.json()
    assert b_data["status"] == "success"
    assert "blinded_signature" in b_data
    
    # Step C: Cast Ballot using the same session token
    ballot_payload = {
        "session_token": session_token,
        "election_type": "PRESIDENTIAL",
        "party_code": "APC",
        "polling_unit_code": "PU-003"
    }
    cast_resp = client.post("/api/v1/ballot/cast", json=ballot_payload)
    assert cast_resp.status_code == 200
    cast_data = cast_resp.json()
    assert cast_data["status"] == "success"
    assert "receipt" in cast_data
    
    # Step D: Verify double-voting prevention (reusing session token should fail)
    duplicate_cast = client.post("/api/v1/ballot/cast", json=ballot_payload)
    assert duplicate_cast.status_code == 400


def test_admin_dashboards_and_audit_export():
    """Test admin tally view and cryptographic ledger export."""
    tally_response = client.get("/admin/tally")
    assert tally_response.status_code == 200
    assert "Live Election Results Tally" in tally_response.text
    
    export_response = client.get("/admin/audit/export")
    assert export_response.status_code == 200
    export_data = export_response.json()
    assert export_data["status"] == "success"
    assert "ledger" in export_data