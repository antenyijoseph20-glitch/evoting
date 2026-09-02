import pytest
from fastapi.testclient import TestClient
from main import app, OFFICIAL_PARTIES, LEDGER, VOTES_DB

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_db_state():
    """Resets the in-memory ledger and votes database before each test."""
    global LEDGER, VOTES_DB
    # Preserve genesis block
    genesis = LEDGER[0]
    LEDGER.clear()
    LEDGER.append(genesis)
    VOTES_DB.clear()
    yield

def test_admin_health():
    """Verify that the health check endpoint returns online status and correct initial metrics."""
    response = client.get("/api/v1/admin/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["database_status"] == "ONLINE"
    assert data["ledger_height"] == 1
    assert data["total_ballots_cast"] == 0

def test_single_vote_submission_and_zk_receipt():
    """Verify that a valid vote creates a ZK receipt hash and anchors correctly to the ledger."""
    # Step 1: Authenticate voter
    auth_res = client.post("/api/v1/auth/verify", json={
        "vin": "1234567890123456789",
        "nin": "12345678901"
    })
    assert auth_res.status_code == 200
    assert auth_res.json()["status"] == "SUCCESS"

    # Step 2: Submit vote
    vote_payload = {
        "selections": {
            "presidential": "All Progressives Congress (APC)",
            "senatorial": "Peoples Democratic Party (PDP)",
            "house_of_reps": "Labour Party (LP)"
        },
        "nonce": "test_nonce_12345",
        "signature": 3106
    }
    vote_res = client.post("/api/v1/ballotbox/submit-vote", json=vote_payload)
    assert vote_res.status_code == 200
    vote_data = vote_res.json()
    
    assert "receipt_hash" in vote_data
    assert "block_hash" in vote_data
    assert vote_data["total_votes_cast"] == 1

    # Step 3: Verify the receipt hash via public verifier endpoint
    receipt_hash = vote_data["receipt_hash"]
    verify_res = client.post("/api/v1/receipt/verify", json={"receipt_hash": receipt_hash})
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["verified"] is True
    assert verify_data["block_id"] == 1

def test_cryptographic_chain_integrity():
    """Verify that consecutive blocks properly link their previous_hash pointers."""
    valid_party = list(OFFICIAL_PARTIES)[0]
    
    # Cast two sequential votes
    for i in range(2):
        client.post("/api/v1/ballotbox/submit-vote", json={
            "selections": {
                "presidential": valid_party,
                "senatorial": valid_party,
                "house_of_reps": valid_party
            },
            "nonce": f"nonce_{i}",
            "signature": 3106
        })

    # Check ledger linkage
    assert len(LEDGER) == 3  # Genesis + 2 votes
    
    block_1 = LEDGER[1]
    block_2 = LEDGER[2]
    
    # Block 2's previous_hash must match Block 1's block_hash
    assert block_2["previous_hash"] == block_1["block_hash"]
    assert block_1["previous_hash"] == LEDGER[0]["block_hash"]

def test_batch_sync_failure_handling():
    """Verify that batch sync processes valid votes while correctly isolating and reporting invalid votes."""
    valid_party = list(OFFICIAL_PARTIES)[0]
    
    batch_payload = {
        "device_id": "test_terminal_01",
        "votes": [
            {
                "selections": {
                    "presidential": valid_party,
                    "senatorial": valid_party,
                    "house_of_reps": valid_party
                },
                "nonce": "batch_valid_1",
                "signature": 3106,
                "client_timestamp": "2026-09-02T22:00:00Z"
            },
            {
                "selections": {
                    "presidential": "Invalid Party X",  # Should fail validation
                    "senatorial": valid_party,
                    "house_of_reps": valid_party
                },
                "nonce": "batch_invalid_2",
                "signature": 3106,
                "client_timestamp": "2026-09-02T22:00:01Z"
            }
        ]
    }

    response = client.post("/api/v1/ballotbox/sync-batch", json=batch_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "SYNC_COMPLETE"
    assert data["processed_count"] == 1
    assert data["failed_count"] == 1
    assert len(data["failed_votes"]) == 1
    assert data["failed_votes"][0]["nonce"] == "batch_invalid_2"
    assert "invalid party" in data["failed_votes"][0]["reason"].lower()

    # Ensure only the valid vote was added to the ledger
    assert len(VOTES_DB) == 1
    assert len(LEDGER) == 2  # Genesis + 1 successful batch vote

def test_ledger_audit_endpoint():
    """Verify the audit endpoint reports integrity status successfully."""
    response = client.get("/api/v1/tally/audit")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "AUDIT_COMPLETE"
    assert data["integrity_verified"] is True