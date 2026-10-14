import sqlite3
import requests
import hashlib
import secrets

BASE_URL = "http://127.0.0.1:8000/api/v1"

# Known authority keys from test environment
E_PUB = 17
N_MOD = 3233
D_PRIV = 2753

def create_valid_signed_ballot(candidate: str):
    """Locally generates a valid RSA blind signature for testing ledger tamper detection."""
    nonce = secrets.token_hex(16)
    raw_bytes = f"{candidate}:{nonce}".encode("utf-8")
    m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % N_MOD
    
    # Blinding factor
    r = 5
    m_prime = (m * pow(r, E_PUB, N_MOD)) % N_MOD
    s_prime = pow(m_prime, D_PRIV, N_MOD)
    
    # Unblind signature using modular inverse
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
    r_inv = egcd(r, N_MOD)[1] % N_MOD
    signature = (s_prime * r_inv) % N_MOD

    return {
        "candidate": candidate,
        "nonce": nonce,
        "signature": signature
    }

def test_ledger_tamper_detection():
    print("======================================================================")
    print(" E-VOTING HASH-CHAIN LEDGER TAMPER DETECTION TEST SUITE")
    print("======================================================================")

    # 1. Obtain and cast valid ballots
    print("\n[STEP 1] Generating and casting 3 valid blind-signed ballots...")
    candidates = ["LP", "APC", "LP"]

    for idx, candidate in enumerate(candidates, start=1):
        ballot_payload = create_valid_signed_ballot(candidate)
        res = requests.post(f"{BASE_URL}/ballotbox/submit-vote", json=ballot_payload)
        assert res.status_code == 200, f"Failed to cast ballot {idx}: {res.text}"
        
        block_hash = res.json().get("block_hash", "N/A")
        print(f"  ✓ Ballot {idx} ({candidate}) cast successfully. Block Hash: {str(block_hash)[:16]}...")

    # 2. Run clean audit pass
    print("\n[STEP 2] Running clean zero-knowledge audit pass...")
    audit_res = requests.get(f"{BASE_URL}/tally/audit")
    assert audit_res.status_code == 200, f"Audit request failed: {audit_res.text}"
    audit_data = audit_res.json()
    
    assert audit_data.get("integrity_verified") is True, f"Audit failed on clean DB: {audit_data}"
    print(f"  ✓ PASSED: Audit verified {audit_data.get('total_ballots_audited')} blocks with 100% integrity.")

    # 3. Direct SQLite Database Tampering
    print("\n[STEP 3] Simulating direct disk edit (Altering block #2 candidate in evoting.db)...")
    conn = sqlite3.connect("evoting.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE ballot_box SET candidate = 'PDP' WHERE id = 2")
    conn.commit()
    conn.close()
    print("  ✓ Database tampered directly on disk!")

    # 4. Verify Audit Pass detects tampering
    print("\n[STEP 4] Re-running audit pass post-tamper...")
    audit_res = requests.get(f"{BASE_URL}/tally/audit")
    assert audit_res.status_code == 200, f"Audit query failed: {audit_res.text}"
    audit_data = audit_res.json()
    
    assert audit_data.get("integrity_verified") is False, "FAIL: Audit pass did not detect direct DB edit!"
    print(f"  ✓ PASSED: Tampering DETECTED! Corrupted blocks count: {audit_data.get('invalid_ballots_count')}")
    print("\n======================================================================")
    print(" HASH-CHAIN LEDGER TAMPER TEST COMPLETE")
    print("======================================================================")

if __name__ == "__main__":
    test_ledger_tamper_detection()