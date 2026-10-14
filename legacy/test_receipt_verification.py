"""
test_receipt_verification.py - Test suite for Voter Receipt Lookup API
"""

import hashlib
import requests

BASE_URL = "http://127.0.0.1:8000/api/v1"

# Keys matching server
E_PUB = 17
N_MOD = 3233
D_PRIV = 2753

def blind_and_sign(candidate: str, nonce: str) -> int:
    raw_bytes = f"{candidate}:{nonce}".encode("utf-8")
    m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % N_MOD
    r = 5  # Blind factor
    m_prime = (m * pow(r, E_PUB, N_MOD)) % N_MOD
    s_prime = pow(m_prime, D_PRIV, N_MOD)
    
    # Extended Euclidean algorithm for inverse
    def egcd(a, b):
        if a == 0: return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
    r_inv = egcd(r, N_MOD)[1] % N_MOD
    s = (s_prime * r_inv) % N_MOD
    return s

def run_receipt_tests():
    print("=" * 70)
    print("  E-VOTING SYSTEM RECEIPT VERIFICATION TEST SUITE")
    print("=" * 70)

    # 1. Cast a ballot
    candidate = "LP"
    nonce = "receipt_test_nonce_9999"
    signature = blind_and_sign(candidate, nonce)

    print("\n[STEP 1] Submitting Ballot to Ballot Box...")
    submit_res = requests.post(
        f"{BASE_URL}/ballotbox/submit-vote",
        json={"candidate": candidate, "nonce": nonce, "signature": signature}
    )
    assert submit_res.status_code == 200, f"Vote submission failed: {submit_res.text}"
    print("  ✓ Ballot successfully submitted.")

    # 2. Verify Receipt Lookup for Valid Nonce
    print("\n[STEP 2] Testing Receipt Lookup with Valid Nonce...")
    receipt_res = requests.get(f"{BASE_URL}/ballotbox/verify-receipt/{nonce}")
    assert receipt_res.status_code == 200, f"Receipt lookup failed: {receipt_res.text}"
    data = receipt_res.json()
    
    assert data["verified"] is True
    assert data["candidate"] == candidate
    assert data["nonce"] == nonce
    assert data["signature"] == signature
    print(f"  ✓ PASSED: Receipt found! Status: {data['status']}")
    print(f"    Candidate: {data['candidate']} | Timestamp: {data['recorded_at']}")

    # 3. Verify Receipt Lookup for Non-existent Nonce
    print("\n[STEP 3] Testing Receipt Lookup with Non-existent Nonce...")
    fake_nonce = "non_existent_nonce_0000"
    missing_res = requests.get(f"{BASE_URL}/ballotbox/verify-receipt/{fake_nonce}")
    assert missing_res.status_code == 404, f"Expected 404 but got {missing_res.status_code}"
    print("  ✓ PASSED: Non-existent receipt correctly returned 404 Not Found.")

    print("\n" + "=" * 70)
    print("  RECEIPT VERIFICATION TEST SUITE COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    run_receipt_tests()