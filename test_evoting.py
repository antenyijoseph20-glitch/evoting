import requests
import hashlib

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_full_voting_pipeline():
    print("🚀 Starting E-Voting End-to-End Test Suite...\n")

    # 1. Test Admin Health Endpoint
    print("-> Testing /admin/health...")
    resp = requests.get(f"{BASE_URL}/admin/health")
    assert resp.status_code == 200, f"Health check failed: {resp.text}"
    print(f"   [PASS] Health response: {resp.json()}")

    # 2. Test Voter Authentication
    print("\n-> Testing /auth/verify (Voter Registration)...")
    auth_payload = {
        "vin": "1234567890123456789",  # 19 digits
        "nin": "12345678901"           # 11 digits
    }
    resp = requests.post(f"{BASE_URL}/auth/verify", json=auth_payload)
    assert resp.status_code == 200, f"Auth verification failed: {resp.text}"
    auth_data = resp.json()
    session_token = auth_data["session_token"]
    print(f"   [PASS] Authenticated successfully. Session Token: {session_token[:12]}...")

    # 3. Test Blind Signature Authority
    print("\n-> Testing /authority/blind-sign...")
    # Generate a dummy blinded message for testing
    blinded_message = 12345
    blind_payload = {
        "session_token": session_token,
        "blinded_message": blinded_message
    }
    resp = requests.post(f"{BASE_URL}/authority/blind-sign", json=blind_payload)
    assert resp.status_code == 200, f"Blind sign failed: {resp.text}"
    blind_data = resp.json()
    blinded_sig = blind_data["blinded_signature"]
    print(f"   [PASS] Blind signature issued successfully.")

    # 4. Test Vote Submission
    print("\n-> Testing /ballotbox/submit-vote...")
    candidate = "Candidate A"
    nonce = hashlib.sha256(b"unique_voter_nonce_123").hexdigest()
    
    # For testing submission against the known keypair (e=17, n=3233, d=2753):
    # Let's compute a valid signature matching our crypto engine: m = hash(candidate:nonce) mod n, s = m^d mod n
    raw_bytes = f"{candidate}:{nonce}".encode("utf-8")
    m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % 3233
    valid_signature = pow(m, 2753, 3233)

    vote_payload = {
        "candidate": candidate,
        "nonce": nonce,
        "signature": valid_signature
    }
    resp = requests.post(f"{BASE_URL}/ballotbox/submit-vote", json=vote_payload)
    assert resp.status_code == 200, f"Vote submission failed: {resp.text}"
    vote_data = resp.json()
    print(f"   [PASS] Vote successfully chained! Block Hash: {vote_data['block_hash'][:16]}...")

    # 5. Test Receipt Verification
    print(f"\n-> Testing /ballotbox/verify-receipt/{nonce}...")
    resp = requests.get(f"{BASE_URL}/ballotbox/verify-receipt/{nonce}")
    assert resp.status_code == 200, f"Receipt verification failed: {resp.text}"
    print(f"   [PASS] Receipt verified: {resp.json()}")

    # 6. Test Election Tally
    print("\n-> Testing /tally/results...")
    resp = requests.get(f"{BASE_URL}/tally/results")
    assert resp.status_code == 200, f"Tally fetch failed: {resp.text}"
    print(f"   [PASS] Current tally: {resp.json()}")

    # 7. Test Global Audit Ledger
    print("\n-> Testing /tally/audit...")
    resp = requests.get(f"{BASE_URL}/tally/audit")
    assert resp.status_code == 200, f"Audit report failed: {resp.text}"
    audit_res = resp.json()
    assert audit_res["integrity_verified"] is True, "Ledger integrity check failed!"
    print(f"   [PASS] Audit passed! Valid ballots: {audit_res['valid_ballots_count']}, Integrity: {audit_res['integrity_verified']}")

    # 8. Test Admin Analytics
    print("\n-> Testing /admin/analytics...")
    resp = requests.get(f"{BASE_URL}/admin/analytics")
    assert resp.status_code == 200, f"Analytics fetch failed: {resp.text}"
    print(f"   [PASS] Analytics summary: {resp.json()}")

    print("\n🎉 ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_full_voting_pipeline()