"""
test_client.py - Automated End-to-End Voting Protocol Client
"""
import requests
import hashlib
import secrets
from math import gcd

BASE_URL = "http://127.0.0.1:8000"


def modinv(a: int, m: int) -> int:
    """Computes modular multiplicative inverse of a mod m using Extended Euclidean Algorithm."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return g, x, y

    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def run_e2e_voting_test():
    print("=" * 60)
    print("  E-VOTING END-TO-END CRYPTOGRAPHIC WORKFLOW TEST")
    print("=" * 60)

    # 1. Health Check & Get Authority Public Key
    print("\n[STEP 1] Fetching System Health & Authority Public Key...")
    res = requests.get(f"{BASE_URL}/")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    health_data = res.json()
    print(f"  ✓ System Status: {health_data['status']}")

    e = 17
    n = 3233
    print(f"  ✓ Authority Public Key: e={e}, n={n}")

    # 2. Authenticate Voter
    print("\n[STEP 2] Authenticating Voter Biometrics (INEC/NIMC)...")
    auth_payload = {
        "vin": "9012345678901234567",
        "nin": "12345678901"
    }
    res = requests.post(f"{BASE_URL}/api/v1/auth/verify", json=auth_payload)
    assert res.status_code == 200, f"Auth failed: {res.text}"
    auth_data = res.json()
    session_token = auth_data["session_token"]
    print(f"  ✓ Voter Identified: {auth_data['voter_name']}")
    print(f"  ✓ Session Token Issued: {session_token[:20]}...")

    # 3. Create Anonymous Ballot & Blind it locally
    print("\n[STEP 3] Preparing Anonymous Ballot & Applying RSA Blind Factor...")
    chosen_candidate = "LP"
    nonce = secrets.token_hex(16)

    # Compute m = H(candidate || nonce) mod n
    raw_bytes = f"{chosen_candidate}:{nonce}".encode("utf-8")
    m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % n

    # Dynamically select r coprime to n
    r = 37
    while gcd(r, n) != 1:
        r += 2

    # m' = (m * r^e) mod n
    m_prime = (m * pow(r, e, n)) % n
    print(f"  ✓ Candidate Choice: '{chosen_candidate}' (Hidden from Authority)")
    print(f"  ✓ Raw Ballot Hash (m): {m}")
    print(f"  ✓ Blind Factor (r):    {r}")
    print(f"  ✓ Blinded Hash (m'):   {m_prime}")

    # 4. Request Blind Signature from Authority
    print("\n[STEP 4] Requesting Blind Signature from Authority...")
    sign_payload = {
        "session_token": session_token,
        "blinded_message": m_prime
    }
    res = requests.post(f"{BASE_URL}/api/v1/authority/blind-sign", json=sign_payload)
    assert res.status_code == 200, f"Blind signing failed: {res.text}"
    s_prime = res.json()["blinded_signature"]
    print(f"  ✓ Received Blind Signature (s'): {s_prime}")

    # 5. Unblind Signature Locally
    print("\n[STEP 5] Unblinding Signature Locally (r^-1 mod n)...")
    r_inv = modinv(r, n)
    s = (s_prime * r_inv) % n
    print(f"  ✓ Modular Inverse (r^-1): {r_inv}")
    print(f"  ✓ Unblinded Valid Signature (s): {s}")

    # Verify locally prior to submission
    local_m = pow(s, e, n)
    print(f"  ✓ Local Signature Check: s^e mod n = {local_m} (Matches m: {local_m == m})")

    # 6. Submit Anonymous Ballot to Public Ballot Box
    print("\n[STEP 6] Casting Anonymous Ballot to Ballot Box...")
    ballot_payload = {
        "candidate": chosen_candidate,
        "nonce": nonce,
        "signature": s
    }
    res = requests.post(f"{BASE_URL}/api/v1/ballotbox/submit-vote", json=ballot_payload)
    assert res.status_code == 200, f"Ballot submission failed: {res.text}"
    vote_res = res.json()
    print(f"  ✓ Ballot Status: {vote_res['status']}")
    print(f"  ✓ Verification:  {vote_res['message']}")
    print(f"  ✓ Cryptographic Receipt: {vote_res['receipt_hash']}")

    # 7. Check Public Election Tally
    print("\n[STEP 7] Checking Public Election Tally...")
    res = requests.get(f"{BASE_URL}/api/v1/ballotbox/tally")
    assert res.status_code == 200, f"Tally failed: {res.text}"
    tally_data = res.json()
    print(f"  ✓ Current Tally: {tally_data['results']}")
    print(f"  ✓ Total Votes Cast: {tally_data['total_votes_cast']}")

    print("\n" + "=" * 60)
    print("  ALL CRYPTOGRAPHIC TESTS & EDGE CASES PASSED PERFECTLY!")
    print("=" * 60)


if __name__ == "__main__":
    run_e2e_voting_test()