"""
test_security_guards.py - Security, Double-Voting & Tamper Resistance Test Suite
"""
import requests
import hashlib
import secrets
from math import gcd

BASE_URL = "http://127.0.0.1:8000"


def modinv(a: int, m: int) -> int:
    """Computes modular multiplicative inverse using Extended Euclidean Algorithm."""
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


def obtain_valid_session_and_signature(candidate="LP", vin="9012345678901234567", nin="12345678901"):
    """Helper utility to run a clean auth + blind-signing protocol pass."""
    # 1. Authenticate
    auth_res = requests.post(
        f"{BASE_URL}/api/v1/auth/verify",
        json={"vin": vin, "nin": nin}
    )
    if auth_res.status_code != 200:
        return None, None, None, auth_res

    session_token = auth_res.json()["session_token"]

    # 2. Blind Hash
    e, n = 17, 3233
    nonce = secrets.token_hex(16)
    raw_bytes = f"{candidate}:{nonce}".encode("utf-8")
    m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % n

    r = 37
    while gcd(r, n) != 1:
        r += 2

    m_prime = (m * pow(r, e, n)) % n

    # 3. Blind Sign
    sign_res = requests.post(
        f"{BASE_URL}/api/v1/authority/blind-sign",
        json={"session_token": session_token, "blinded_message": m_prime}
    )
    if sign_res.status_code != 200:
        return session_token, None, None, sign_res

    s_prime = sign_res.json()["blinded_signature"]

    # 4. Unblind
    r_inv = modinv(r, n)
    s = (s_prime * r_inv) % n

    return session_token, nonce, s, None


def run_security_stress_tests():
    print("=" * 70)
    print("  E-VOTING SYSTEM SECURITY & ANTI-TAMPER TEST SUITE")
    print("=" * 70)

    # -------------------------------------------------------------------
    # TEST 1: Session Token Re-use (Attempting Double Blind Signing)
    # -------------------------------------------------------------------
    print("\n[TEST 1] Guarding Against Session Token Re-use...")
    session_token, nonce, signature, error = obtain_valid_session_and_signature(
        vin="9012345678901234567", 
        nin="12345678901"
    )
    assert session_token is not None, f"Prerequisite failed: {error.text if error else 'Unknown error'}"

    # Attempt to request a SECOND blind signature using the SAME session token
    re_sign_payload = {
        "session_token": session_token,
        "blinded_message": 1234
    }
    re_sign_res = requests.post(f"{BASE_URL}/api/v1/authority/blind-sign", json=re_sign_payload)
    
    if re_sign_res.status_code in [400, 401, 403]:
        print(f"  ✓ PASSED: Re-using session token for blind signature was rejected ({re_sign_res.status_code}).")
        print(f"    Server Response: {re_sign_res.json().get('detail')}")
    else:
        print(f"  ❌ FAILED: Server accepted reused session token! Status: {re_sign_res.status_code}")

    # -------------------------------------------------------------------
    # TEST 2: Voter Double-Authentication (INEC Registry Double Voting)
    # -------------------------------------------------------------------
    print("\n[TEST 2] Guarding Against Re-authentication After Blind Signing...")
    re_auth_res = requests.post(
        f"{BASE_URL}/api/v1/auth/verify",
        json={"vin": "9012345678901234567", "nin": "12345678901"}
    )
    if re_auth_res.status_code in [400, 401, 403]:
        print(f"  ✓ PASSED: INEC Registry blocked voter re-authentication ({re_auth_res.status_code}).")
        print(f"    Server Response: {re_auth_res.json().get('detail')}")
    elif re_auth_res.status_code == 200:
        second_token = re_auth_res.json()["session_token"]
        test_sign = requests.post(
            f"{BASE_URL}/api/v1/authority/blind-sign",
            json={"session_token": second_token, "blinded_message": 999}
        )
        if test_sign.status_code in [400, 401, 403]:
            print(f"  ✓ PASSED: Re-authenticated session blocked from secondary signature ({test_sign.status_code}).")
            print(f"    Server Response: {test_sign.json().get('detail')}")
        else:
            print(f"  ❌ FAILED: Second session granted signature privileges! Status: {test_sign.status_code}")

    # -------------------------------------------------------------------
    # TEST 3: Payload Tampering (MITM Candidate Modification)
    # -------------------------------------------------------------------
    print("\n[TEST 3] Guarding Against Payload Tampering (Modifying Choice)...")
    tampered_ballot = {
        "candidate": "APC",  # Altered choice
        "nonce": nonce,
        "signature": signature
    }
    tamper_res = requests.post(f"{BASE_URL}/api/v1/ballotbox/submit-vote", json=tampered_ballot)
    
    if tamper_res.status_code == 400:
        print("  ✓ PASSED: Tampered payload rejected! Signature invalid for altered candidate choice.")
        print(f"    Server Response (400): {tamper_res.json().get('detail')}")
    else:
        print(f"  ❌ FAILED: Tampered ballot accepted! Status: {tamper_res.status_code}")

    # -------------------------------------------------------------------
    # TEST 4: Valid Ballot Cast & Double-Submission Prevention
    # -------------------------------------------------------------------
    print("\n[TEST 4] Casting Valid Ballot & Testing Signature Replay Attack...")
    valid_ballot = {
        "candidate": "LP",
        "nonce": nonce,
        "signature": signature
    }
    valid_res = requests.post(f"{BASE_URL}/api/v1/ballotbox/submit-vote", json=valid_ballot)
    
    if valid_res.status_code == 200:
        print("  ✓ Initial Ballot Cast Successfully.")
        
        # Replay Attack
        replay_res = requests.post(f"{BASE_URL}/api/v1/ballotbox/submit-vote", json=valid_ballot)
        if replay_res.status_code == 400:
            print("  ✓ PASSED: Replay Attack Blocked! Duplicate signature/nonce rejected.")
            print(f"    Server Response (400): {replay_res.json().get('detail')}")
        else:
            print(f"  ❌ FAILED: Replay attack succeeded! Status: {replay_res.status_code}")
    else:
        print(f"  ❌ Initial ballot submission failed: {valid_res.text}")

    # -------------------------------------------------------------------
    # TEST 5: Forged/Random Signature Injection
    # -------------------------------------------------------------------
    print("\n[TEST 5] Guarding Against Forged / Unsigned Signature Injection...")
    forged_ballot = {
        "candidate": "PDP",
        "nonce": secrets.token_hex(16),
        "signature": 9999
    }
    forged_res = requests.post(f"{BASE_URL}/api/v1/ballotbox/submit-vote", json=forged_ballot)
    
    if forged_res.status_code == 400:
        print("  ✓ PASSED: Forged signature rejected by cryptographic verifier.")
        print(f"    Server Response (400): {forged_res.json().get('detail')}")
    else:
        print(f"  ❌ FAILED: Forged signature accepted! Status: {forged_res.status_code}")

    # -------------------------------------------------------------------
    # TEST 6: Expired / Unknown Session Token Submission
    # -------------------------------------------------------------------
    print("\n[TEST 6] Guarding Against Non-Existent or Expired Session Tokens...")
    fake_sign_res = requests.post(
        f"{BASE_URL}/api/v1/authority/blind-sign",
        json={"session_token": "sess_invalid_fake_token_12345", "blinded_message": 100}
    )
    if fake_sign_res.status_code in [400, 401, 403, 404]:
        print(f"  ✓ PASSED: Invalid session token rejected ({fake_sign_res.status_code}).")
        print(f"    Server Response: {fake_sign_res.json().get('detail')}")
    else:
        print(f"  ❌ FAILED: Server responded with status: {fake_sign_res.status_code}")

    print("\n" + "=" * 70)
    print("  SECURITY & ANTI-TAMPER TEST SUITE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    run_security_stress_tests()