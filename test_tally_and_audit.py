"""
test_tally_and_audit.py - State-aware Tally & Zero-Knowledge Audit Test Suite
"""

import hashlib
import requests

BASE_URL = "http://127.0.0.1:8000/api/v1"

# Cryptographic keys
E_PUB = 17
N_MOD = 3233
D_PRIV = 2753

def blind_and_sign(candidate: str, nonce: str) -> int:
    raw_bytes = f"{candidate}:{nonce}".encode("utf-8")
    m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % N_MOD
    r = 5
    m_prime = (m * pow(r, E_PUB, N_MOD)) % N_MOD
    s_prime = pow(m_prime, D_PRIV, N_MOD)
    
    def egcd(a, b):
        if a == 0: return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
    r_inv = egcd(r, N_MOD)[1] % N_MOD
    s = (s_prime * r_inv) % N_MOD
    return s

def run_tally_and_audit_tests():
    print("=" * 70)
    print("  E-VOTING SYSTEM TALLY & ZERO-KNOWLEDGE AUDIT TEST SUITE")
    print("=" * 70)

    # 1. Fetch initial baseline tally
    init_res = requests.get(f"{BASE_URL}/tally/results")
    assert init_res.status_code == 200
    baseline_tally = init_res.json()["tally"]
    baseline_total = init_res.json()["total_votes_cast"]
    
    print(f"\n[BASELINE] Initial Database Votes: {baseline_total} | {baseline_tally}")

    # 2. Cast sample ballots
    votes_to_cast = [
        ("LP", "audit_nonce_001"),
        ("LP", "audit_nonce_002"),
        ("APC", "audit_nonce_003"),
        ("PDP", "audit_nonce_004"),
        ("LP", "audit_nonce_005")
    ]

    print("\n[STEP 1] Casting Sample Ballots for Audit Pass...")
    for candidate, nonce in votes_to_cast:
        sig = blind_and_sign(candidate, nonce)
        res = requests.post(
            f"{BASE_URL}/ballotbox/submit-vote",
            json={"candidate": candidate, "nonce": nonce, "signature": sig}
        )
        assert res.status_code == 200, f"Failed to submit vote: {res.text}"
    print(f"  ✓ {len(votes_to_cast)} sample ballots successfully recorded.")

    # 3. Test Public Tally Endpoint relative to baseline
    print("\n[STEP 2] Querying Public Tally Endpoint...")
    tally_res = requests.get(f"{BASE_URL}/tally/results")
    assert tally_res.status_code == 200, f"Tally request failed: {tally_res.text}"
    tally_data = tally_res.json()
    
    print(f"  ✓ Total Votes Cast: {tally_data['total_votes_cast']}")
    print(f"  ✓ Breakdown: {tally_data['tally']}")
    
    # Relative assertions
    assert tally_data["total_votes_cast"] == baseline_total + len(votes_to_cast)
    assert tally_data["tally"].get("LP", 0) == baseline_tally.get("LP", 0) + 3
    assert tally_data["tally"].get("APC", 0) == baseline_tally.get("APC", 0) + 1
    assert tally_data["tally"].get("PDP", 0) == baseline_tally.get("PDP", 0) + 1

    # 4. Test Global Zero-Knowledge Audit Engine
    print("\n[STEP 3] Executing Zero-Knowledge Global Audit Pass...")
    audit_res = requests.get(f"{BASE_URL}/tally/audit")
    assert audit_res.status_code == 200, f"Audit request failed: {audit_res.text}"
    audit_data = audit_res.json()

    print(f"  ✓ Total Ballots Audited: {audit_data['total_ballots_audited']}")
    print(f"  ✓ Valid Signatures:     {audit_data['valid_ballots_count']}")
    print(f"  ✓ Invalid Signatures:   {audit_data['invalid_ballots_count']}")
    print(f"  ✓ Integrity Status:     {audit_data['integrity_verified']}")

    assert audit_data["invalid_ballots_count"] == 0
    assert audit_data["integrity_verified"] is True
    print("  ✓ PASSED: All ballots mathematically verified; zero tampered records found.")

    print("\n" + "=" * 70)
    print("  TALLY & ZERO-KNOWLEDGE AUDIT TEST SUITE COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    run_tally_and_audit_tests()