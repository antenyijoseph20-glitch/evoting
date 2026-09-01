import os
import time
import hashlib
import json
from Crypto.Util import number

# =====================================================================
# 1. FULL DOMAIN HASH (FDH) PRIMITIVE
# =====================================================================

def full_domain_hash(message: bytes, modulus_n: int) -> int:
    """
    FDH expands a variable-length message digest into an integer uniformly 
    distributed in Z_n* (0 < integer < modulus_n) using SHA-256 counter-expansion.
    This prevents RSA signature malleability and multiplicative attacks.
    """
    target_bit_len = modulus_n.bit_length()
    target_byte_len = (target_bit_len + 7) // 8
    
    expanded_digest = b""
    counter = 0
    
    while len(expanded_digest) < target_byte_len:
        h = hashlib.sha256()
        h.update(counter.to_bytes(4, byteorder='big'))
        h.update(message)
        expanded_digest += h.digest()
        counter += 1

    # Truncate and convert big-endian byte array to big integer modulo n
    raw_int = int.from_bytes(expanded_digest[:target_byte_len], byteorder='big')
    fdh_val = raw_int % modulus_n
    
    # Guarantee coprime candidate in Z_n*
    if fdh_val == 0:
        return 1
    return fdh_val


# =====================================================================
# 2. ELECTION AUTHORITY (SIGNER & CREDENTIAL ISSUER)
# =====================================================================

class ElectionAuthority:
    """
    Holds the Private Blind-Signing RSA Key.
    Verifies voter eligibility, signs BLINDED messages (m'), and records token issuance.
    """
    def __init__(self, key_size: int = 2048):
        # Generate prime factors p, q and RSA key pair (e, d, n)
        self.p = number.getPrime(key_size // 2, os.urandom)
        self.q = number.getPrime(key_size // 2, os.urandom)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        
        self.e = 65537
        self.d = number.inverse(self.e, self.phi)
        
        # Double-Voting Prevention: Tracks voters who have received a blind signature token
        self.issued_tokens_registry = set()

    @property
    def public_key(self) -> tuple[int, int]:
        """Returns Public Key (e, n)."""
        return (self.e, self.n)

    def issue_blind_signature(self, session_token: str, blinded_message: int) -> int | None:
        """
        Signs the blinded message m' using private key d: s' = (m')^d mod n.
        Enforces strict single-issuance per session token.
        """
        # Security Guard 1: Check for double-issuance attempt
        if session_token in self.issued_tokens_registry:
            print(f"[SECURITY ALERT] Token Issuance Blocked: Session '{session_token[:12]}...' already received a blind token.")
            return None

        # Sign blinded payload without learning underlying choice m
        blind_signature = pow(blinded_message, self.d, self.n)
        
        # Atomic Lock: Register token as issued
        self.issued_tokens_registry.add(session_token)
        print(f"[AUTHORITY] Blind signature s' successfully issued for session token '{session_token[:12]}...'")
        
        return blind_signature


# =====================================================================
# 3. VOTER CLIENT MODULE (BLINDING & UNBLINDING)
# =====================================================================

class VoterClient:
    """
    Executes client-side blinding, vote payload formatting, and unblinding s' -> s.
    The Election Authority never sees the candidate choice or the unblinding factor r.
    """
    def __init__(self, candidate_choice: str, e_auth_public_key: tuple[int, int]):
        self.choice = candidate_choice
        self.e, self.n = e_auth_public_key
        
        # High-entropy random nonce guarantees vote uniqueness and prevents dictionary attacks
        self.nonce = os.urandom(16).hex()
        
        # Formulate Canonical Vote Payload
        self.raw_ballot = json.dumps({
            "candidate": self.choice,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        
        # Step A: Apply Full Domain Hash (FDH)
        self.m = full_domain_hash(self.raw_ballot, self.n)
        
        # Step B: Pick random secret factor r in Z_n*
        while True:
            self.r = number.getRandomRange(2, self.n - 1, os.urandom)
            if number.GCD(self.r, self.n) == 1:
                break
                
        # Step C: Compute Blinded Message m' = (m * r^e) mod n
        r_pow_e = pow(self.r, self.e, self.n)
        self.m_prime = (self.m * r_pow_e) % self.n

    def get_blinded_payload(self) -> int:
        return self.m_prime

    def unblind_signature(self, blind_signature_s_prime: int) -> int:
        """
        Removes blinding factor r: s = (s' * r^-1) mod n.
        Returns the unblinded signature s valid for (m, e, n).
        """
        r_inv = number.inverse(self.r, self.n)
        unblinded_s = (blind_signature_s_prime * r_inv) % self.n
        return unblinded_s


# =====================================================================
# 4. BALLOT BOX & TALLY PORTAL (VERIFIER & DOUBLE-VOTE PREVENTION)
# =====================================================================

class BallotBox:
    """
    Anonymously receives (raw_ballot, signature_s).
    Validates cryptographic authenticity against Public Key (e, n)
    and checks the nonce registry to prevent ballot replay / double-voting.
    """
    def __init__(self, e_auth_public_key: tuple[int, int]):
        self.e, self.n = e_auth_public_key
        self.candidates_tally = {"APC": 0, "LP": 0, "PDP": 0, "NNPP": 0}
        
        # Double-Spend Prevention: Tracks submitted ballot nonces
        self.seen_nonces = set()
        
        # Public Audit Ledger (IReV)
        self.audit_ledger = []

    def cast_ballot(self, raw_ballot: bytes, signature_s: int) -> tuple[bool, str]:
        """
        Step 1: Recompute FDH(raw_ballot) -> m.
        Step 2: Verify signature s^e ≡ m (mod n).
        Step 3: Check nonce to prevent replay double-voting.
        """
        try:
            ballot_data = json.loads(raw_ballot.decode())
            candidate = ballot_data.get("candidate")
            nonce = ballot_data.get("nonce")
        except Exception:
            return False, "Ballot Rejection: Malformed JSON payload."

        # Security Check 1: Nonce Uniqueness (Replay / Double Vote Check)
        if nonce in self.seen_nonces:
            return False, "Ballot Rejection: REPLAY DETECTED! This ballot nonce has already been cast."

        # Security Check 2: Verify Cryptographic Signature s^e mod n == m
        recomputed_m = full_domain_hash(raw_ballot, self.n)
        valid_m = pow(signature_s, self.e, self.n)

        if valid_m != recomputed_m:
            return False, "Ballot Rejection: Invalid Cryptographic Signature! Signature failed RSA public key verification."

        # Valid Vote: Record and lock nonce
        self.seen_nonces.add(nonce)
        self.candidates_tally[candidate] += 1

        # Audit Entry
        audit_entry = {
            "timestamp": time.time(),
            "candidate": candidate,
            "ballot_hash": hashlib.sha256(raw_ballot).hexdigest(),
            "signature_hash": hashlib.sha256(str(signature_s).encode()).hexdigest()
        }
        self.audit_ledger.append(audit_entry)

        return True, "Ballot Successfully Verified & Tallied Anonymously."


# =====================================================================
# DEMONSTRATION & TEST RUNNER
# =====================================================================

if __name__ == "__main__":
    print("=== INITIALIZING MODULE 2: CRYPTOGRAPHIC VOTING ENGINE ===")
    
    # 1. Initialize Authority & Public Ballot Box
    authority = ElectionAuthority(key_size=2048)
    ballot_box = BallotBox(authority.public_key)
    
    # Simulated Session Token generated during Module 1 Auth
    voter_session_token = "sess_9012345678901234567_token_alpha"

    print("\n--- STEP 1: VOTER CLIENT PREPARES VOTE & BLINDS IT ---")
    # Voter selects candidate "LP"
    voter = VoterClient(candidate_choice="LP", e_auth_public_key=authority.public_key)
    blinded_payload = voter.get_blinded_payload()
    print(f"Candidate Choice: 'LP' | Nonce: {voter.nonce}")
    print(f"Blinded Message (m'): {str(blinded_payload)[:30]}... [ID/Choice Hidden]")

    print("\n--- STEP 2: AUTHORITY SIGNS BLINDED PAYLOAD ---")
    s_prime = authority.issue_blind_signature(voter_session_token, blinded_payload)
    print(f"Blinded Signature (s'): {str(s_prime)[:30]}...")

    print("\n--- STEP 3: VOTER UNBLINDS SIGNATURE LOCALLY ---")
    unblinded_s = voter.unblind_signature(s_prime)
    print(f"Unblinded Signature (s): {str(unblinded_s)[:30]}...")

    print("\n--- STEP 4: SUBMIT ANONYMOUS VOTE TO BALLOT BOX ---")
    # Vote is submitted anonymously with raw_ballot and unblinded_s
    success, msg = ballot_box.cast_ballot(voter.raw_ballot, unblinded_s)
    print(f"Ballot Box Response: {msg}")

    print("\n--- STEP 5: SECURITY TEST - ATTEMPT DOUBLE VOTE ---")
    print("A. Attempting duplicate token request from Authority:")
    authority.issue_blind_signature(voter_session_token, blinded_payload)

    print("\nB. Attempting replay attack with same ballot on Ballot Box:")
    replay_success, replay_msg = ballot_box.cast_ballot(voter.raw_ballot, unblinded_s)
    print(f"Ballot Box Replay Response: {replay_msg}")

    print("\n--- STEP 6: PUBLIC TALLY STATUS ---")
    print("Tally Standings:", json.dumps(ballot_box.candidates_tally, indent=2))