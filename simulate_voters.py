import concurrent.futures
import hashlib
import random
import time
import requests

BASE_URL = "http://127.0.0.1:8000/api/v1"
CANDIDATES = ["Candidate A", "Candidate B", "Candidate C"]

def simulate_voter(index):
    try:
        # 1. Generate unique 19-digit VIN and 11-digit NIN
        vin = f"{2000000000000000000 + index}"
        nin = f"{20000000000 + index}"
        
        # Authenticate / Register
        auth_resp = requests.post(f"{BASE_URL}/auth/verify", json={"vin": vin, "nin": nin})
        if auth_resp.status_code != 200:
            print(f"[-] Voter {index} auth failed: {auth_resp.text}")
            return False
        
        session_token = auth_resp.json()["session_token"]
        
        # Blind Sign Authority
        blind_resp = requests.post(f"{BASE_URL}/authority/blind-sign", json={
            "session_token": session_token,
            "blinded_message": 12345 + index
        })
        if blind_resp.status_code != 200:
            print(f"[-] Voter {index} blind sign failed: {blind_resp.text}")
            return False

        # Submit Vote
        candidate = random.choice(CANDIDATES)
        nonce = hashlib.sha256(f"voter_nonce_{index}_{time.time()}".encode()).hexdigest()
        
        # Compute signature matching the backend's RSA parameters (e=17, n=3233, d=2753)
        raw_bytes = f"{candidate}:{nonce}".encode("utf-8")
        m = int.from_bytes(hashlib.sha256(raw_bytes).digest(), byteorder="big") % 3233
        valid_signature = pow(m, 2753, 3233)

        vote_resp = requests.post(f"{BASE_URL}/ballotbox/submit-vote", json={
            "candidate": candidate,
            "nonce": nonce,
            "signature": valid_signature
        })
        
        if vote_resp.status_code == 200:
            print(f"[+] Voter {index:2d} successfully cast ballot for -> {candidate}")
            return True
        else:
            print(f"[-] Voter {index} vote submission failed: {vote_resp.text}")
            return False
            
    except Exception as e:
        print(f"[-] Error in voter {index}: {e}")
        return False

def run_simulation(total_voters=15, max_workers=5):
    print(f"🚀 Launching concurrent simulation: {total_voters} voters using {max_workers} worker threads...\n")
    start_time = time.time()
    
    success_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(simulate_voter, i) for i in range(total_voters)]
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                success_count += 1
                
    duration = time.time() - start_time
    print(f"\n✨ Simulation complete in {duration:.2f} seconds!")
    print(f"📊 Successfully recorded {success_count}/{total_voters} votes into the blockchain ledger.")

if __name__ == "__main__":
    run_simulation(total_voters=20, max_workers=5)