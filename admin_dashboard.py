import time
import requests
import sys

BASE_URL = "http://localhost:8000/api/v1"

def clear_screen():
    print("\033[H\033[J", end="")

def render_dashboard():
    print("=" * 70)
    print("        🇳🇬 NIGERIA E2E-V LIVE ADMINISTRATIVE DASHBOARD")
    print("=" * 70)
    print("Polling server metrics... Press Ctrl+C to exit.\n")

    try:
        while True:
            # Fetch Health & Analytics
            health_res = requests.get(f"{BASE_URL}/admin/health", timeout=3)
            analytics_res = requests.get(f"{BASE_URL}/admin/analytics", timeout=3)
            audit_res = requests.get(f"{BASE_URL}/tally/audit", timeout=3)

            if health_res.status_code != 200 or analytics_res.status_code != 200:
                print("⚠️ [WARNING] Unable to reach backend server. Is it running?")
                time.sleep(3)
                continue

            health = health_res.json()
            analytics = analytics_res.json()
            audit = audit_res.json()

            clear_screen()
            print("=" * 70)
            print("        🇳🇬 NIGERIA E2E-V LIVE ADMINISTRATIVE DASHBOARD")
            print("=" * 70)
            print(f" 🟢 System Status      : {health['status']} (DB: {health['database_status']})")
            print(f" 🕒 Server Time        : {health['server_time']}")
            print(f" 🔗 Ledger Height      : {health['ledger_height']} Blocks")
            print(f" 🛡️  Chain Integrity    : {'PASSED (100% Secure)' if audit['integrity_verified'] else 'FAILED ⚠️'}")
            print(f" 📦 Latest Block Hash  : {health['latest_block_hash'][:24]}...")
            print("-" * 70)
            print(f" 👥 Registered Voters  : {health['total_registered_voters']}")
            print(f" 🗳️  Total Votes Cast   : {analytics['total_votes']}")
            print("=" * 70)
            print(" LIVE VOTE DISTRIBUTION & TALLY:")
            print("-" * 70)

            tally = analytics["tally"]
            percentages = analytics["vote_percentages"]

            if not tally:
                print(" (No votes recorded yet)")
            else:
                for candidate, count in tally.items():
                    pct = percentages.get(candidate, 0.0)
                    bar_length = int(pct // 2)  # 50 chars max for 100%
                    bar = "█" * bar_length + "-" * (50 - bar_length)
                    print(f" [{candidate.ljust(5)}] {count:3d} votes |{bar}| {pct:5.2f}%")

            print("-" * 70)
            print(f" ⏱️  Last Vote Cast At  : {analytics['last_vote_timestamp'] or 'N/A'}")
            print("=" * 70)
            print(" [Refreshing every 2 seconds... Press Ctrl+C to stop]")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n\nExiting Administrative Dashboard. Goodbye!")
        sys.exit(0)
    except requests.exceptions.ConnectionError:
        print("\n❌ Connection error: Could not connect to FastAPI server at http://localhost:8000")
        sys.exit(1)

if __name__ == "__main__":
    render_dashboard()