import json
import requests

AUDIT_URL = "http://127.0.0.1:8000/api/v1/tally/audit"


def audit_ledger():
    print(f"Connecting to audit endpoint: {AUDIT_URL}...\n")
    try:
        response = requests.get(AUDIT_URL)
        response.raise_for_status()

        audit_data = response.json()

        print("==================================================")
        print("          🇳🇬 E-VOTING LEDGER AUDIT REPORT         ")
        print("==================================================")
        print(
            f"🛡️ Chain Integrity Status : {audit_data.get('status', 'UNKNOWN')}"
        )
        print(f"🔗 Total Blocks Audited   : {audit_data.get('ledger_height', 0)}")
        print(
            f"📦 Final Block Hash       : {audit_data.get('latest_hash', 'N/A')}"
        )
        print("--------------------------------------------------")
        print("Detailed Audit payload:")
        print(json.dumps(audit_data, indent=4))
        print("==================================================")

    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to connect to backend audit endpoint: {e}")


if __name__ == "__main__":
    audit_ledger()