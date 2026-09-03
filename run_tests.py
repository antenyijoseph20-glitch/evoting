import sys
import os
import subprocess
import time
import urllib.request
import urllib.error

# --- INTELLIGENT VENV DISCOVERY ---
def find_working_python():
    # 1. Check if current interpreter already works
    try:
        import fastapi
        import uvicorn
        return sys.executable
    except ImportError:
        pass

    # 2. Scan workspace for any directory containing bin/python or Scripts/python.exe
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        # Limit depth to avoid deep recursion
        if root.count(os.sep) - current_dir.count(os.sep) > 2:
            continue
        for d in dirs:
            py_path = os.path.join(root, d, "bin", "python")
            if not os.path.exists(py_path):
                py_path = os.path.join(root, d, "Scripts", "python.exe")
            
            if os.path.exists(py_path):
                # Test if this python has fastapi
                try:
                    res = subprocess.run([py_path, "-c", "import fastapi, uvicorn"], capture_output=True)
                    if res.returncode == 0:
                        return py_path
                except Exception:
                    pass
    return None

def ensure_virtual_environment():
    try:
        import fastapi
        import uvicorn
    except ImportError:
        print("🔍 Searching workspace for your virtual environment Python...")
        working_py = find_working_python()
        if working_py:
            print(f"🔄 [Auto-Discovery] Found working interpreter: {working_py}")
            os.execve(working_py, [working_py] + sys.argv, os.environ)
        else:
            print("❌ ERROR: Could not find any Python environment with 'fastapi' and 'uvicorn' installed.")
            print("Please ensure your virtual environment is created and dependencies are installed.")
            sys.exit(1)

ensure_virtual_environment()

DB_FILES = ["evoting.db", "evoting.db-wal", "evoting.db-shm"]
SERVER_URL = "http://127.0.0.1:8000"

def purge_database():
    print("[1/4] Purging existing database artifacts...")
    for db_file in DB_FILES:
        if os.path.exists(db_file):
            os.remove(db_file)
            print(f"  Removed: {db_file}")

def kill_stale_servers():
    print("[2/4] Terminating existing server instances...")
    try:
        subprocess.run(["pkill", "-f", "uvicorn main:app"], capture_output=True)
    except Exception:
        pass
    time.sleep(1)

def start_server():
    print("[3/4] Launching e-voting core server...")
    server_log = open("server.log", "w")
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=server_log,
        stderr=server_log
    )
    print(f"Server process launched with PID {process.pid}. Waiting for table initialization...")
    
    max_retries = 20
    for attempt in range(max_retries):
        try:
            req = urllib.request.urlopen(f"{SERVER_URL}/docs", timeout=1)
            if req.status == 200:
                tally_req = urllib.request.urlopen(f"{SERVER_URL}/api/v1/tally/results", timeout=1)
                if tally_req.status == 200:
                    print("Server is live and database tables are fully initialized!")
                    return process
        except Exception:
            pass
        time.sleep(0.5)
    
    process.terminate()
    print("ERROR: Server failed to start or initialize tables within timeout period.")
    if os.path.exists("server.log"):
        print("--- server.log ---")
        with open("server.log", "r") as log:
            print(log.read())
    sys.exit(1)

def run_test_suites():
    print("\n[4/4] Executing test suites...")
    print("=" * 70)
    
    test_scripts = [
        "test_security_guards.py",
        "test_receipt_verification.py",
        "test_tally_and_audit.py",
        "test_hash_chain_tamper.py"
    ]
    
    for script in test_scripts:
        print(f"\n▶ Running {script}...")
        result = subprocess.run([sys.executable, script])
        if result.returncode != 0:
            print(f"❌ Test suite {script} FAILED.")
            sys.exit(result.returncode)
        print(f"✔ {script} PASSED.")

if __name__ == "__main__":
    print("=" * 70)
    print(" INITIALIZING E-VOTING TEST RUNNER (AUTO-DISCOVER)")
    print("=" * 70)
    
    server_process = None
    try:
        purge_database()
        kill_stale_servers()
        server_process = start_server()
        run_test_suites()
        print("\n🎉 ALL E-VOTING TEST SUITES PASSED SUCCESSFULLY!")
    except KeyboardInterrupt:
        print("\nTest run interrupted by user.")
    finally:
        if server_process:
            print("\n======================================================================")
            print(" CLEANING UP PROCESSES")
            print("======================================================================")
            server_process.terminate()
            server_process.wait()
            print("Server stopped. Cleanup complete.")