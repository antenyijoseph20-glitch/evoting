#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define cleanup handler for exit/interrupt signals
cleanup() {
    echo ""
    echo "======================================================================"
    echo " CLEANING UP PROCESSES"
    echo "======================================================================"
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Stopping e-voting server process (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    pkill -f "main.py" 2>/dev/null || true
    echo "Cleanup complete."
}

# Trap SIGINT, SIGTERM, and EXIT signals to run cleanup automatically
trap cleanup EXIT INT TERM

echo "======================================================================"
echo " INITIALIZING E-VOTING TEST RUNNER"
echo "======================================================================"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    echo "ERROR: Virtual environment not found in venv/ or .venv/"
    exit 1
fi

# 1. Clear database files for a clean test run
echo "[1/4] Purging existing database artifacts..."
rm -f evoting.db evoting.db-wal evoting.db-shm

# 2. Kill any stale server instances
echo "[2/4] Terminating existing server instances..."
pkill -f "main.py" 2>/dev/null || true

# 3. Start the server in background using activated venv python and direct output to server.log
echo "[3/4] Launching e-voting core server..."
python main.py > server.log 2>&1 &
SERVER_PID=$!

echo "Server process launched with PID $SERVER_PID. Waiting for table initialization..."

# Wait until the server endpoints are fully live and initialized
MAX_RETRIES=20
RETRY_COUNT=0
UNTIL_READY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/docs || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        # Check that table schema initialization completes
        TALLY_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/api/v1/tally/results || echo "000")
        if [ "$TALLY_CODE" = "200" ]; then
            UNTIL_READY=true
            break
        fi
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 0.5
done

if [ "$UNTIL_READY" = false ]; then
    echo "ERROR: Server failed to start or initialize tables within timeout period."
    echo "Check server.log for details:"
    cat server.log
    exit 1
fi

echo "Server is live and database tables are fully initialized!"
echo ""

# 4. Execute test suites sequentially
echo "[4/4] Executing test suites..."
echo "======================================================================"

python test_security_guards.py
python test_receipt_verification.py
python test_tally_and_audit.py
python test_hash_chain_tamper.py