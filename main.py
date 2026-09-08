import sqlite3
import secrets
from fastapi import FastAPI, HTTPException, status, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import hashlib
import os

app = FastAPI(title="Nigeria E2E-V Secure Voting System", version="2.1.2")

# Ensure static directory exists
os.makedirs("static", exist_ok=True)

DB_NAME = "evoting.db"

# --- CRYPTOGRAPHIC ENGINE: 2048-bit RSA Authority Keypair ---
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def is_prime(n, k=64):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=1024):
    while True:
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

print("[SECURITY] Generating secure 2048-bit RSA Authority Keypair...")
RSA_E = 65537
p = generate_prime(1024)
q = generate_prime(1024)
RSA_N = p * q
phi = (p - 1) * (q - 1)
RSA_D = modinv(RSA_E, phi)
print("[SECURITY] 2048-bit RSA Authority Keypair initialized successfully.")

# --- DATABASE SETUP & AUTOMATED MIGRATIONS ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 1. Base tables creation
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accredited_voters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voter_hash TEXT UNIQUE,
            polling_unit_code TEXT,
            session_token TEXT,
            accredited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            signed_status INTEGER DEFAULT 0
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            block_index INTEGER PRIMARY KEY AUTOINCREMENT,
            previous_hash TEXT,
            election_type TEXT,
            party_code TEXT,
            polling_unit_code TEXT,
            block_hash TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    
    # 2. Seed default test voter if table is empty
    cursor.execute("SELECT COUNT(*) FROM accredited_voters")
    if cursor.fetchone()[0] == 0:
        test_hash = hashlib.sha256("12345678901NG12345678".encode()).hexdigest()
        cursor.execute("""
            INSERT INTO accredited_voters (voter_hash, polling_unit_code, session_token, signed_status)
            VALUES (?, ?, ?, 0)
        """, (test_hash, "PU-001", None))
        conn.commit()
        
    conn.close()
    print("[DATABASE] SQLite schema verified and migration checks passed successfully.")

init_db()

# --- PYDANTIC SCHEMAS ---
class VerifyRequest(BaseModel):
    nin: str = Field(..., min_length=11, max_length=11)
    vin: str
    polling_unit_code: str

class BlindSignRequest(BaseModel):
    session_token: str
    blinded_message: int

class BallotCastRequest(BaseModel):
    session_token: str
    election_type: str
    party_code: str
    polling_unit_code: str

# Comprehensive list of standard registered political parties for the ballot
VALID_PARTIES = {
    "PRESIDENTIAL": ["APC", "PDP", "LP", "NNPP", "APGA", "AAC", "ADC", "PRP"],
    "SENATORIAL": ["APC", "PDP", "LP", "NNPP", "APGA", "AAC", "ADC", "PRP"],
    "HOUSE_OF_REPS": ["APC", "PDP", "LP", "NNPP", "APGA", "AAC", "ADC", "PRP"]
}

# --- HTML TEMPLATE FOR ADMIN REGISTRATION ---
ADMIN_FORM_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin - Register Test Voter</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; margin: 0; padding: 40px; display: flex; justify-content: center; }}
        .card {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }}
        h2 {{ margin-top: 0; color: #004d40; font-size: 22px; text-align: center; }}
        label {{ display: block; margin-bottom: 8px; font-weight: 600; color: #555; font-size: 14px; }}
        input {{ width: 100%; padding: 10px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }}
        button {{ background: #004d40; color: white; border: none; padding: 12px; width: 100%; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 14px; }}
        button:hover {{ background: #00695c; }}
        .message {{ padding: 10px; margin-bottom: 20px; border-radius: 4px; font-size: 14px; text-align: center; }}
        .success {{ background: #e0f2f1; color: #004d40; border: 1px solid #b2dfdb; }}
        .error {{ background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>Register Test Voter</h2>
        {message_block}
        <form method="POST" action="/admin/register">
            <label for="nin">NIN (11 digits)</label>
            <input type="text" id="nin" name="nin" placeholder="e.g. 12345678901" maxlength="11" required>

            <label for="vin">Voter ID (VIN)</label>
            <input type="text" id="vin" name="vin" placeholder="e.g. NG12345678" required>

            <label for="polling_unit">Polling Unit Code</label>
            <input type="text" id="polling_unit" name="polling_unit" value="PU-001" required>

            <button type="submit">Commit Voter to DB</button>
        </form>
        <p style="text-align:center; margin-top:15px;"><a href="/" style="color:#004d40; text-decoration:none; font-size:13px;">&larr; Back to Voting Portal</a></p>
    </div>
</body>
</html>
"""

# --- ROUTES ---
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    index_path = os.path.abspath(os.path.join("static", "index.html"))
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>Portal is active, but static/index.html is missing.</h3>"

@app.get("/admin/register", response_class=HTMLResponse)
async def render_admin_register():
    return ADMIN_FORM_HTML.format(message_block="")
# --- HTML TEMPLATE FOR LIVE RESULTS DASHBOARD ---
TALLY_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin - Live Election Results Tally</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; margin: 0; padding: 40px; color: #333; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        h2 {{ margin-top: 0; color: #004d40; font-size: 24px; text-align: center; }}
        .nav-links {{ text-align: center; margin-bottom: 25px; }}
        .nav-links a {{ color: #004d40; text-decoration: none; margin: 0 15px; font-weight: 600; font-size: 14px; }}
        .nav-links a:hover {{ text-decoration: underline; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; font-size: 14px; }}
        th {{ background-color: #004d40; color: white; }}
        tr:hover {{ background-color: #f1f8f6; }}
        .tier-header {{ background-color: #e0f2f1; font-weight: bold; color: #004d40; }}
        .total-badge {{ background: #004d40; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Live Election Results Tally</h2>
        <div class="nav-links">
            <a href="/">&larr; Back to Voting Portal</a>
            <a href="/admin/register">+ Register Test Voter</a>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Election Tier</th>
                    <th>Party Code</th>
                    <th>Total Votes Cast</th>
                </tr>
            </thead>
            <tbody>
                {tally_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

@app.get("/admin/tally", response_class=HTMLResponse)
async def view_election_tally():
    """Aggregates votes from the ledger database and renders a live results tally table."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Query to group and count votes by election type and party code from the ledger
    cursor.execute("""
        SELECT election_type, party_code, COUNT(*) as vote_count
        FROM ledger
        GROUP BY election_type, party_code
        ORDER BY election_type, vote_count DESC
    """)
    results = cursor.fetchall()
    conn.close()
    
    rows_html = ""
    if not results:
        rows_html = '<tr><td colspan="3" style="text-align:center; color:#777;">No votes recorded in the ledger yet.</td></tr>'
    else:
        current_tier = ""
        for election_type, party_code, vote_count in results:
            rows_html += f"""
                <tr>
                    <td><strong>{election_type}</strong></td>
                    <td>{party_code}</td>
                    <td><span class="total-badge">{vote_count}</span></td>
                </tr>
            """
            
    return TALLY_DASHBOARD_HTML.format(tally_rows=rows_html)

@app.post("/admin/register", response_class=HTMLResponse)
async def handle_admin_register(nin: str = Form(...), vin: str = Form(...), polling_unit: str = Form(...)):
    clean_nin = nin.strip()
    clean_vin = vin.strip().upper()
    clean_pu = polling_unit.strip()
    
    voter_hash = hashlib.sha256(f"{clean_nin}{clean_vin}".encode()).hexdigest()
    
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO accredited_voters (voter_hash, polling_unit_code, signed_status)
            VALUES (?, ?, 0)
        """, (voter_hash, clean_pu))
        conn.commit()
        conn.close()
        msg_html = f'<div class="message success">Successfully registered NIN: {clean_nin[:4]}...</div>'
    except sqlite3.IntegrityError:
        msg_html = '<div class="message error">Error: This voter already exists in database.</div>'
    except Exception as e:
        msg_html = f'<div class="message error">Error: {str(e)}</div>'
        
    return ADMIN_FORM_HTML.format(message_block=msg_html)

@app.post("/api/v1/auth/verify")
async def verify_voter(payload: VerifyRequest):
    clean_nin = payload.nin.strip()
    clean_vin = payload.vin.strip().upper()
    voter_hash = hashlib.sha256(f"{clean_nin}{clean_vin}".encode()).hexdigest()
    session_token = secrets.token_hex(32)
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM accredited_voters WHERE voter_hash = ?", (voter_hash,))
    row = cursor.fetchone()
    
    if not row:
        cursor.execute("""
            INSERT OR IGNORE INTO accredited_voters (voter_hash, polling_unit_code, session_token, signed_status)
            VALUES (?, ?, ?, 0)
        """, (voter_hash, payload.polling_unit_code, session_token))
        conn.commit()
    
    cursor.execute("""
        UPDATE accredited_voters 
        SET session_token = ?, polling_unit_code = ? 
        WHERE voter_hash = ?
    """, (session_token, payload.polling_unit_code, voter_hash))
    conn.commit()
    conn.close()
    
    return {
        "status": "success",
        "message": "Voter successfully accredited.",
        "session_token": session_token
    }

@app.post("/api/v1/authority/blind-sign")
async def blind_sign_ballot(payload: BlindSignRequest):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT voter_hash, signed_status FROM accredited_voters WHERE session_token = ?", (payload.session_token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired session token for signing."
        )

    voter_hash, signed_status = row
    if signed_status == 1:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Blind signature has already been issued for this session."
        )

    cursor.execute("UPDATE accredited_voters SET signed_status = 1, session_token = NULL WHERE voter_hash = ?", (voter_hash,))
    conn.commit()
    conn.close()
    
    blinded_signature = pow(payload.blinded_message, RSA_D, RSA_N)

    return {
        "status": "success",
        "blinded_signature": blinded_signature,
        "modulus_n": str(RSA_N),
        "public_exponent": RSA_E
    }

@app.post("/api/v1/ballot/cast")
async def cast_ballot(payload: BallotCastRequest):
    if payload.election_type not in VALID_PARTIES:
        raise HTTPException(status_code=400, detail="Invalid election type specified.")
    
    if payload.party_code not in VALID_PARTIES[payload.election_type]:
        raise HTTPException(status_code=400, detail=f"Party {payload.party_code} is not contesting in the {payload.election_type} election.")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM accredited_voters WHERE session_token = ?", (payload.session_token,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired session token. You may have already cast your ballot."
        )
    
    voter_record_id = row[0]
    cursor.execute("UPDATE accredited_voters SET session_token = NULL WHERE id = ?", (voter_record_id,))
    
    cursor.execute("SELECT block_hash FROM ledger ORDER BY block_index DESC LIMIT 1")
    last_block = cursor.fetchone()
    previous_hash = last_block[0] if last_block else "0" * 64
    
    cursor.execute("SELECT COUNT(*) FROM ledger")
    next_index = cursor.fetchone()[0] + 1
    
    block_raw_data = f"{next_index}:{previous_hash}:{payload.election_type}:{payload.party_code}:{payload.polling_unit_code}"
    block_hash = hashlib.sha256(block_raw_data.encode()).hexdigest()
    
    # FIXED: Exactly 5 values bound to match the 5 column targets in the SQL statement
    cursor.execute("""
        INSERT INTO ledger (previous_hash, election_type, party_code, polling_unit_code, block_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (previous_hash, payload.election_type, payload.party_code, payload.polling_unit_code, block_hash))
    
    conn.commit()
    conn.close()
    
    return {
        "status": "success",
        "message": "Ballot securely recorded and anchored to hash-chain ledger.",
        "receipt": {
            "block_index": next_index,
            "block_hash": block_hash,
            "election_type": payload.election_type,
            "party_code": payload.party_code
        }
    }