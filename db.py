"""SQLite access. Every write path uses BEGIN IMMEDIATE so check-then-write is atomic."""
import sqlite3
import contextlib
from config import DB_PATH, ELECTION_PARTIES

SCHEMA = """
CREATE TABLE IF NOT EXISTS voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_hash TEXT UNIQUE NOT NULL,
    polling_unit_code TEXT NOT NULL,
    phone_number TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    voter_id INTEGER NOT NULL REFERENCES voters(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    otp_expires_at TEXT NOT NULL,
    otp_attempts INTEGER NOT NULL DEFAULT 0,
    otp_verified INTEGER NOT NULL DEFAULT 0,
    face_attempts INTEGER NOT NULL DEFAULT 0,
    face_verified INTEGER NOT NULL DEFAULT 0
);
-- No timestamp and no rowid: the insertion order of votes cannot be matched to the ledger.
CREATE TABLE IF NOT EXISTS votes_cast (
    voter_id INTEGER NOT NULL,
    election_type TEXT NOT NULL,
    PRIMARY KEY (voter_id, election_type)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ledger (
    block_index INTEGER PRIMARY KEY AUTOINCREMENT,
    previous_hash TEXT NOT NULL,
    election_type TEXT NOT NULL,
    party_code TEXT NOT NULL,
    polling_unit_code TEXT NOT NULL,
    block_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS elections (
    election_type TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','OPEN','CLOSED'))
);
CREATE TABLE IF NOT EXISTS admins (
    username TEXT PRIMARY KEY,
    pw_salt BLOB NOT NULL,
    pw_hash BLOB NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ADMIN','REGISTRAR','AUDITOR'))
);
CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES admins(username),
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS officers (
    officer_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PRESIDING_OFFICER','PARTY_AGENT')),
    polling_unit_code TEXT NOT NULL,
    party_code TEXT,
    public_key TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS result_sheets (
    block_index INTEGER PRIMARY KEY AUTOINCREMENT,
    election_type TEXT NOT NULL,
    polling_unit_code TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    officer_id TEXT NOT NULL REFERENCES officers(officer_id),
    signature TEXT NOT NULL,
    flags TEXT NOT NULL DEFAULT '',
    previous_hash TEXT NOT NULL,
    block_hash TEXT NOT NULL,
    UNIQUE (election_type, polling_unit_code)
);
CREATE TABLE IF NOT EXISTS countersignatures (
    block_index INTEGER NOT NULL REFERENCES result_sheets(block_index),
    officer_id TEXT NOT NULL REFERENCES officers(officer_id),
    signature TEXT NOT NULL,
    PRIMARY KEY (block_index, officer_id)
);
CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_size INTEGER NOT NULL,
    root TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextlib.contextmanager
def tx():
    """Write transaction. Any exception (including HTTPException) rolls back."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


@contextlib.contextmanager
def read():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        for etype in ELECTION_PARTIES:
            conn.execute("INSERT OR IGNORE INTO elections (election_type) VALUES (?)", (etype,))
    finally:
        conn.close()
