"""SQLite access. Every write path uses BEGIN IMMEDIATE so check-then-write is atomic."""
import os
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
-- Separate from sessions: a voter who keeps restarting still hits the hourly cap.
CREATE TABLE IF NOT EXISTS voter_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id INTEGER NOT NULL REFERENCES voters(id),
    created_at TEXT NOT NULL
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
    detail TEXT,
    prev_hash TEXT,
    entry_hash TEXT
);
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    height INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TEXT NOT NULL
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
    review_status TEXT NOT NULL DEFAULT 'PENDING',
    reviewed_by TEXT,
    reviewed_at TEXT,
    review_note TEXT,
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
CREATE TABLE IF NOT EXISTS ledger_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    height INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_block_hash ON ledger(block_hash);
CREATE INDEX IF NOT EXISTS idx_result_sheets_review ON result_sheets(election_type, review_status);
CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit(ts);
CREATE INDEX IF NOT EXISTS idx_voters_pu ON voters(polling_unit_code);
CREATE INDEX IF NOT EXISTS idx_voter_attempts ON voter_attempts(voter_id, created_at);
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
    """Consistent read snapshot.

    Several endpoints read a chain and its checkpoint (or rows and counts) and then
    compare them. Without an explicit transaction each SELECT could see a different
    commit, producing a spurious "truncated ledger" alarm while a vote or
    checkpoint is being written. BEGIN gives one snapshot for the whole block.
    """
    conn = connect()
    try:
        conn.execute("BEGIN")
        yield conn
    finally:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring databases created by older versions up to the current schema.

    CREATE TABLE IF NOT EXISTS never adds columns to an existing table, so additive
    migrations are applied explicitly and idempotently.
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(result_sheets)")}
    additions = {
        "review_status": "TEXT NOT NULL DEFAULT 'PENDING'",
        "reviewed_by": "TEXT",
        "reviewed_at": "TEXT",
        "review_note": "TEXT",
    }
    for name, decl in additions.items():
        if name not in cols:
            conn.execute(f"ALTER TABLE result_sheets ADD COLUMN {name} {decl}")

    audit_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='admin_audit'").fetchone()
    if audit_exists:
        audit_cols = {r["name"] for r in conn.execute("PRAGMA table_info(admin_audit)")}
        for name in ("prev_hash", "entry_hash"):
            if name not in audit_cols:
                conn.execute(f"ALTER TABLE admin_audit ADD COLUMN {name} TEXT")
        _backfill_audit_chain(conn)


def _backfill_audit_chain(conn: sqlite3.Connection) -> None:
    """Chain entries written before the audit log became tamper-evident.

    The migration runs at startup, before any request; hash the existing rows in
    insertion order so the log has a single continuous chain from GENESIS.
    """
    import audit_log as alog  # lazy: keeps module-level imports free of web app deps

    prev = alog.GENESIS
    rows = conn.execute("SELECT id, ts, actor, action, detail, entry_hash "
                        "FROM admin_audit ORDER BY id").fetchall()
    for r in rows:
        if r["entry_hash"]:
            prev = r["entry_hash"]
            continue
        h = alog.entry_hash(prev, r["ts"], r["actor"], r["action"], r["detail"] or "")
        conn.execute("UPDATE admin_audit SET prev_hash=?, entry_hash=? WHERE id=?",
                     (prev, h, r["id"]))
        prev = h


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        for etype in ELECTION_PARTIES:
            conn.execute("INSERT OR IGNORE INTO elections (election_type) VALUES (?)", (etype,))
        # SQLite has no file-permission model. The database holds voter hashes,
        # sessions and results, so keep it readable only by the service account.
        try:
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass
    finally:
        conn.close()
