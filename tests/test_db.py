"""Schema creation and in-place migration."""
import audit_log as alog
import db


def test_init_db_is_idempotent_and_seeds_elections(client):
    with db.read() as c:
        first = {r["election_type"]: r["status"] for r in c.execute("SELECT * FROM elections")}
    assert set(first) == {"PRESIDENTIAL", "SENATE", "HOUSE_OF_REPS", "GOVERNOR", "HOUSE_OF_ASSEMBLY"}
    assert set(first.values()) == {"PENDING"}
    db.init_db()
    with db.read() as c:
        second = {r["election_type"]: r["status"] for r in c.execute("SELECT * FROM elections")}
    assert second == first


def test_migration_adds_review_columns_in_place(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "old.db"))
    conn = db.connect()
    try:
        conn.execute("CREATE TABLE result_sheets (block_index INTEGER PRIMARY KEY)")
        db._migrate(conn)
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(result_sheets)")}
        assert {"review_status", "reviewed_by", "reviewed_at", "review_note"} <= columns
        # running it again must not fail
        db._migrate(conn)
    finally:
        conn.close()


def test_migration_backfills_the_audit_chain(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "old-audit.db"))
    conn = db.connect()
    try:
        conn.execute("CREATE TABLE admin_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                     "ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT)")
        conn.execute("INSERT INTO admin_audit (ts, actor, action, detail) VALUES (?,?,?,?)",
                     ("2026-01-01T00:00:00+00:00", "alice", "LOGIN", ""))
        conn.execute("INSERT INTO admin_audit (ts, actor, action, detail) VALUES (?,?,?,?)",
                     ("2026-01-01T00:01:00+00:00", "alice", "LOGOUT", ""))
    finally:
        conn.close()

    db.init_db()
    with db.read() as c:
        check = alog.verify(c)
    assert check["valid"] is True
    assert check["entries_checked"] == 2
    assert check["checkpoint"] is None
