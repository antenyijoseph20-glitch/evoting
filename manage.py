"""Management CLI.

  python3 manage.py create-admin <username> <ADMIN|REGISTRAR|AUDITOR>
  python3 manage.py hmac-keygen
  python3 manage.py authority-keygen [--out FILE]
  python3 manage.py officer-keygen <officer_id> [--out FILE]
  python3 manage.py add-officer <id> <name> <PRESIDING_OFFICER|PARTY_AGENT> <polling_unit> <public_key> [--party CODE]
  python3 manage.py list-officers
  python3 manage.py deactivate-officer <officer_id>
  python3 manage.py list-elections
  python3 manage.py register-officer <id> <PRESIDING_OFFICER|PARTY_AGENT> <polling_unit> [party]  (dev only)
  python3 manage.py backup <path>
  python3 manage.py status
  python3 manage.py seed-dev      (development only: one test voter, elections opened)
"""
import argparse
import getpass
import json
import os
import re
import secrets
import sqlite3
import sys

import config
import db
import results_core as rc
import security as sec
import signing as sg

ROLES = ("ADMIN", "REGISTRAR", "AUDITOR")
OFFICER_ROLES = ("PRESIDING_OFFICER", "PARTY_AGENT")
ALL_PARTIES = {p for parties in config.ELECTION_PARTIES.values() for p in parties}
PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
OFFICER_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,64}$")
POLLING_UNIT_RE = re.compile(r"^[A-Za-z0-9\-]{3,32}$")


def _officer_details(role: str, party: str | None) -> None:
    if role == "PARTY_AGENT":
        if party not in ALL_PARTIES:
            sys.exit("A PARTY_AGENT requires a valid party code (" + ", ".join(sorted(ALL_PARTIES)) + ").")
    elif party:
        sys.exit("A PRESIDING_OFFICER must not have a party code.")


def _officer_identity(officer_id: str, pu: str) -> None:
    if not OFFICER_ID_RE.match(officer_id):
        sys.exit("officer_id must be 2-64 letters, digits, dots, dashes or underscores.")
    if not POLLING_UNIT_RE.match(pu):
        sys.exit("polling unit must be 3-32 letters, digits or hyphens.")


def _write_key(path: str, pem: bytes) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        sys.exit(f"{path} already exists; refusing to overwrite a private key.")
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def create_admin(username: str, role: str) -> None:
    pw = getpass.getpass("Password (min 12 chars): ")
    if len(pw) < 12 or pw != getpass.getpass("Confirm: "):
        sys.exit("Password too short or mismatch.")
    salt, h = sec.hash_password(pw)
    with db.tx() as c:
        # Upsert without deleting the row (a DELETE would trip the session FK),
        # and revoke any existing sessions when the password is reset.
        c.execute("INSERT INTO admins (username, pw_salt, pw_hash, role) VALUES (?,?,?,?) "
                  "ON CONFLICT(username) DO UPDATE SET pw_salt=excluded.pw_salt, "
                  "pw_hash=excluded.pw_hash, role=excluded.role",
                  (username, salt, h, role))
        c.execute("DELETE FROM admin_sessions WHERE username=?", (username,))
    print(f"Admin '{username}' ({role}) saved; existing sessions revoked.")


def hmac_keygen() -> None:
    """Print a fresh HMAC secret for EVOTING_HMAC_SECRET (never write it to git)."""
    print(secrets.token_urlsafe(48))


def authority_keygen(out: str | None) -> None:
    """Generate the election authority Ed25519 key used for checkpoints.

    Run this offline for a real deployment, keep the private key on encrypted
    media, and give only the public key to observers.
    """
    pem, public = sg.generate_keypair()
    path = out or "authority_ed25519.key"
    _write_key(path, pem)
    print(f"Authority private key written to {path} (mode 0600). Keep it offline and backed up.")
    print(f"Authority public key: {public}")


def officer_keygen(officer_id: str, out: str | None) -> None:
    """Run this on the officer's own device. Only the public key is shared."""
    if not OFFICER_ID_RE.match(officer_id):
        sys.exit("officer_id must be 2-64 letters, digits, dots, dashes or underscores.")
    pem, public = sg.generate_keypair()
    path = out or f"{officer_id}.key"
    _write_key(path, pem)
    print(f"Private key written to {path} (mode 0600). Keep it on this device.")
    print(f"Public key: {public}")


def add_officer(officer_id: str, name: str, role: str, pu: str, public_key: str,
                party: str | None) -> None:
    _officer_identity(officer_id, pu)
    _officer_details(role, party)
    if not PUBLIC_KEY_RE.match(public_key):
        sys.exit("public_key must be 64 lowercase hex characters (the output of officer-keygen).")
    try:
        with db.tx() as c:
            c.execute("INSERT INTO officers (officer_id, name, role, polling_unit_code, party_code, "
                      "public_key) VALUES (?,?,?,?,?,?)",
                      (officer_id, name, role, pu, party, public_key))
    except sqlite3.IntegrityError:
        sys.exit(f"Officer {officer_id} is already registered.")
    print(f"Officer {officer_id} ({role}, {pu}) registered from its public key.")


def register_officer(oid: str, role: str, pu: str, party: str | None) -> None:
    """Development convenience: generates the keypair on this machine.

    For any real deployment use officer-keygen on the officer's device and add-officer here.
    """
    if not config.DEV:
        sys.exit("register-officer is development-only. Use officer-keygen + add-officer.")
    _officer_identity(oid, pu)
    _officer_details(role, party)
    pem, pub = sg.generate_keypair()
    with db.tx() as c:
        c.execute("INSERT INTO officers (officer_id, name, role, polling_unit_code, party_code, public_key) "
                  "VALUES (?,?,?,?,?,?)", (oid, oid, role, pu, party, pub))
    fd = os.open(f"{oid}.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    print(f"Officer {oid} registered. Private key written to {oid}.key (give to the officer; never store centrally).")


def list_officers() -> None:
    with db.read() as c:
        rows = c.execute("SELECT officer_id, name, role, polling_unit_code, party_code, active, public_key "
                         "FROM officers ORDER BY polling_unit_code, role, officer_id").fetchall()
    if not rows:
        print("No officers registered.")
        return
    for r in rows:
        state = "active" if r["active"] else "inactive"
        print(f"{r['officer_id']:<24} {state:<8} {r['role']:<16} PU={r['polling_unit_code']:<12} "
              f"party={r['party_code'] or '-':<5} {r['public_key']}")


def deactivate_officer(officer_id: str) -> None:
    with db.tx() as c:
        cur = c.execute("UPDATE officers SET active=0 WHERE officer_id=?", (officer_id,))
        if cur.rowcount != 1:
            sys.exit(f"Officer {officer_id} not found.")
    print(f"Officer {officer_id} deactivated.")


def list_elections() -> None:
    with db.read() as c:
        rows = c.execute("SELECT election_type, status FROM elections ORDER BY election_type").fetchall()
    for r in rows:
        print(f"{r['election_type']:<20} {r['status']}")


def backup(path: str) -> None:
    if os.path.abspath(path) == os.path.abspath(config.DB_PATH):
        sys.exit("Backup path must differ from the live database.")
    if not os.path.exists(config.DB_PATH):
        sys.exit(f"No database at {config.DB_PATH}.")
    if os.path.exists(path):
        sys.exit(f"{path} already exists; refusing to overwrite.")
    src = db.connect()
    try:
        dst = sqlite3.connect(path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"Backup written to {path}.")


def status() -> None:
    with db.read() as c:
        voters = c.execute("SELECT COUNT(*) FROM voters").fetchone()[0]
        rows = c.execute("SELECT * FROM ledger ORDER BY block_index").fetchall()
        cp = rc.latest_ledger_checkpoint(c)
        sheets = c.execute("SELECT COUNT(*) FROM result_sheets").fetchone()[0]
        flagged = c.execute("SELECT COUNT(*) FROM result_sheets WHERE flags != '' "
                            "AND review_status='PENDING'").fetchone()[0]
        elections = {r["election_type"]: r["status"] for r in c.execute("SELECT * FROM elections")}
        sheet_chain = rc.verify_sheet_chain(c)
        sheet_cp_check = rc.verify_checkpoint(c)
        ledger_chain = rc.verify_ledger_chain(c, rows)
    print(json.dumps({
        "database": config.DB_PATH,
        "environment": config.ENV,
        "voters": voters,
        "votes_cast": len(rows),
        "ledger_chain": ledger_chain,
        "ledger_checkpoint": dict(cp) if cp else None,
        "result_sheets": sheets,
        "pending_flag_reviews": flagged,
        "result_sheet_chain": sheet_chain,
        "result_checkpoint_check": sheet_cp_check,
        "elections": elections,
    }, indent=2))


def seed_dev() -> None:
    if not config.DEV:
        sys.exit("seed-dev is disabled in production.")
    with db.tx() as c:
        c.execute("INSERT OR IGNORE INTO voters (voter_hash, polling_unit_code, phone_number) VALUES (?,?,?)",
                  (sec.voter_hash("12345678901", "NG12345678"), "PU-001", "+2340000000000"))
        c.execute("UPDATE elections SET status='OPEN' WHERE status='PENDING'")
    print("Dev voter NIN=12345678901 VIN=NG12345678 created; elections opened. OTP prints in server console.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="E-voting administration CLI.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("create-admin")
    a.add_argument("username")
    a.add_argument("role", choices=ROLES)

    sub.add_parser("hmac-keygen")

    ak = sub.add_parser("authority-keygen")
    ak.add_argument("--out")

    k = sub.add_parser("officer-keygen")
    k.add_argument("officer_id")
    k.add_argument("--out")

    ao = sub.add_parser("add-officer")
    ao.add_argument("officer_id")
    ao.add_argument("name")
    ao.add_argument("role", choices=OFFICER_ROLES)
    ao.add_argument("polling_unit")
    ao.add_argument("public_key")
    ao.add_argument("--party")

    sub.add_parser("list-officers")

    d = sub.add_parser("deactivate-officer")
    d.add_argument("officer_id")

    sub.add_parser("list-elections")

    r = sub.add_parser("register-officer")
    r.add_argument("officer_id")
    r.add_argument("role", choices=OFFICER_ROLES)
    r.add_argument("polling_unit")
    r.add_argument("party", nargs="?")

    b = sub.add_parser("backup")
    b.add_argument("path")

    sub.add_parser("status")
    sub.add_parser("seed-dev")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.cmd not in ("officer-keygen", "authority-keygen", "hmac-keygen", "backup"):
        db.init_db()
    if args.cmd == "create-admin":
        create_admin(args.username, args.role)
    elif args.cmd == "hmac-keygen":
        hmac_keygen()
    elif args.cmd == "authority-keygen":
        authority_keygen(args.out)
    elif args.cmd == "officer-keygen":
        officer_keygen(args.officer_id, args.out)
    elif args.cmd == "add-officer":
        add_officer(args.officer_id, args.name, args.role, args.polling_unit, args.public_key, args.party)
    elif args.cmd == "list-officers":
        list_officers()
    elif args.cmd == "deactivate-officer":
        deactivate_officer(args.officer_id)
    elif args.cmd == "list-elections":
        list_elections()
    elif args.cmd == "register-officer":
        register_officer(args.officer_id, args.role, args.polling_unit, args.party)
    elif args.cmd == "backup":
        backup(args.path)
    elif args.cmd == "status":
        status()
    elif args.cmd == "seed-dev":
        seed_dev()
