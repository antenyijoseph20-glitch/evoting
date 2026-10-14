"""Management CLI.
   python3 manage.py create-admin <username> <ADMIN|REGISTRAR|AUDITOR>
   python3 manage.py register-officer <id> <PRESIDING_OFFICER|PARTY_AGENT> <polling_unit> [party]
   python3 manage.py seed-dev      (development only: one test voter, elections opened)
"""
import getpass
import os
import sys

import config
import db
import security as sec


def create_admin(username: str, role: str) -> None:
    pw = getpass.getpass("Password (min 12 chars): ")
    if len(pw) < 12 or pw != getpass.getpass("Confirm: "):
        sys.exit("Password too short or mismatch.")
    salt, h = sec.hash_password(pw)
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO admins (username, pw_salt, pw_hash, role) VALUES (?,?,?,?)",
                  (username, salt, h, role))
    print(f"Admin '{username}' ({role}) saved.")


def register_officer(oid: str, role: str, pu: str, party: str | None) -> None:
    """Generates the keypair. The private key file goes to the officer's device; only the public key is stored."""
    import signing as sg
    pem, pub = sg.generate_keypair()
    with db.tx() as c:
        c.execute("INSERT INTO officers (officer_id, name, role, polling_unit_code, party_code, public_key) "
                  "VALUES (?,?,?,?,?,?)", (oid, oid, role, pu, party, pub))
    fd = os.open(f"{oid}.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    print(f"Officer {oid} registered. Private key written to {oid}.key (give to the officer; never store centrally).")


def seed_dev() -> None:
    if not config.DEV:
        sys.exit("seed-dev is disabled in production.")
    with db.tx() as c:
        c.execute("INSERT OR IGNORE INTO voters (voter_hash, polling_unit_code, phone_number) VALUES (?,?,?)",
                  (sec.voter_hash("12345678901", "NG12345678"), "PU-001", "+2340000000000"))
        c.execute("UPDATE elections SET status='OPEN' WHERE status='PENDING'")
    print("Dev voter NIN=12345678901 VIN=NG12345678 created; elections opened. OTP prints in server console.")


if __name__ == "__main__":
    db.init_db()
    a = sys.argv[1:]
    if a[:1] == ["create-admin"] and len(a) == 3 and a[2] in ("ADMIN", "REGISTRAR", "AUDITOR"):
        create_admin(a[1], a[2])
    elif a[:1] == ["register-officer"] and len(a) in (4, 5) and a[2] in ("PRESIDING_OFFICER", "PARTY_AGENT"):
        register_officer(a[1], a[2], a[3], a[4] if len(a) == 5 else None)
    elif a[:1] == ["seed-dev"]:
        seed_dev()
    else:
        sys.exit(__doc__)
