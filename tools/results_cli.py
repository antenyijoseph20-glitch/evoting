"""Polling-unit results tooling.

Runs on the officer's own device: the private key never leaves it.
The server only ever sees a signed payload.

    python3 tools/results_cli.py keygen --out officer.key
    python3 tools/results_cli.py submit --key officer.key --officer PO-001 \
        --election PRESIDENTIAL --pu PU-001 --accredited 250 --rejected 5 \
        --scores APC=101,LP=90 --url http://127.0.0.1:8000
    python3 tools/results_cli.py countersign --key agent.key --officer AG-APC-1 \
        --election PRESIDENTIAL --pu PU-001

Use the public key printed by `keygen` when an ADMIN registers the officer
(manage.py add-officer or POST /admin/officers). Keep the .key file mode 0600.
"""
import argparse
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

import signing as sg

DEFAULT_URL = os.getenv("EVOTING_URL", "http://127.0.0.1:8000")
OFFICER_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,64}$")


def _fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def _load_key(path: str):
    try:
        mode = os.stat(path).st_mode
    except OSError as e:
        _fail(f"cannot read key file: {e}")
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        _fail(f"{path} is accessible by group/others; run: chmod 600 {path}")
    with open(path, "rb") as f:
        try:
            return sg.load_private(f.read())
        except Exception:
            _fail(f"{path} is not an unprotected PKCS8 Ed25519 private key")


def _parse_scores(raw: str) -> dict:
    scores = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            _fail(f"bad score '{item}'; expected PARTY=VOTES")
        party, value = item.split("=", 1)
        try:
            scores[party.strip().upper()] = int(value)
        except ValueError:
            _fail(f"bad vote count for {party.strip()}")
    if not scores:
        _fail("--scores must contain at least one PARTY=VOTES entry")
    return scores


def _post(url: str, body: dict, timeout: float) -> dict:
    try:
        r = requests.post(url, json=body, timeout=timeout)
    except requests.RequestException as e:
        _fail(f"cannot reach {url}: {e}")
    try:
        data = r.json()
    except ValueError:
        data = {"detail": r.text[:500]}
    if not 200 <= r.status_code < 300:
        _fail(f"HTTP {r.status_code}: {data.get('detail', data)}")
    return data


def keygen(args) -> None:
    if not OFFICER_ID_RE.match(args.officer_id):
        _fail("officer id must be 2-64 letters, digits, dots, dashes or underscores")
    pem, public = sg.generate_keypair()
    path = args.out or f"{args.officer_id}.key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        _fail(f"{path} already exists; refusing to overwrite a private key")
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    print(json.dumps({"officer_id": args.officer_id, "key_file": path,
                      "public_key": public}, indent=2))
    print("Register the public_key above as this officer. Keep the private key on this device.",
          file=sys.stderr)


def submit(args) -> None:
    key = _load_key(args.key)
    payload = {
        "v": 1,
        "election_type": args.election.upper(),
        "polling_unit_code": args.pu,
        "accredited": args.accredited,
        "rejected": args.rejected,
        "scores": _parse_scores(args.scores),
        "signed_at": args.signed_at or datetime.now(timezone.utc).isoformat(),
    }
    body = {"payload": payload, "officer_id": args.officer,
            "signature": sg.sign(key, sg.sheet_message(payload))}
    print(json.dumps(_post(f"{args.url.rstrip('/')}/results/submit", body, args.timeout), indent=2))


def countersign(args) -> None:
    key = _load_key(args.key)
    base = args.url.rstrip("/")
    election, pu = args.election.upper(), args.pu
    try:
        r = requests.get(f"{base}/results/sheet/{election}/{pu}", timeout=args.timeout)
    except requests.RequestException as e:
        _fail(f"cannot reach {base}: {e}")
    if r.status_code != 200:
        _fail(f"cannot fetch result sheet (HTTP {r.status_code}): {r.text[:300]}")
    payload_hash = r.json()["sheet"]["payload_hash"]
    body = {"officer_id": args.officer,
            "signature": sg.sign(key, sg.countersign_message(payload_hash))}
    print(json.dumps(_post(f"{base}/results/{election}/{pu}/countersign", body, args.timeout), indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Sign and submit polling-unit result sheets.")
    sub = p.add_subparsers(dest="command", required=True)

    k = sub.add_parser("keygen", help="generate an Ed25519 officer keypair locally")
    k.add_argument("--officer-id", default="officer")
    k.add_argument("--out", help="private key path (default: <officer-id>.key)")
    k.set_defaults(fn=keygen)

    s = sub.add_parser("submit", help="sign and POST a result sheet")
    s.add_argument("--key", required=True)
    s.add_argument("--officer", required=True, help="registered officer_id")
    s.add_argument("--election", required=True)
    s.add_argument("--pu", required=True, help="polling unit code")
    s.add_argument("--accredited", required=True, type=int)
    s.add_argument("--rejected", required=True, type=int)
    s.add_argument("--scores", required=True, help="e.g. APC=101,LP=90")
    s.add_argument("--signed-at", help="ISO-8601 timestamp (default: now, UTC)")
    s.add_argument("--url", default=DEFAULT_URL)
    s.add_argument("--timeout", type=float, default=15)
    s.set_defaults(fn=submit)

    c = sub.add_parser("countersign", help="countersign an existing result sheet")
    c.add_argument("--key", required=True)
    c.add_argument("--officer", required=True, help="registered party agent officer_id")
    c.add_argument("--election", required=True)
    c.add_argument("--pu", required=True)
    c.add_argument("--url", default=DEFAULT_URL)
    c.add_argument("--timeout", type=float, default=15)
    c.set_defaults(fn=countersign)
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    args.fn(args)
