# E2E-V — End-to-End Verifiable E-Voting (Research Prototype)

A working, pilot-ready reference implementation of a remote electronic voting
workflow for Nigeria: registered voters identify themselves with NIN/VIN, confirm
an SMS one-time code, pass a biometric check, cast one ballot per election, and
receive a receipt. Polling-unit result sheets are signed by officers, chained,
committed to a Merkle tree, and published with inclusion proofs. An independent
offline verifier checks the whole archive.

> **Status: pilot software, not a certified election system.**
> This repository is suitable for supervised pilots, research, security review and
> procurement demonstrations. It is **not** ready for a national election (including
> Nigeria's 2027 general election) and must not be presented to voters as one.
> See [docs/NATIONAL_READINESS.md](docs/NATIONAL_READINESS.md) for the legal,
> identity, ballot-secrecy, scale and assurance gaps that remain.

---

## What works

**Voter flow**

- Register-first eligibility (no auto-enrolment); only a keyed HMAC hash of
  NIN+VIN is stored — neither NIN nor VIN is ever persisted.
- SMS OTP via a provider-neutral HTTP webhook (console output in development).
- Face check in development (exactly one face must be present); production
  refuses to start without a real matcher.
- One ballot per voter per election, enforced atomically; polling unit is taken
  from the register, never from the client.
- A receipt block hash that anyone can verify publicly.

**Integrity**

- SHA-256 hash-chained vote ledger containing only election, party and polling
  unit — no voter link and no timestamp.
- Signed ledger-head checkpoints make truncation detectable. Every checkpoint read
  re-verifies the Ed25519 signature against the authority key, so a forged
  checkpoint row cannot hide a rewritten or shortened ledger.
- EC8A-style result sheets signed by presiding officers (Ed25519, domain
  separated) and countersigned by party agents.
- Result-sheet hash chain plus an RFC 6962-style Merkle tree with signed
  checkpoints and per-polling-unit inclusion proofs. The admin status view
  re-derives the root from the stored sheets and verifies the checkpoint
  signature, so deleting or altering a covered sheet is detected.
- Flagged sheets (e.g. over-votes) are excluded from the tally until an ADMIN
  makes a one-shot, audited decision to accept or void them.
- The staff audit log is hash-chained and can be committed with a signed
  checkpoint. Verification re-checks every link and the Ed25519 signature, so a
  rewritten or shortened covered log is detected rather than trusted.
- A public tally re-checks each stored sheet's metadata, payload hash and officer
  signature; a row that no longer agrees with what was signed is excluded and
  reported, never counted.
- Results and detailed exports stay sealed until the election is CLOSED.
- `verify_offline.py` independently re-checks signatures, chains, flags, the
  Merkle root and the authority signature from an export file.

**Operations**

- Role-based admin console (`/admin`): ADMIN, REGISTRAR, AUDITOR.
- Polling-officer CLI that signs on the officer's own device; the server never
  holds an officer's private key.
- Public results and verification portal (`/results`), including receipt lookup
  and browser-side chain recomputation.
- Health endpoints, SQLite WAL, in-place schema migration, backup command.

---

## Quickstart (development)

Requires Python 3.12+ and a C toolchain only if a wheel is unavailable.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

# Create the schema, one test voter and open the elections.
.venv/bin/python manage.py seed-dev

# Run one worker (SQLite + the rate limiter are per-process).
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
```

`manage.py` does not read `.env` automatically. If you set `EVOTING_DB` or
`EVOTING_HMAC_SECRET` there, export the same values before running the CLI and
the server; a different HMAC secret hashes the seeded NIN/VIN differently.

Open:

| URL | Purpose |
|---|---|
| <http://127.0.0.1:8000/> | Voter flow |
| <http://127.0.0.1:8000/admin> | Admin console |
| <http://127.0.0.1:8000/results> | Public results & verification |
| <http://127.0.0.1:8000/docs> | OpenAPI docs (development only) |
| <http://127.0.0.1:8000/healthz> | Liveness |

The development voter is NIN `12345678901`, VIN `NG12345678`. The OTP is printed
in the server console as `[DEV-SMS] OTP for +234*******000: 123456`.

Create staff accounts:

```bash
.venv/bin/python manage.py create-admin alice ADMIN
.venv/bin/python manage.py create-admin rita REGISTRAR
.venv/bin/python manage.py create-admin audrey AUDITOR
```

Role capabilities:

| Role | Can do |
|---|---|
| `ADMIN` | Everything: elections, voters, officers, result review, checkpoints, audit |
| `REGISTRAR` | Register and list voters; read overview |
| `AUDITOR` | Read-only results, audit log, chain verification and exports |

---

## Keys and secrets

Development needs no manual keys: the HMAC secret falls back to a development-only
value and the authority key is generated automatically on first start. Anything
that faces real voters needs the values below.

| Value | Needed for | Create it with | Keep it |
|---|---|---|---|
| `EVOTING_HMAC_SECRET` | Hashing NIN/VIN and binding OTPs (required in production) | `python3 manage.py hmac-keygen` | Server secret store; never in git |
| `EVOTING_AUTHORITY_KEY` | Signing vote-ledger, result-sheet and audit-log checkpoints | `python3 manage.py authority-keygen --out authority_ed25519.key` | Offline/HSM; public key published to observers |
| Officer Ed25519 key | Signing each polling unit's result sheet | `python3 tools/results_cli.py keygen --officer-id PO-001 --out PO-001.key` | On the officer's own device only |
| `EVOTING_SMS_API_KEY` | Delivering OTPs through the SMS webhook | Your SMS provider | Server secret store |
| `EVOTING_FACE_MATCHER` | Production biometric matching with liveness | Your matcher as `package.module:callable` | Deployed with the service; not a secret |
| TLS certificate and private key | HTTPS for voters and staff (never expose HTTP) | Your CA or ACME client | Reverse proxy; renew automatically |

Generate the HMAC secret and authority key on a trusted machine. The authority
private key is the root of every checkpoint signature: if it leaks, all signatures
can be forged, and if it is lost, nobody can sign new checkpoints. Keep it mode
`0600`; production refuses to start if the key file is accessible by group or
others.

---

## Polling-unit officer key ceremony

The private key must be generated and kept on the officer's own device.

```bash
# On the officer's device:
python3 tools/results_cli.py keygen --officer-id PO-001 --out PO-001.key
# prints: {"officer_id":"PO-001","key_file":"PO-001.key","public_key":"<64 hex>"}

# On the server / admin console, register only the public key:
python3 manage.py add-officer PO-001 "Amina Okafor" PRESIDING_OFFICER PU-001 <public_key>
# or paste the public key into Admin -> Officers
```

Submit and countersign result sheets against a running server:

```bash
python3 tools/results_cli.py submit --key PO-001.key --officer PO-001 \
  --election PRESIDENTIAL --pu PU-001 --accredited 250 --rejected 5 \
  --scores APC=101,LP=90 --url http://127.0.0.1:8000

python3 tools/results_cli.py countersign --key AG-APC-001.key \
  --officer AG-APC-001 --election PRESIDENTIAL --pu PU-001 \
  --url http://127.0.0.1:8000
```

A party agent must be registered for the same polling unit with the matching
party code. `submit` is accepted once the election is OPEN; results remain
sealed until it is CLOSED.

Result sheets can still arrive after voting closes, because polling units report
at the end of the day. Treat the signed result-sheet checkpoint and the exported
archive as the final record: once they are published, a later submission or a
changed tally is evidence of a process failure and must be investigated rather
than silently accepted. Sign a fresh checkpoint after the last sheet so the
archive verifier can confirm that the checkpoint covers every sheet; it rejects an
archive whose sheets are newer than its signed checkpoint.

---

## Operating an election

1. Register voters (Admin → Voters, or `POST /admin/voters`).
2. Register officers from their public keys.
3. Open the election (Admin → Elections). Voting is possible only while OPEN.
4. Polling units submit signed result sheets; party agents countersign.
5. Close the election. Tallies and detailed public data are released.
6. Review any flagged sheets (Admin → Results). Each decision is audited.
7. Sign a result-sheet checkpoint (Admin → Results), a ledger checkpoint
   (Admin → Overview or Audit), and an audit-log checkpoint (Admin → Audit).
8. Download the archive (`/results/export`, unlocked once nothing is OPEN) and
   verify it independently:

```bash
python3 verify_offline.py export.json --authority-key <published-authority-public-key>
# RESULT: ALL CHECKS PASSED
```

`verify_offline.py` needs only Python and `cryptography`; it trusts nothing on
the server. Pass `--authority-key` with the authority public key published through
an independent channel (or `--require-pinned-key` to fail if it is omitted). Without
a pinned key the verifier warns that it is trusting the key embedded in the
archive, which an attacker who rewrote the archive could also replace.

---

## Security invariants

- No table links a voter to a party or vote. `votes_cast` is `WITHOUT ROWID` and
  has no timestamp; the ledger stores only election, party and polling unit.
- Every write path runs inside `BEGIN IMMEDIATE` (`db.tx()`), so check-then-write
  is atomic across processes. Multi-statement verification reads use one snapshot
  (`db.read()`), so a concurrent vote cannot create a false truncation alarm.
- Polling unit comes from the voter register, never the request body.
- NIN/VIN are keyed-hashed with a secret (`EVOTING_HMAC_SECRET`); the raw values
  are never stored or logged.
- OTPs are HMACs bound to the session token; attempts and expiry are enforced.
- A voter is limited to five verification attempts per rolling hour, tracked separately
  from sessions so restarting or resending the code does not reset the cap. Starting a
  new verification replaces the previous live session.
- Admin passwords use scrypt with a fresh salt; sessions are opaque bearer
  tokens stored only as SHA-256 hashes.
- Result signatures are Ed25519 with domain separation, over canonical JSON, so
  signatures cannot be replayed across purposes.
- Administrative audit entries are hash-chained; signed checkpoints fix a height
  and head, and every verification re-checks the chain and Ed25519 signature.
- Result detail and exports are locked while any election is OPEN; only counts
  of submitted/flagged sheets are public.
- The production process refuses to start unless SMS, a biometric matcher, the
  HMAC secret and an authority key file are configured (`production_blockers()`).
- The frontend never uses `innerHTML` for untrusted data; the CSP is
  `script-src 'self'`.

### Deliberate development stubs (blocked in production)

- `face_check()` detects a face; it does **not** identify a person, and has no
  liveness or presentation-attack defence.
- SMS delivery is a console print unless `EVOTING_SMS_GATEWAY_URL` is set.
- Rate limiting is in-process, so it is per worker.
- SQLite is a single-writer pilot store.

---

## API summary

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/auth/verify` | public | NIN/VIN check, create session, send OTP |
| POST | `/api/v1/auth/verify-otp` | session | Confirm OTP |
| POST | `/api/v1/biometric/verify-face` | session | Face check |
| POST | `/api/v1/ballot/cast` | session | Cast one ballot, return receipt |
| GET | `/api/v1/elections` | public | Election status and parties |
| GET | `/api/v1/receipt/{hash}` | public | Verify a receipt and the chain |
| GET | `/api/v1/audit/ledger` | public | Blocks from CLOSED elections + chain check |
| GET | `/results/status/{type}` | public | Live submission counts only |
| GET | `/results/tally/{type}` | public | Tally, once CLOSED |
| GET | `/results/sheet/{type}/{pu}` | public | Sheet commitment; figures only once CLOSED |
| GET | `/results/proof/{type}/{pu}` | public | Merkle inclusion proof |
| GET | `/results/checkpoint` | public | Latest signed result checkpoint |
| GET | `/results/export` | public | Full archive, locked while anything is OPEN |
| POST | `/results/submit` | signature | Officer-signed result sheet |
| POST | `/results/{type}/{pu}/countersign` | signature | Party-agent countersignature |
| POST | `/results/checkpoint` | ADMIN | Sign the Merkle root |
| POST | `/admin/login`, `/admin/logout` | public/session | Staff session |
| GET | `/admin/me`, `/admin/stats` | staff | Identity and operations status |
| GET | `/admin/elections` | staff | Election status list |
| POST | `/admin/elections/{type}/{open\|close}` | ADMIN | One-way election transitions |
| GET/POST | `/admin/voters` | ADMIN, REGISTRAR | Register/list voters |
| GET/POST | `/admin/officers…` | ADMIN | Register/activate officers |
| GET | `/admin/results` | ADMIN, AUDITOR | Sheets with review state |
| POST | `/admin/results/{type}/{pu}/review` | ADMIN | Accept or void a flagged sheet |
| GET | `/admin/audit`, `/admin/audit/export` | ADMIN, AUDITOR | Audit trail and ledger |
| POST | `/admin/audit/checkpoint` | ADMIN | Sign the ledger head |
| POST | `/admin/audit/log-checkpoint` | ADMIN | Sign the admin audit-log head |
| GET | `/admin/audit/verify-log` | ADMIN, AUDITOR | Verify the audit-log chain and checkpoint |
| GET | `/admin/audit/log-export` | ADMIN, AUDITOR | Audit log, checkpoint and authority key for review |
| GET | `/admin/audit/verify-chain` | ADMIN, AUDITOR | Verify chain against checkpoint |
| GET | `/admin/results/export` | ADMIN, AUDITOR | Internal audit archive |

---

## Tests

```bash
.venv/bin/python -m pytest -q
```

The suite covers the full voter flow, OTP/face/rate limits, duplicate voting,
admin RBAC, signed result submission and review, tally release policy, Merkle
proofs, ledger checkpoints and truncation detection, forged checkpoint
signatures, result-tree truncation, tampered stored sheets, admin audit-log
chaining, edit/truncation/forged-signature detection, schema migration, and
`verify_offline.py` against a real export (including tampered and malformed
archives and a pinned authority key).

---

## Deployment (pilot)

```bash
cp .env.example .env      # fill in secrets and SMS settings
docker compose up --build -d
docker compose logs -f
```

Requires Docker Compose 2.24 or newer for the optional `env_file` entry in
`docker-compose.yml`.

What the image does:

- non-root user, one uvicorn worker, no source bind-mount, no `--reload`;
- database and authority key on the `evoting_data` volume;
- healthcheck against `/healthz`;
- `EVOTING_ENV=production` fails closed until SMS, a biometric matcher, an HMAC
  secret and an authority key file are supplied.

In production the authority key must already exist; the unprivileged container
user will not generate one. Generate it offline on a trusted machine, then copy
it onto the volume before starting:

```bash
.venv/bin/python manage.py authority-keygen --out authority_ed25519.key
docker compose create
docker cp --chown=evoting:evoting authority_ed25519.key \
  evoting-pilot:/app/data/authority_ed25519.key
docker compose start
```

Before exposing it publicly you also need, at minimum: TLS termination, a WAF,
backups with restore drills, log shipping, an HSM or offline key ceremony for
the authority key, independent observers, and a signed operational runbook. The
compose file binds to `127.0.0.1` by default for a reason.

---

## Repository layout

```text
main.py               voter API, public pages, security headers, health
admin.py              role-based admin API
audit_log.py          hash-chained admin audit log and signed head checkpoints
results.py            polling-unit result API
results_core.py       signing, chaining, Merkle checkpoints, tally, review
ledger.py             vote hash chain and signed head checkpoints
security.py           voter hashing, OTP, SMS webhook, passwords, rate limits
config.py             env-driven settings and production blockers
db.py                 schema, WAL transactions, in-place migration
manage.py             admin/officer/backup/status CLI
tools/results_cli.py  officer-side key generation, submission, countersign
verify_offline.py     independent archive verifier
static/               voter, admin and results UIs (vanilla JS, external files)
tests/                pytest suite
legacy/               earlier prototype modules; not imported, not in the image
docs/NATIONAL_READINESS.md   candid gap analysis and staged path
```

---

## License and use

No license is granted for use in a public election. Any real deployment requires
legal authority, independent security assessment, and the safeguards described
in [docs/NATIONAL_READINESS.md](docs/NATIONAL_READINESS.md). Until then, use it
for supervised pilots and research only.
