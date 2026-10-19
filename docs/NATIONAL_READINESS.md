# National Readiness: What It Would Take

This document is deliberately blunt. The code in this repository is a solid
pilot-grade reference implementation. It is **not** a national election system,
and no amount of finishing UI or backend work would make it safe to run Nigeria's
2027 general election as an uncontrolled remote internet ballot.

Remote internet voting is one of the hardest public-sector systems to operate
legitimately. The hard parts are not cryptography alone; they are law, identity,
coercion, inclusion, operations and public trust. This document separates what is
already implemented from what is missing, and proposes a path that does not put
voters or the result at risk.

---

## 1. Legal and institutional authority

A national election is not a software launch. Before one ballot can be cast
remotely, at minimum:

- The Constitution and the Electoral Act must permit the method. Nigeria's
  current framework and INEC procedures are built around in-person accreditation
  (BVAS) and polling-unit result upload (IReV); remote voting is not an
  administrative switch.
- INEC must issue regulations, certify the system, and define the audit and
  dispute process.
- Political parties, civil-society observers, the courts and the public must
  accept the mechanism. A result produced by an unaccredited system is exposed
  to legal challenge regardless of its technical quality.
- Data protection (NDPA 2023), procurement, accessibility and language
  obligations must be satisfied.
- Liability, insurance, procurement and vendor-independence arrangements must be
  in place.

**No engineering work in this repository can satisfy this section.** It requires
a mandate, not a merge.

---

## 2. Identity and eligibility

Current implementation: a voter is registered with NIN/VIN, which are keyed-hashed.
At voting time the same pair is typed in, then an SMS OTP and a face **detection**
check are required.

Why that is not identity assurance:

- Typing NIN/VIN proves knowledge of two numbers, not that the person is the
  registered voter. Both numbers can be bought, leaked or coerced.
- There is no NIMC/INEC identity lookup, no biometric de-duplication against the
  register, no liveness/presentation-attack detection, and no enrolled template
  comparison.
- SMS OTP is vulnerable to SIM swap, number recycling, interception and shared
  phones. It is a second factor, not an identity.
- Nothing binds the session to a device or to a supervised location.

For a national system you would need, at minimum:

- An authoritative eligibility feed from INEC's register, with cryptographic
  eligibility proofs that do not reveal identity.
- A certified biometric matcher with liveness and anti-spoofing, operating on
  enrolled templates under a lawful data-protection regime.
- Device/app attestation, secure key storage, and a recovery process that cannot
  be used to steal a vote.
- Strong protection against insider registration fraud and duplicate identities.

---

## 3. Ballot secrecy

This is the most serious limitation of the current design, and it is not visible
in the UI.

The server receives `(election_type, party_code, polling_unit_code)` at cast
time and writes it to the ledger. It does not store `voter_id` alongside the
ballot, which prevents a trivial database join. But:

- The server processes the request while it knows the session, the voter, the
  timestamp and the client address. Logs, in-memory state, timing and the order
  of ledger entries can re-link a voter to a choice.
- Polling units can be small. Even without a voter link, a party/PU tally may
  identify how a household or a small community voted.
- An administrator with database write access can rewrite ledger rows unless the
  hash chain is checked against a checkpoint held elsewhere. The signed head
  checkpoint makes truncation/alteration detectable, but it does not stop the
  write; detection must be independent and timely.

A credible secret ballot requires cryptography that keeps the choice hidden from
the server and from insiders, for example:

- encrypted ballots plus a verifiable mixnet or a homomorphic tally with
  verifiable decryption shares held by independent trustees;
- zero-knowledge proofs of eligibility and well-formedness;
- threshold trustees so no single party can decrypt or forge;
- publication of proofs that anyone can verify.

This repository does **not** implement any of that. Its integrity story is about
result sheets, not about cryptographic ballot secrecy.

---

## 4. Coercion and vote buying

A polling unit provides a social and physical environment that remote voting
removes. At home, a voter can be watched, pressured, paid or threatened while
voting. A receipt that proves how a ballot was cast is useful for individual
verification but also enables vote buying.

A national remote system needs coercion resistance and receipt-freeness, or
supervised voting locations, or both. Possible mitigations include:

- coercion-resistant protocols (for example, credentials that can be re-used to
  replace a coerced vote without revealing that replacement);
- multiple, private, supervised kiosks for voters who cannot travel far;
- legal and operational mechanisms to report and remedy coercion;
- careful receipt design that proves inclusion without proving the choice.

Receipt-freeness is a research-grade property. It should be a requirement in any
pilot's threat model, not an afterthought.

---

## 5. Availability, scale and inclusion

Current implementation: SQLite in WAL mode, one uvicorn worker, in-process rate
limiting, a single SMS webhook, no queue, no cache, no multi-region deployment.

A national remote ballot would face:

- tens of millions of eligible voters and extreme peak concurrency in the final
  hours;
- SMS gateway throughput and delivery failures;
- DDoS and fraud attempts;
- unreliable power, connectivity and shared devices;
- voters without smartphones, data or literacy;
- accessibility needs (disability, language, assisted voting);
- offline or low-connectivity areas;
- disaster recovery and a tested continuity plan.

A production architecture would need at least: a replicated relational database,
distributed rate limiting and sessions, a durable queue, an HSM-backed key
service, a CDN/WAF, multi-region failover, load and chaos testing, and assisted
channels (USSD/IVR/kiosk) that do not weaken the security model.

---

## 6. Assurance and operations

What a national system needs that this repository does not have:

- an independent threat model and penetration test;
- a formal key ceremony, HSM custody, threshold signing and rotation;
- separation of duties (today one ADMIN can open elections, register officers,
  review results and sign checkpoints);
- MFA for staff, hardware-backed admin credentials and short-lived sessions;
- a tamper-evident administrative audit log (now hash-chained with signed
  checkpoints, but not yet mirrored to independent witnesses);
- transparency-log witnesses that mirror signed checkpoints to independent
  parties and publish them widely;
- reproducible builds, dependency pinning, SBOM and supply-chain controls;
- incident response, forensic readiness, monitoring and on-call operations;
- encryption at rest for the database, backups and logs, with managed keys
  (the pilot only sets file permissions);
- risk-limiting audits and a paper or independently verifiable backup;
- a dispute-resolution process with published evidence and deadlines;
- data-retention, privacy-impact and deletion rules.

---

## 7. What this repository is genuinely good for now

Used honestly, it can support:

1. **Supervised pilots** with a few hundred to a few thousand consenting voters,
   in a controlled environment, with independent observers and a parallel paper
   count.
2. **Polling-unit result capture and public verification.** The signed-sheet,
   hash-chain and Merkle-proof design is directly useful for digitising EC8A-style
   results and letting observers verify that published totals match signed sheets.
3. **Research and procurement demonstrations** of end-to-end verifiability,
   role separation, and offline verification.
4. **Civic-tech transparency portals** built on the signed result archive.

It is not suitable for an unsupervised national ballot, diaspora voting, or any
election where a wrong result would be irreversible.

---

## 8. A staged path (recommended)

### Stage 0 — Harden and demonstrate (weeks)

- External code review and threat model.
- Key ceremony and HSM/offline custody for the authority key.
- Move to PostgreSQL, Redis-backed rate limits/sessions, and multiple workers.
- Add MFA and separation of duties for staff.
- Hash-chain the admin audit log and publish checkpoints to independent
  witnesses. (The chain and signed checkpoints are implemented; external
  witnessing, timely independent verification and retention guarantees are not.)
- Load-test the intended pilot size; run a public test election.
- Publish source hashes and a reproducible-build recipe.

### Stage 1 — Supervised pilot (months)

- 1,000–10,000 voters, in defined locations or with assisted kiosks.
- Independent observers, open threat model, public bug bounty.
- Parallel paper count and risk-limiting audit.
- Publish a full transparency report, including every incident.
- Measure coercion reports, accessibility, failure rates and cost per vote.

### Stage 2 — Legal mandate and certification (12–24+ months)

- Work with INEC, the National Assembly, parties, courts, observers and NDPA
  authorities on a lawful, limited scope.
- Certify identity integration, biometric liveness, accessibility and the tally
  protocol.
- Independent security audit and formal verification of the ballot-secrecy and
  verifiability claims.
- Define recount, dispute and remedy procedures before any real vote.

### Stage 3 — Limited production, if justified

- Consider remote voting only for narrowly defined groups or supervised
  locations, after Stages 0–2 succeed.
- Keep a paper or independently verifiable record and a meaningful audit trail.
- Never remove the ability to challenge and recount.

For 2027, the realistic and useful contribution of this project is **not** a
national remote ballot. It is a well-engineered pilot plus a verifiable
polling-unit results pipeline that can raise transparency without gambling the
election on an unproven remote channel.

---

## 9. Concrete engineering backlog (prioritised)

If the goal is to move toward a defensible pilot, do these in order:

1. Replace the single-node store and in-process limits (PostgreSQL, Redis,
   multiple workers, migrations, backups/restore drills).
2. Add staff MFA, separation of duties, and hardware-backed session keys.
3. Publish signed audit-log (and vote-ledger/result-sheet) checkpoints to
   independent witnesses; chaining and signed checkpoints now exist.
4. Integrate a real biometric matcher with liveness, plus device attestation.
5. Move officer/authority signing to an HSM or threshold scheme; document and
   rehearse the key ceremony.
6. Add cryptographic ballot secrecy: encrypted ballots, trustee decryption
   shares, proofs, and an independently verifiable tally.
7. Add coercion mitigation and receipt-freeness analysis; consider supervised
   kiosks for at-risk voters.
8. Build a public transparency log and observer tooling around signed checkpoints.
9. Add risk-limiting audit tooling and a paper/independent record.
10. Commission an external penetration test and publish the results.

Until items 1–10 are addressed and a legal mandate exists, the honest description
of this software is: **a pilot-ready prototype with strong result-sheet integrity
and an intentionally incomplete identity and ballot-secrecy model.**
