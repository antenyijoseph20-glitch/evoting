# Nigeria Secure E-Voting Platform

A secure, audit-oriented electronic voting platform prototype designed to model the core stages of a modern election workflow: voter registration, identity verification, OTP-based authentication, ballot issuance, vote casting, receipt verification, and tally aggregation.

This project is built as a technical demonstration and governance-focused engineering prototype for digital voting workflows. It is intended to support research, review, and validation of secure election-system design principles. It is not, by itself, a production-grade national election system without additional government-backed identity integration, telecom infrastructure, legal framework compliance, and hardened operational deployment controls.

---


## Overview

This repository focuses on the design of a trustworthy digital voting architecture with emphasis on:

- voter identity validation workflows
- secure ballot issuance
- session-based authorization
- receipt verification
- auditability and traceability
- election tally aggregation
- administrative oversight and monitoring

The system is structured to reflect the responsibilities expected in a high-trust civic technology environment, where transparency, accountability, and system integrity are critical.

---

## National Interest and Governance Context

The project is framed for environments where public trust and electoral integrity are essential. In such settings, a voting system must not only demonstrate technical capability but also show alignment with:

- verifiability and accountability
- secure identity confirmation
- operational governance
- audit trail integrity
- procedural transparency
- independent oversight
- compliance with legal and institutional requirements

This repository demonstrates strong prototype-level design principles for these objectives, but it does not yet represent a complete national election deployment model.

---

## Core Features

- Voter registration and validation flow
- NIN/VIN-based identity logic
- OTP authentication flow
- Biometric verification support
- Ballot issuance and assignment
- Vote casting and receipt generation
- Receipt authenticity verification
- Audit log and integrity checks
- Tally and result aggregation
- Administrative dashboard monitoring
- SQLite-backed local data store
- Docker-based deployment support
- FastAPI-based service structure

---

## Architecture

The project is organized around modular components, including:

- authentication and identity validation
- ballot security and receipt generation
- voting logic engine
- audit verification and integrity checks
- admin monitoring and dashboard logic
- API layer for client and system integration
- configuration and security controls

This structure supports maintainability and allows the system to be reviewed as an engineering model rather than a monolithic application.

---

## Technology Stack

- Python 3.11+
- FastAPI
- SQLite
- Pydantic
- OpenCV
- pytest
- Docker / Docker Compose
- Uvicorn

---

## Repository Structure

```text
evoting/
├── .github/
│   └── workflows/
│       └── ci.yml
├── .gitignore
├── Dockerfile
├── README.md
├── admin_dashboard.py
├── api_main.py
├── auth_module.py
├── ballot_security.py
├── biometric_otp_module.py
├── check_audit.py
├── config.py
├── crypto_engine.py
├── docker-compose.yml
├── election_engine.py
├── election_workflow.py
├── haarcascade_eye_tree_eyeglasses.xml
├── haarcascade_frontalface_default.xml
├── index.html
├── main.py
├── pytest.ini
├── requirements.txt
├── requirements-lock.txt
├── run_tests.py
├── run_tests.sh
├── schema.sql
├── security_flow.py
├── security_hardening.py
├── server.log
├── session_manager.py
├── simulate_voters.py
├── static/
├── test_client.py
├── test_evoting.py
├── test_hash_chain_tamper.py
├── test_main.py
├── test_receipt_verification.py
├── test_security_guards.py
├── test_tally_and_audit.py
├── voting_engine.py
└── ...
