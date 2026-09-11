# TempleGo 💳⚡

**TempleGo** is a lightweight, high-performance Point of Sale (POS), utility management, and financial ledger backend application built from scratch in **Go (Golang)**. It features atomic SQLite persistence, robust transaction handling, audit logging, and a real-time responsive web dashboard.

---

## 🚀 Key Features

* **Atomic Transaction Processing:** Guarantees ACID compliance for all balance updates, debits, credits, and utility payments.
* **Transaction Reversal Engine:** Instantly negates erroneous transactions and logs audit trails securely.
* **Utility & Airtime Billing:** Supports processing simulated payments for Airtime, Data subscriptions, and Electricity (NEPA/Disco).
* **Comprehensive Audit Trail:** Tracks every transaction type, amount, timestamp, and account action.
* **Thread-Safe Concurrency:** Fully tested under high concurrency workloads to prevent race conditions.
* **Embedded Web Dashboard:** A clean, responsive terminal hub interface served directly by the backend.

---

## 🛠️ Tech Stack

* **Language:** Go (Golang) 1.24+
* **Database:** SQLite (`modernc.org/sqlite` - pure Go implementation)
* **Frontend:** HTML5, CSS3, Vanilla JavaScript (Grid layout)
* **Testing:** Go `net/http/httptest`, `sync` wait groups, and built-in race detector (`-race`)

---

## 📁 Project Structure

```text
templeGo/
├── db.go            # Database layer, schema initialization, and store methods
├── db_test.go       # Unit tests for data store operations
├── main.go          # HTTP server, REST API endpoints, and configuration
├── main_test.go     # HTTP integration test suite
├── static/
│   └── index.html   # Terminal Hub frontend dashboard
├── go.mod           # Go module definition
└── README.md        # Project documentation
