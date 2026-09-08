# ðŸ¯ Honeypot-Based Attack Monitoring & Security Analysis System

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-2.3+-000000?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
  <img src="https://img.shields.io/badge/Cowrie-Honeypot-FF6B35?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

<p align="center">
  A full-stack web application that ingests Cowrie honeypot telemetry, classifies attack events using deterministic rule-based analysis, and presents live security intelligence through an admin dashboard with PDF/CSV reporting.
</p>

---

## ðŸ“– Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [Configuration](#ï¸-configuration)
- [Usage](#-usage)
- [Threat Classification](#-threat-classification)
- [Database Schema](#-database-schema)
- [Testing](#-testing)
- [API Endpoints](#-api-endpoints)
- [Screenshots](#-screenshots)
- [Academic Context](#-academic-context)

---

## ðŸ” Overview

Traditional intrusion detection systems often generate high volumes of noise or rely on opaque ML models that are difficult to explain in academic and low-latency environments. This system solves that by:

1. **Simulating or capturing** real SSH/Telnet authentication attempts via a Cowrie honeypot
2. **Ingesting raw JSON logs** and sanitizing fields (Source IP, Ports, Protocol, Credentials, Commands)
3. **Applying transparent, deterministic classification rules** to assign attack categories and severity levels
4. **Storing normalized records** in an embedded SQLite database
5. **Serving an admin dashboard** with live telemetry indicators, filtering, and downloadable PDF/CSV reports

---

## âœ¨ Features

| Feature | Description |
|---|---|
| ðŸ” **Secure Admin Auth** | Session-based login with Werkzeug password hashing |
| ðŸ“Š **Live Dashboard** | Real-time attack telemetry with severity indicators |
| ðŸ§  **Rule-Based Analyzer** | Deterministic threat classification (no black-box ML) |
| ðŸ”Ž **Event Monitoring** | Filterable event log with IP, severity & type search |
| ðŸ“„ **PDF/CSV Reports** | Downloadable security audit reports via ReportLab |
| ðŸ—„ï¸ **SQLite Database** | Lightweight embedded DB with optimized indexes |
| ðŸ›¡ï¸ **Security Headers** | XSS, clickjacking & sniffing protection headers |
| ðŸ¥ **Health Check API** | `/health` endpoint for uptime monitoring |
| ðŸ§ª **Full Test Suite** | 10+ pytest test modules with in-memory DB |
| âš™ï¸ **CLI Commands** | `create-admin` and `ingest-logs` CLI tools |

---

## ðŸ—ï¸ Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                  Cowrie Honeypot                     â”‚
â”‚         (SSH/Telnet Deception Layer)                 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                       â”‚ JSON Logs
                       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚              Log Ingestion Pipeline                  â”‚
â”‚   collector.py â†’ log_parser.py â†’ analyzer.py        â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                       â”‚ Normalized Events
                       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚              SQLite Database                         â”‚
â”‚        events | users | system_logs                 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                       â”‚
                       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚              Flask Web Application                   â”‚
â”‚  Dashboard | Monitoring | Reports | Auth | API       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## ðŸ“ Project Structure

```
honeypot-monitor/
â”‚
â”œâ”€â”€ app.py                          # Flask application factory
â”œâ”€â”€ config.py                       # Environment configurations
â”œâ”€â”€ requirements.txt                # Python dependencies
â”œâ”€â”€ pytest.ini                      # Test runner configuration
â”œâ”€â”€ verify_system.py                # System health verification script
â”‚
â”œâ”€â”€ honeypot/                       # Core honeypot engine
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ analyzer.py                 # Deterministic threat classifier
â”‚   â”œâ”€â”€ collector.py                # Log ingestion CLI & pipeline
â”‚   â”œâ”€â”€ log_parser.py               # Cowrie JSON log parser
â”‚   â””â”€â”€ sample_logs/
â”‚       â””â”€â”€ cowrie.sample.json      # Sample honeypot telemetry
â”‚
â”œâ”€â”€ routes/                         # Flask blueprints
â”‚   â”œâ”€â”€ auth.py                     # Login / logout / session
â”‚   â”œâ”€â”€ dashboard.py                # Dashboard & statistics
â”‚   â”œâ”€â”€ monitoring.py               # Live event monitoring
â”‚   â””â”€â”€ reports.py                  # PDF / CSV report generation
â”‚
â”œâ”€â”€ services/                       # Business logic layer
â”‚   â”œâ”€â”€ analysis_service.py         # Attack analysis queries
â”‚   â”œâ”€â”€ report_service.py           # PDF/CSV generation service
â”‚   â””â”€â”€ statistics_service.py      # Dashboard metric aggregations
â”‚
â”œâ”€â”€ database/
â”‚   â”œâ”€â”€ db.py                       # SQLite connection & lifecycle
â”‚   â””â”€â”€ schema.sql                  # Database schema definition
â”‚
â”œâ”€â”€ templates/                      # Jinja2 HTML templates
â”‚   â”œâ”€â”€ base.html
â”‚   â”œâ”€â”€ dashboard.html
â”‚   â”œâ”€â”€ monitoring.html
â”‚   â”œâ”€â”€ reports.html
â”‚   â”œâ”€â”€ login.html
â”‚   â””â”€â”€ error.html
â”‚
â”œâ”€â”€ static/
â”‚   â”œâ”€â”€ css/style.css               # Application styles
â”‚   â””â”€â”€ js/
â”‚       â”œâ”€â”€ dashboard.js            # Dashboard charts & live refresh
â”‚       â””â”€â”€ monitoring.js           # Event table & filters
â”‚
â”œâ”€â”€ tests/                          # Pytest test suite
â”‚   â”œâ”€â”€ conftest.py
â”‚   â”œâ”€â”€ test_analyzer.py
â”‚   â”œâ”€â”€ test_app.py
â”‚   â”œâ”€â”€ test_auth.py
â”‚   â”œâ”€â”€ test_collector.py
â”‚   â”œâ”€â”€ test_dashboard.py
â”‚   â”œâ”€â”€ test_database.py
â”‚   â”œâ”€â”€ test_monitoring.py
â”‚   â”œâ”€â”€ test_parser.py
â”‚   â””â”€â”€ test_reports.py
â”‚
â”œâ”€â”€ docs/                           # Documentation
â”‚   â”œâ”€â”€ project_overview.md
â”‚   â”œâ”€â”€ architecture.md
â”‚   â”œâ”€â”€ database.md
â”‚   â”œâ”€â”€ deployment.md
â”‚   â”œâ”€â”€ testing.md
â”‚   â”œâ”€â”€ user_manual.md
â”‚   â”œâ”€â”€ development_log.md
â”‚   â”œâ”€â”€ academic_project_report.md
â”‚   â””â”€â”€ viva_preparation.md
â”‚
â””â”€â”€ reports/                        # Generated report output directory
```

---

## ðŸ› ï¸ Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.9+, Flask 2.3+ |
| **Database** | SQLite (embedded, zero-config) |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **PDF Reports** | ReportLab 4.0+ |
| **Honeypot** | Cowrie (SSH/Telnet) â€” sample mode or real integration |
| **Auth** | Werkzeug PBKDF2 password hashing |
| **Testing** | pytest 7.4+ |
| **Config** | python-dotenv |

---

## ðŸš€ Getting Started

### Prerequisites

- Python **3.9+**
- pip

### 1. Clone the repository

```bash
git clone https://github.com/Gopinath4106/Honeypot.git
cd Honeypot
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up environment variables

```bash
cp .env.example .env
# Edit .env with your preferred settings
```

### 5. Initialize the database

```bash
flask --app app db-init
# Or it initializes automatically on first run
```

### 6. Create an admin user

```bash
flask --app app create-admin
```

### 7. Run the application

```bash
python app.py
```

Open your browser at **http://127.0.0.1:5000**

---

## âš™ï¸ Configuration

Configuration is managed via environment variables (`.env` file):

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `dev-insecure-key...` | Flask session signing key |
| `DATABASE_PATH` | `instance/database.db` | Path to SQLite database |
| `HONEYPOT_MODE` | `sample` | `sample` (offline) or `real` (live Cowrie) |
| `HONEYPOT_LOG_PATH` | `honeypot/sample_logs/cowrie.sample.json` | Path to Cowrie log file |
| `REPORTS_DIR` | `reports/` | Directory for generated reports |
| `FLASK_ENV` | `development` | `development`, `testing`, or `production` |

**Example `.env`:**

```env
SECRET_KEY=your-very-secret-key-here
FLASK_ENV=development
HONEYPOT_MODE=sample
DATABASE_PATH=instance/database.db
```

---

## ðŸ“‹ Usage

### Ingest Honeypot Logs

```bash
flask --app app ingest-logs
```

This parses the configured Cowrie JSON log file, classifies each event, and stores results in the database.

### Access the Dashboard

1. Navigate to `http://127.0.0.1:5000`
2. Log in with your admin credentials
3. View live attack statistics, severity distribution, and top attacking IPs

### Generate Reports

- Go to the **Reports** section in the dashboard
- Download PDF or CSV security audit reports

---

## ðŸ§  Threat Classification

The `ThreatAnalyzer` uses **deterministic rule-based pattern matching** â€” no black-box ML models.

### Severity Levels

| Level | Description |
|---|---|
| ðŸŸ¢ `LOW` | Connection attempts, session lifecycle events |
| ðŸŸ¡ `MEDIUM` | Failed authentication, reconnaissance commands |
| ðŸŸ  `HIGH` | Successful honeypot logins, arbitrary command execution |
| ðŸ”´ `CRITICAL` | Malicious payloads: reverse shells, downloaders, privilege escalation |

### Attack Categories

- **Connection Attempt** â€” TCP handshake to honeypot listener
- **Failed Authentication** â€” Brute-force credential probing
- **Successful Honeypot Authentication** â€” Attacker gained shell access
- **Reconnaissance / Probe** â€” `whoami`, `uname`, `id`, `ps`, `netstat`, etc.
- **Command Execution** â€” Arbitrary shell commands
- **Malicious Payload / Exploit Attempt** â€” Reverse shells, miners, fork bombs, etc.
- **Suspicious Interaction** â€” TCP tunneling, port forwarding attempts
- **Session Lifecycle** â€” Session open/close events

### Critical Command Signatures (sample)

```
curl ... | bash         # Remote code execution
wget ... | bash         # Remote code execution
rm -rf /                # Destructive wipe
/etc/shadow             # Credential file access
nc -e /bin/bash         # Netcat reverse shell
bash -i >&              # Interactive reverse shell
chmod 777 /tmp          # Temp directory exploitation
:(){ :|:& };:           # Fork bomb
```

---

## ðŸ—„ï¸ Database Schema

```sql
-- Attack Events
CREATE TABLE events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    source_port     INTEGER,
    destination_port INTEGER,
    protocol        TEXT DEFAULT 'ssh',
    event_type      TEXT NOT NULL,
    severity        TEXT CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    username        TEXT,
    command         TEXT,
    raw_log         TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Admin Users
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- System / Audit Logs
CREATE TABLE system_logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    level     TEXT CHECK (level IN ('INFO','WARNING','ERROR','SECURITY')),
    message   TEXT NOT NULL
);
```

---

## ðŸ§ª Testing

Run the full test suite:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

Run a specific module:

```bash
pytest tests/test_analyzer.py -v
```

Tests use an **in-memory SQLite database** â€” no test data persists to disk.

**Test coverage includes:**
- `test_analyzer.py` â€” Threat classification rules
- `test_parser.py` â€” Cowrie log parsing
- `test_collector.py` â€” Log ingestion pipeline
- `test_auth.py` â€” Authentication flows
- `test_dashboard.py` â€” Dashboard routes & metrics
- `test_monitoring.py` â€” Event monitoring & filters
- `test_reports.py` â€” PDF/CSV report generation
- `test_database.py` â€” Database lifecycle
- `test_app.py` â€” Application factory & health check

---

## ðŸŒ API Endpoints

| Method | Route | Description |
|---|---|---|
| `GET` | `/health` | System health check (JSON) |
| `GET` | `/` | Redirect to dashboard |
| `GET/POST` | `/login` | Admin login |
| `GET` | `/logout` | Admin logout |
| `GET` | `/dashboard` | Main analytics dashboard |
| `GET` | `/monitoring` | Live event monitoring table |
| `GET` | `/monitoring/api/events` | Events JSON API (filterable) |
| `GET` | `/reports` | Reports page |
| `GET` | `/reports/download/pdf` | Download PDF security report |
| `GET` | `/reports/download/csv` | Download CSV event export |

---

## ðŸ“š Academic Context

> **Level:** 3rd Year BCA â€” Cyber Security Major Project  
> **Focus Areas:** Honeypots Â· Log Analysis Â· Incident Monitoring Â· Rule-Based Threat Classification Â· Web Application Security

This project demonstrates:
- End-to-end **telemetry pipeline** design
- **Transparent, explainable** security classification (no ML black boxes)
- Secure web application development (session management, security headers, input validation)
- Proper software engineering practices (modular blueprints, factory pattern, test coverage)

---

## ðŸ“œ License

This project is licensed under the **MIT License** â€” see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with â¤ï¸ by <a href="https://github.com/Gopinath4106">Gopinath4106</a>
</p>
