# Honeypot-Based Attack Monitoring and Security Analysis System

An academic major project for 3rd-Year BCA Cyber Security. A controlled cybersecurity monitoring platform that captures, parses, categorizes, visualizes, and reports on unauthorized interactions recorded by an isolated honeypot (Cowrie SSH/Telnet).

---

## 🎯 Project Objectives

1. **Controlled Telemetry**: Deploy an isolated honeypot environment to record unauthorized connection attempts safely.
2. **Deterministic Analysis**: Perform rule-based classification and severity scoring without relying on non-deterministic AI/ML black boxes.
3. **Interactive SOC Dashboard**: Provide security personnel with real-time statistics, attack event grids, and visual trend charts.
4. **Security Reporting**: Generate automated PDF audit reports and CSV datasets for compliance and incident response analysis.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.10.x / Flask
- **Database**: SQLite with parameterized queries
- **Frontend**: HTML5, Vanilla CSS3 (Custom Dark Cybersecurity SOC Theme), Bootstrap 5.3
- **Visualization**: Chart.js
- **Reporting**: ReportLab (PDF) & CSV
- **Honeypot Support**: Cowrie SSH/Telnet with offline Sample Mode fallback
- **Testing**: Pytest

---

## 📁 Directory Structure

```text
honeypot-attack-monitor/
├── app.py                  # Application factory and main entry point
├── config.py               # Environment configuration settings
├── requirements.txt        # Pinned Python dependencies
├── pytest.ini              # Pytest configuration
├── .gitignore              # Git exclusions for Python/secrets
├── .env.example            # Environment variables template
├── database/               # Database connection and SQL schemas
├── honeypot/               # Log collector, parser, and sample logs
│   └── sample_logs/        # Offline sample honeypot logs
├── routes/                 # Flask route blueprints (auth, dashboard, monitoring, reports)
├── services/               # Core business and reporting logic
├── static/                 # Static CSS, JS, and image assets
├── templates/              # Jinja2 HTML templates
├── reports/                # Output directory for generated PDF reports
├── docs/                   # Academic documentation and development logs
└── tests/                  # Automated unit and integration test suites
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10.x installed.

### 2. Setup Virtual Environment & Install Dependencies
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Initialize Database & Seed Development Admin Account
```powershell
# Initialize SQLite schema
flask init-db

# Create an administrator account (syntax: flask create-admin <user> <pass>)
flask create-admin admin admin123

# Ingest sample honeypot attack telemetry
flask ingest-logs
```

### 4. Run Automated Test Suite (48 Test Cases)
```powershell
pytest -v
```

### 5. Launch the Development Server
```powershell
python app.py
```
Open your web browser at: `http://127.0.0.1:5000`
- **Default Credentials**: `admin` / `admin123`

---

## 📚 Complete Project Documentation

| Document | Description |
| :--- | :--- |
| [`docs/academic_project_report.md`](file:///e:/project/docs/academic_project_report.md) | **Full Academic Major Project Report** (Abstract, SRS, DFD, Architecture, Results, References) |
| [`docs/viva_preparation.md`](file:///e:/project/docs/viva_preparation.md) | **30+ Technical Viva Questions & Answers** for Project Reviews & Interviews |
| [`docs/testing.md`](file:///e:/project/docs/testing.md) | **Testing Plan & Matrix** (48 Automated Tests + 11 Manual Test Cases) |
| [`docs/deployment.md`](file:///e:/project/docs/deployment.md) | **Deployment Runbook** (Cowrie SSH Honeypot Lab Setup & Log Ingestion) |
| [`docs/user_manual.md`](file:///e:/project/docs/user_manual.md) | **Operator Manual** (Dashboard, Live Explorer, Modal Inspector, PDF Reporting) |
| [`docs/database.md`](file:///e:/project/docs/database.md) | **Database Design** (ER Diagram, Data Dictionary, SQL Parameterization Standard) |
| [`docs/project_overview.md`](file:///e:/project/docs/project_overview.md) | **Project Overview & Objectives** |
| [`docs/architecture.md`](file:///e:/project/docs/architecture.md) | **System Architecture & Dataflow** |
| [`docs/development_log.md`](file:///e:/project/docs/development_log.md) | **SDLC Milestone Tracking Log** |

---

## 🔒 Security Principles
- **Strict Isolation**: Honeypot interactions are kept inside an isolated local network trap.
- **Defensive Focus**: No automated retaliation or active offensive scanning.
- **Safe SQL**: 100% parameterized queries eliminating SQL injection vulnerabilities.
- **Secure Password Storage**: Werkzeug PBKDF2/SHA-256 cryptographic password hashing.
- **HTTP Security Headers**: Enforces `nosniff`, `SAMEORIGIN`, and browser XSS filtering.
