🍯 Honeypot-Based Attack Monitoring & Security Analysis System
A full-stack web application that ingests Cowrie honeypot telemetry, classifies attack events using deterministic rule-based analysis, and presents live security intelligence through an admin dashboard with PDF/CSV reporting.

🔍 Overview
Traditional intrusion detection systems often generate high volumes of noise or rely on opaque ML models that are difficult to explain in academic and low-latency environments. This system solves that by:

Simulating or capturing real SSH/Telnet authentication attempts via a Cowrie honeypot
Ingesting raw JSON logs and sanitizing fields (Source IP, Ports, Protocol, Credentials, Commands)
Applying transparent, deterministic classification rules to assign attack categories and severity levels
Storing normalized records in an embedded SQLite database
Serving an admin dashboard with live telemetry indicators, filtering, and downloadable PDF/CSV reports
✨ Key Features
Feature	Description
🔐 Secure Admin Auth	Session-based login with Werkzeug password hashing
📊 Live Dashboard	Real-time attack telemetry with severity indicators
🧠 Rule-Based Analyzer	Deterministic threat classification (no black-box ML)
🔎 Event Monitoring	Filterable event log with IP, severity & type search
📄 PDF/CSV Reports	Downloadable security audit reports via ReportLab
🛡️ Security Headers	XSS, clickjacking & sniffing protection headers
🧪 Full Test Suite	48-case pytest suite with 100% pass rate
⚙️ CLI Commands	create-admin and ingest-logs CLI tools
🛠️ Tech Stack
Layer	Technology
Backend	Python 3.9+, Flask 2.3+
Database	SQLite (embedded, zero-config)
Frontend	HTML5, CSS3, Vanilla JavaScript, Chart.js, Bootstrap 5
PDF Reports	ReportLab 4.0+
Honeypot	Cowrie (SSH/Telnet)
Auth	Werkzeug PBKDF2/SHA256 password hashing
Testing	pytest 7.4+
Academic Context: 3rd Year BCA — Cyber Security Major Project Focus Areas: Honeypots · Log Analysis · Incident Monitoring · Rule-Based Threat Classification · Web Application Security
