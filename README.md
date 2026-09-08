# 🍯 Honeypot-Based Attack Monitoring & Security Analysis System

A full-stack cybersecurity monitoring platform that collects **SSH/Telnet attack telemetry from the Cowrie honeypot**, analyzes suspicious activities using a **deterministic rule-based threat classification engine**, stores normalized security events in **SQLite**, and presents actionable intelligence through a modern **admin dashboard**.

The system is designed to demonstrate how honeypot telemetry can be transformed into structured security intelligence for **attack monitoring, incident analysis, threat classification, and security reporting**.

---

## 📌 Project Overview

Cybersecurity monitoring systems often generate large volumes of logs that can be difficult to analyze manually. Machine-learning-based systems can also introduce challenges related to explainability, training data, and computational requirements.

This project addresses these challenges by implementing a **transparent rule-based attack analysis pipeline**.

The system:

1. Captures or simulates SSH/Telnet attack activity through **Cowrie Honeypot**
2. Ingests raw JSON honeypot telemetry
3. Sanitizes and validates incoming log fields
4. Extracts relevant security information such as:

   * Source IP
   * Source and destination ports
   * Protocol
   * Username
   * Password
   * Commands
   * Event type
   * Timestamp
5. Applies deterministic security rules to classify attack activity
6. Assigns an appropriate **severity level**
7. Stores normalized events in an embedded **SQLite database**
8. Displays security intelligence through an **admin dashboard**
9. Provides filtering and event monitoring capabilities
10. Generates downloadable **PDF and CSV security reports**

---

## 🎯 Objectives

The primary objectives of the project are:

* To understand how honeypots can be used for cybersecurity monitoring
* To capture and analyze malicious SSH/Telnet activity
* To develop a centralized attack monitoring dashboard
* To classify attacks using explainable rule-based techniques
* To store honeypot telemetry in a structured database
* To provide security analysts with searchable event information
* To generate security audit reports
* To demonstrate secure web application development practices
* To develop a complete cybersecurity application combining backend, frontend, database, and security concepts

---

## 🏗️ System Architecture

```text
                   ┌─────────────────────┐
                   │   Attacker / Bot    │
                   └──────────┬──────────┘
                              │
                              │ SSH / Telnet
                              ▼
                   ┌─────────────────────┐
                   │   Cowrie Honeypot   │
                   │   SSH / Telnet      │
                   └──────────┬──────────┘
                              │
                              │ JSON Telemetry
                              ▼
                   ┌─────────────────────┐
                   │    Log Ingestion    │
                   │      Pipeline       │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Data Sanitization   │
                   │ & Validation        │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Rule-Based Threat   │
                   │ Classification      │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │      SQLite DB      │
                   │ Normalized Events   │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │    Flask Backend    │
                   │   REST / Web Routes │
                   └──────────┬──────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │       Admin Dashboard         │
              │                               │
              │ • Attack Statistics            │
              │ • Severity Indicators          │
              │ • Event Monitoring             │
              │ • Search & Filtering           │
              │ • Charts                       │
              └──────────────┬────────────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ PDF / CSV Reports   │
                  └─────────────────────┘
```

---

## ✨ Key Features

### 🔐 Secure Admin Authentication

The application provides a protected administrative interface with:

* Session-based authentication
* Password hashing using Werkzeug
* Protected dashboard routes
* Secure login/logout workflow

Passwords are never stored in plain text.

---

### 📊 Security Monitoring Dashboard

The dashboard provides a centralized view of honeypot activity.

It displays information such as:

* Total attack events
* Attack categories
* Severity levels
* Source IP addresses
* Authentication attempts
* Suspicious commands
* Protocol information
* Recent security events

---

### 🧠 Rule-Based Threat Classification

Instead of using a black-box machine-learning model, the project uses **deterministic security rules**.

This provides:

* Explainable decisions
* Predictable results
* Low computational overhead
* Easy debugging
* Easy modification of detection rules
* Suitability for academic demonstration

Example:

```text
Incoming Event
      │
      ▼
Authentication Failure?
      │
      ├── YES ──► Brute Force Analysis
      │
      └── NO
           │
           ▼
      Suspicious Command?
           │
           ├── YES ──► Command Injection / Shell Activity
           │
           └── NO
                │
                ▼
           Normal Event
```

---

### 🔎 Event Monitoring

Security events can be searched and filtered based on information such as:

* Source IP
* Attack type
* Severity
* Protocol
* Event type
* Date/time

This allows administrators to quickly identify suspicious activity.

---

### 📄 Security Reports

The application supports downloadable security reports.

#### CSV Reports

Useful for:

* Data analysis
* Spreadsheet processing
* External security analysis
* Archiving

#### PDF Reports

Generated using **ReportLab** and suitable for:

* Security audits
* Academic demonstrations
* Incident documentation
* Management reports

---

### 🛡️ Web Security

The application implements security-oriented HTTP headers to provide protection against common web threats.

Security measures include:

* XSS-related protection
* Clickjacking protection
* MIME sniffing protection
* Password hashing
* Session-based authentication
* Input validation
* Sanitization of log data

---

### 🧪 Automated Testing

The project includes a comprehensive automated test suite using **pytest**.

The test suite covers application functionality such as:

* Authentication
* Log ingestion
* Threat classification
* Database operations
* API/web routes
* Reporting functionality
* Security behavior

**Test Status:**

```text
48 test cases
100% passing
```

---

### ⚙️ Command-Line Tools

The application provides CLI commands for administrative tasks.

#### Create Admin

```bash
flask create-admin
```

#### Ingest Honeypot Logs

```bash
flask ingest-logs
```

These commands simplify administration and log processing.

---

# 🛠️ Technology Stack

| Layer                   | Technology                |
| ----------------------- | ------------------------- |
| Programming Language    | Python 3.9+               |
| Backend Framework       | Flask 2.3+                |
| Database                | SQLite                    |
| Frontend                | HTML5, CSS3, JavaScript   |
| UI Framework            | Bootstrap 5               |
| Data Visualization      | Chart.js                  |
| PDF Generation          | ReportLab 4.0+            |
| Honeypot                | Cowrie                    |
| Authentication          | Flask Sessions + Werkzeug |
| Password Hashing        | Werkzeug PBKDF2/SHA256    |
| Testing                 | pytest 7.4+               |
| Log Format              | JSON                      |
| Development Environment | VS Code / Antigravity IDE |

---

# 📂 Project Structure

```text
Honeypot/
│
├── app/
│   ├── __init__.py
│   ├── routes.py
│   ├── models.py
│   ├── analyzer.py
│   ├── database.py
│   ├── auth.py
│   └── reports.py
│
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   ├── events.html
│   └── ...
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── logs/
│   └── cowrie.json
│
├── tests/
│   ├── test_auth.py
│   ├── test_analyzer.py
│   ├── test_routes.py
│   ├── test_database.py
│   └── ...
│
├── reports/
│
├── requirements.txt
├── README.md
├── run.py
└── .gitignore
```

> The exact folder structure may vary depending on the final implementation.

---

# 🔄 Data Processing Pipeline

The system follows a structured security-event processing pipeline.

### Step 1 — Attack Generation

An attacker or simulated attacker interacts with the Cowrie honeypot using SSH/Telnet.

Examples include:

```text
SSH Login Attempts
Username Enumeration
Password Guessing
Command Execution
Shell Interaction
Suspicious Commands
```

### Step 2 — Honeypot Logging

Cowrie records the interaction as structured JSON telemetry.

### Step 3 — Log Ingestion

The application reads the raw JSON log files.

### Step 4 — Sanitization

Relevant fields are extracted and validated.

Example:

```text
Source IP
Username
Password
Port
Protocol
Command
Timestamp
Event Type
```

### Step 5 — Threat Classification

The rule-based engine evaluates the event and determines:

```text
Attack Category
Severity
Reason
```

### Step 6 — Database Storage

The normalized security event is stored in SQLite.

### Step 7 — Dashboard Visualization

The Flask backend provides the processed information to the web dashboard.

### Step 8 — Reporting

Administrators can export the collected security information as PDF or CSV reports.

---

# 🧠 Threat Classification

The threat analysis engine uses predefined rules to identify suspicious behavior.

Possible classifications include:

| Attack Category     | Description                               | Example                        |
| ------------------- | ----------------------------------------- | ------------------------------ |
| Brute Force         | Repeated authentication attempts          | Multiple failed SSH logins     |
| Credential Attack   | Attempts to use weak/common credentials   | Username/password guessing     |
| Command Execution   | Suspicious shell commands                 | System reconnaissance commands |
| Reconnaissance      | Attempts to gather system information     | Network/system enumeration     |
| Suspicious Activity | Potentially malicious behavior            | Unusual interaction patterns   |
| Normal Activity     | Activity that does not match attack rules | Valid/expected events          |

Severity can be assigned using levels such as:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

The classification is deterministic, meaning the same input event produces the same classification.

---

# 🗄️ Database

The application uses **SQLite** as an embedded database.

SQLite was selected because it provides:

* Zero configuration
* No separate database server
* Simple deployment
* Lightweight storage
* Easy development and testing
* Suitable for an academic security monitoring application

The database stores normalized security events instead of relying solely on raw honeypot logs.

Typical event information includes:

```text
Event ID
Timestamp
Source IP
Source Port
Destination Port
Protocol
Username
Password
Command
Attack Type
Severity
Event Type
```

---

# 🌐 Application Components

## Backend

The Flask backend handles:

* Authentication
* Routing
* Log ingestion
* Threat analysis
* Database operations
* Dashboard data
* Report generation
* API/web requests

---

## Frontend

The frontend uses:

* HTML5
* CSS3
* Bootstrap 5
* Vanilla JavaScript
* Chart.js

The dashboard is designed to be responsive and accessible from different screen sizes.

---

## Honeypot

**Cowrie** acts as the SSH/Telnet honeypot.

It provides a controlled environment where suspicious interactions can be captured without exposing an actual production system.

Cowrie telemetry becomes the primary source of attack-event data for the monitoring system.

---

# 🔌 Application Endpoints

The application provides web/API routes for functionality such as:

```text
/login
/logout
/dashboard
/events
/reports
/api/events
/api/statistics
```

> Endpoint names may differ depending on the final implementation.

---

# 📊 Dashboard Capabilities

The administrator can use the dashboard to:

* Monitor incoming attacks
* View attack statistics
* Identify high-severity events
* Search security events
* Filter events
* Analyze source IP addresses
* Review authentication attempts
* Inspect suspicious commands
* Generate security reports

---

# 🚀 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/Gopinath4106/Honeypot.git
```

Navigate into the project:

```bash
cd Honeypot
```

---

## 2. Create a Virtual Environment

Windows:

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Configure Environment Variables

Create a `.env` file if required by the application.

Example:

```env
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///honeypot.db
```

> Never commit real passwords, secret keys, API keys, or sensitive credentials to GitHub.

---

## 5. Initialize the Application

Run the application using the project's configured entry point.

Example:

```bash
python run.py
```

or:

```bash
flask run
```

---

## 6. Create an Administrator

```bash
flask create-admin
```

Follow the prompts to create the administrator account.

---

## 7. Ingest Honeypot Logs

Place the Cowrie JSON telemetry in the configured log directory and run:

```bash
flask ingest-logs
```

The application will process the logs and store normalized events in SQLite.

---

# 🧪 Running Tests

Install the testing dependencies:

```bash
pip install pytest
```

Run the complete test suite:

```bash
pytest
```

Expected result:

```text
48 tests passed
```

---

# 📑 Reporting

The reporting module allows administrators to export security events.

### CSV

CSV reports can be used for:

* Excel analysis
* Data processing
* Security investigation
* Long-term archiving

### PDF

PDF reports provide a structured security summary containing relevant attack information.

Report generation is implemented using:

```text
ReportLab
```

---

# 🔒 Security Considerations

This project demonstrates several secure development practices:

* Password hashing instead of plaintext storage
* Session-based authentication
* Input validation
* Log sanitization
* Security-related HTTP headers
* Protected administrative routes
* Separation of raw telemetry and normalized records
* Controlled honeypot environment

### Important

This project is intended for **educational, research, and controlled cybersecurity testing purposes**.

The honeypot should be deployed in an isolated environment and should not be used to intentionally expose production systems or sensitive infrastructure.

---

# 🎓 Academic Context

**Course:** BCA — Cyber Security
**Project Type:** Major Project
**Academic Level:** 3rd Year

### Focus Areas

* Honeypot Technology
* Cyber Attack Monitoring
* Log Analysis
* Threat Detection
* Rule-Based Classification
* Incident Monitoring
* Web Application Security
* Authentication Security
* Database Management
* Security Reporting

---

# 📚 Learning Outcomes

Through this project, the following concepts are demonstrated:

* Designing a full-stack cybersecurity application
* Working with honeypot technologies
* Processing security logs
* Building a Flask backend
* Designing web dashboards
* Working with SQLite databases
* Implementing authentication
* Developing deterministic threat-analysis rules
* Generating security reports
* Writing automated tests
* Applying secure web-development practices

---

# 🔮 Future Enhancements

Possible future improvements include:

* Machine-learning-based anomaly detection
* IP reputation integration
* GeoIP visualization
* Email/SMS security alerts
* Real-time WebSocket telemetry
* Advanced attack correlation
* Threat intelligence integration
* Docker deployment
* Multi-user role management
* SIEM integration
* Attack trend prediction
* Automated incident response

---

# 📸 Screenshots

Add screenshots of your application here.

### Login

```text
Add login screenshot here
```

### Security Dashboard

```text
Add dashboard screenshot here
```

### Attack Events

```text
Add event-monitoring screenshot here
```

### Reports

```text
Add PDF/report screenshot here
```

---

# 👨‍💻 Author

**Gopinath**

BCA — Cyber Security

### Project

**Honeypot-Based Attack Monitoring & Security Analysis System**

---

# ⭐ Project Highlights

```text
🍯 Cowrie Honeypot
🐍 Python + Flask Backend
🧠 Rule-Based Threat Classification
🗄️ SQLite Database
📊 Security Monitoring Dashboard
📄 PDF & CSV Reporting
🔐 Secure Authentication
🛡️ Web Security Headers
🧪 Automated Testing
```

---

# 📄 License

This project is developed for **academic and educational purposes**.

You may adapt and extend the project for learning, research, and controlled cybersecurity experimentation.

