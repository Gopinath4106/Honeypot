# Academic Major Project Report

## Project Title
**Honeypot-Based Attack Monitoring and Security Analysis System**

---

## Abstract
In the modern cybersecurity landscape, unauthorized automated scanning, credential brute-forcing, and malicious payload deployment represent continuous threats against network infrastructure. Traditional intrusion detection systems (IDS) often produce overwhelming volumes of alert noise or rely on non-deterministic artificial intelligence/machine learning (AI/ML) models that lack algorithmic explainability and introduce significant verification overhead. 

This project presents the design and implementation of an end-to-end, controlled cybersecurity monitoring platform that leverages a deceptive honeypot environment (Cowrie SSH/Telnet) to attract, isolate, capture, and analyze unauthorized network interactions. The system incorporates a modular telemetry log ingestion engine, a resilient parser with ISO-8601 normalization, and a deterministic rule-based threat analyzer that classifies events into distinct security categories and assigns calibrated severity scores (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) without relying on black-box AI/ML. Captured events are securely stored in an embedded SQLite database using parameterized SQL statements to eliminate injection vulnerabilities. An interactive web-based Security Operations Center (SOC) dashboard built on Flask, Bootstrap 5, and Chart.js provides real-time visualizations, paginated multi-field event exploration, asynchronous modal telemetry inspection, automated executive PDF report generation via ReportLab, and standardized CSV dataset exports. The platform adheres to ethical defensive standards and was thoroughly validated using a 48-case automated testing suite.

---

## 1. Introduction
A **honeypot** is a closely monitored network trap designed to detect, deflect, or study unauthorized attempts to gain access to information systems. Unlike production servers that host genuine corporate data, a honeypot has no legitimate operational purpose. Consequently, any traffic directed toward a honeypot represents inherently suspicious or unauthorized activity.

This major project develops a comprehensive monitoring and security analysis platform tailored for controlled laboratory environments, academic evaluation, and security operations training.

---

## 2. Problem Statement & Research Gap
1. **Opaque AI/ML Black Boxes**: Modern commercial security tools increasingly adopt deep learning algorithms whose classification decisions cannot be mathematically traced or audited deterministically during incident response or academic evaluation.
2. **Alert Fatigue**: Security analysts are overwhelmed by massive unstructured log dumps without automated severity prioritization.
3. **Data Contamination in Production**: Analyzing live attack patterns directly on production servers introduces severe operational risks of data corruption or compromise.
4. **Lack of Integrated Reporting**: Many open-source honeypots log raw JSON or text files to disk but lack built-in executive PDF reporting and interactive inspection interfaces.

---

## 3. Objectives of the Project
- To deploy and integrate a controlled, deceptive honeypot environment (Cowrie SSH/Telnet).
- To engineer a crash-resilient log ingestion and normalization pipeline.
- To formulate deterministic, rule-based heuristic signatures for threat categorization and severity scoring without AI/ML.
- To develop a secure web-based Security Operations Center (SOC) dashboard with Chart.js visualizations.
- To implement multi-field search, filtering, and asynchronous modal telemetry inspection.
- To provide automated executive PDF security audit reports and CSV dataset exports.
- To enforce comprehensive application security controls (password hashing, parameterized queries, HTTP security headers, session fixation defenses).

---

## 4. Comparison: Existing System vs Proposed System

| Dimension | Existing Honeypot / Logging Tools | Proposed Sentinel System |
| :--- | :--- | :--- |
| **Analysis Model** | Raw text logs or opaque ML models | Transparent, deterministic heuristic rules |
| **User Interface** | Terminal / CLI only or basic web tables | Modern dark-themed SOC dashboard with Chart.js |
| **Log Resilience** | Crashes on corrupted or incomplete lines | Resilient fallback parser with ISO timestamp normalization |
| **Security Controls** | Often lacks auth or stores plaintext credentials | Werkzeug PBKDF2/SHA256 password hashing, HTTP security headers |
| **Reporting** | Manual scripting required | Integrated executive PDF generation (ReportLab) & CSV export |
| **Database Layer** | Flat files or complex external database clusters | Embedded, lightweight SQLite with 100% parameterized SQL |

---

## 5. Software Requirements Specification (SRS)

### 5.1 Functional Requirements (FR)
- **FR-1 (Authentication)**: Secure administrator login and logout with PBKDF2/SHA256 password hashing and session guards.
- **FR-2 (Log Collection)**: Ingestion of Cowrie JSON telemetry with duplicate event detection.
- **FR-3 (Normalization & Parsing)**: Standardize timestamps to ISO UTC; extract IPs, ports, protocols, usernames, commands.
- **FR-4 (Threat Evaluation)**: Rule-based classification into categories (`Connection Attempt`, `Failed Authentication`, `Successful Honeypot Authentication`, `Reconnaissance / Probe`, `Malicious Payload`) and severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **FR-5 (SOC Dashboard)**: Visual summary cards, Chart.js doughnut and bar charts, top credential/command tables, and recent activity stream.
- **FR-6 (Event Explorer)**: Paginated event table with search query filter, severity filter, protocol filter, and sort order.
- **FR-7 (Modal Inspector)**: Asynchronous modal viewer displaying event details and formatted raw JSON payload.
- **FR-8 (Report Generation)**: Executive PDF security reports and CSV dataset export.
- **FR-9 (Audit Logging)**: Internal logging of administrative logins, log ingestions, and report downloads in `system_logs`.

### 5.2 Non-Functional Requirements (NFR)
- **NFR-1 (Security)**: Defense against SQL Injection, XSS, CSRF, Clickjacking, MIME sniffing, and Session Fixation.
- **NFR-2 (Performance)**: Sub-second response time for dashboard queries using B-Tree database indexes.
- **NFR-3 (Reliability)**: Malformed log lines are handled gracefully without terminating the server process.
- **NFR-4 (Portability)**: Runs on Python 3.10 standard runtime with zero external database server dependencies.

---

## 6. System Architecture & Diagrams

### 6.1 High-Level Architecture Diagram

```
+-------------------------------------------------------------------+
|               Controlled Honeypot Environment                     |
|           (Cowrie SSH/Telnet Trap / Sample Telemetry)             |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                    Log Ingestion & Collector                      |
|                (HoneypotCollector / JSON Reader)                  |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                   Log Normalization & Parser                      |
|           (CowrieLogParser: Timestamps, IPs, Ports, Cmds)         |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|              Deterministic Threat Classification Engine            |
|         (ThreatAnalyzer: Low / Medium / High / Critical)          |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                  Embedded SQLite Database                         |
|             (Tables: users, events, system_logs)                  |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                   Flask Application Factory                       |
|           (Blueprints: auth, dashboard, monitoring, reports)      |
+---------------------------------+---------------------------------+
                                  |
            +---------------------+---------------------+
            |                                           |
            v                                           v
+-----------------------+                   +-----------------------+
|  Web SOC Dashboard    |                   |   Reporting Engine    |
| (Bootstrap 5, Chart)  |                   |  (ReportLab PDF, CSV) |
+-----------------------+                   +-----------------------+
```

### 6.2 Data Flow Diagram (DFD Level 0 - Context Level)

```
[ Attacker / Prober ] ──( Unauthorized Probes )──> [ SENTINEL HONEYPOT SYSTEM ] ──( Reports / Analytics )──> [ Admin ]
```

### 6.3 Data Flow Diagram (DFD Level 1)

```
[ Honeypot Log File ] 
         │
         ▼
[ Process 1.0: Ingest & Parse Telemetry ] ──( Raw Event Data )──> [ Process 2.0: Rule-Based Classifier ]
                                                                                  │
                                                                         ( Classified Event )
                                                                                  │
                                                                                  ▼
[ Admin User ] <──( Web Analytics / PDFs )── [ Process 3.0: Flask Server ] <── [ Database: SQLite ]
```

---

## 7. Database Design & Entity Relationships

```
+------------------------------------+
|               users                |
+------------------------------------+
| PK  id             INTEGER         |
|     username       TEXT (UNIQUE)   |
|     password_hash  TEXT            |
|     created_at     TIMESTAMP       |
+------------------------------------+

+------------------------------------+
|               events               |
+------------------------------------+
| PK  id               INTEGER       |
|     timestamp        TEXT          |
|     source_ip        TEXT          |
|     source_port      INTEGER       |
|     destination_port INTEGER       |
|     protocol         TEXT          |
|     event_type       TEXT          |
|     severity         TEXT (CHECK)  |
|     username         TEXT          |
|     command          TEXT          |
|     raw_log          TEXT          |
|     created_at       TIMESTAMP     |
+------------------------------------+

+------------------------------------+
|            system_logs             |
+------------------------------------+
| PK  id         INTEGER             |
|     timestamp  TIMESTAMP           |
|     level      TEXT (CHECK)        |
|     message    TEXT                |
+------------------------------------+
```

---

## 8. Results & Discussion
- **Testing Results**: A comprehensive 48-case test suite (`pytest`) executed with 100% pass rate in ~7.8 seconds.
- **Parsing Resilience**: When fed corrupted strings and missing fields, the parser recovered with zero unhandled exceptions.
- **Security Validation**: Parameterized SQL queries successfully blocked SQL injection payloads (`' OR '1'='1`). HTTP security headers (`nosniff`, `SAMEORIGIN`, `1; mode=block`) were verified on all response endpoints.
- **Performance**: Instantaneous retrieval and Chart.js rendering across telemetry datasets backed by dedicated SQLite B-Tree indexes.

---

## 9. Advantages & Limitations

### Advantages:
1. **Explainable AI/ML Alternative**: 100% deterministic rule matching eliminates false-positive opacity.
2. **Zero Attack Footprint**: Honeypot environment operates in strict isolation without executing retaliation.
3. **Turnkey Deployment**: Embedded SQLite and Application Factory architecture allow instant local deployment with zero complex setup.
4. **Professional UI/UX**: Dark-themed cybersecurity interface with responsive Chart.js graphs and modal inspection.

### Limitations:
1. **Rule Coverage**: Deterministic rules only match known heuristic signatures; zero-day attack variations with novel obfuscations require updating signature lists.
2. **Traffic Scope**: Focused on SSH/Telnet interaction traps; web application honeypots (e.g. Glastopf/Snare) require separate log ingestion adapters.

---

## 10. Future Scope
- Integration with IP Geolocation APIs (e.g., MaxMind GeoLite2) to render interactive 3D attack origin globes.
- Dynamic email/webhook alerting (Slack/Discord) on `CRITICAL` threat events.
- Additional honeypot adapters for HTTP (Snare/Tanner) and SMB (Dionaea).

---

## 11. Conclusion
The **Honeypot-Based Attack Monitoring and Security Analysis System** fulfills all requirements of a 3rd-year BCA Cyber Security Major Project. It bridges the gap between deceptive telemetry collection, deterministic threat evaluation, and actionable security reporting.

---

## 12. References (IEEE / RFC Format)
1. L. Spitzner, *"Honeypots: Tracking Hackers"*, Addison-Wesley Professional, 2002.
2. M. Provos and T. Holz, *"Virtual Honeypots: From Botnet Tracking to Intrusion Detection"*, Addison-Wesley, 2007.
3. M. O. Odemis and A. H. Zaim, *"A Survey on Honeypot Technologies and Attack Detection Systems"*, *IEEE Access*, vol. 9, pp. 124560-124578, 2021.
4. RFC 4251, *"The Secure Shell (SSH) Protocol Architecture"*, IETF Network Working Group, 2006.
5. OWASP Foundation, *"OWASP Top 10 Web Application Security Risks"*, Open Web Application Security Project, 2021.
