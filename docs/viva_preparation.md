# Master Viva & Technical Interview Preparation Guide

A comprehensive question-and-answer guide designed for your 3rd-Year Major Project Viva, Project Review Committee, and Cybersecurity Job Interviews.

---

## 🛡️ SECTION 1: Honeypot & Cybersecurity Core Concepts

### Q1. What is a Honeypot?
**Answer:** A honeypot is a controlled, deceptive security resource designed to be probed, attacked, or compromised. It has no legitimate production purpose, meaning any incoming traffic is by definition unauthorized or malicious.

### Q2. What type of honeypot does this project use?
**Answer:** This project uses **Cowrie**, which is a **medium-to-high interaction** SSH and Telnet honeypot. It mimics an authentic Linux shell environment, traps attackers, and records their credentials, shell commands, and uploaded payloads into structured JSON logs.

### Q3. What is the difference between Low, Medium, and High-Interaction Honeypots?
**Answer:**
- **Low-Interaction**: Emulates only basic network banners/handshakes (e.g. listening on port 22 and returning an SSH string). It is very safe but collects minimal attacker behavior.
- **Medium-Interaction**: Emulates interactive protocols and partial command responses (e.g. Cowrie simulating bash commands without giving real root access).
- **High-Interaction**: Uses real operating systems and virtual machines. Captures full attack lifecycles but carries the risk of the attacker using the trapped system to pivot if not strictly isolated.

### Q4. Why is Cowrie optimal for this academic project?
**Answer:** Cowrie provides an ideal balance: it allows attackers to execute shell commands (`uname`, `cat /etc/passwd`, `wget`) inside an emulated sandbox, captures all telemetry in real-time JSON format, but prevents attackers from breaking out into real production systems.

### Q5. What is the difference between a Honeypot and an Intrusion Detection System (IDS)?
**Answer:** An IDS monitors legitimate production network traffic to spot anomalies, which often leads to false alarms. A honeypot is a dedicated trap—because it has no valid users, any traffic it receives is inherently malicious, resulting in virtually zero false positives.

### Q6. Is honeypot monitoring considered ethical and legal?
**Answer:** Yes, as long as it operates **passively in a controlled environment**. Our system only observes and records traffic sent to our trap; it **never** launches retaliatory strikes or unauthorized scans against external systems.

---

## ⚙️ SECTION 2: Rule-Based Analysis vs AI/ML

### Q7. Why did you choose Deterministic Rule-Based Analysis instead of AI/Machine Learning?
**Answer:**
1. **Algorithmic Explainability**: Rule-based signatures allow us to explain exactly why a command like `cat /etc/shadow` was marked `CRITICAL`. AI/ML models operate as "black boxes" where decisions cannot be easily audited.
2. **Zero Latency**: Heuristics evaluate signatures in microseconds with zero GPU or heavy framework dependencies.
3. **Deterministic Consistency**: In academic evaluations and incident response, identical inputs always produce identical, verifiable threat scores.

### Q8. What severity levels exist in your system and how are they assigned?
**Answer:**
- **`LOW`**: TCP handshakes, client SSH banners, session disconnects.
- **`MEDIUM`**: Single failed password attempts, host reconnaissance commands (`uname -a`, `whoami`, `id`, `ifconfig`, `uptime`).
- **`HIGH`**: Successful authentication into the honeypot trap, arbitrary shell commands.
- **`CRITICAL`**: Dangerous exploit payloads, password file dumping (`cat /etc/shadow`), reverse shells (`nc -e`, `/dev/tcp`), cryptocurrency miner droppers (`wget ... miner`), and log wipers (`rm -rf`, `history -c`).

### Q9. How do you detect credential brute-forcing?
**Answer:** The parser and statistics service group failed login events (`cowrie.login.failed`) by the source IP address and timestamp window to track repeated password guessing patterns.

### Q10. How does the system handle command execution telemetry?
**Answer:** The `ThreatAnalyzer` extracts the raw shell command string and runs regex pattern matching against known malicious payload signatures and reconnaissance heuristics.

### Q11. What is the difference between "Observed Telemetry" and "Confirmed Real Attack"?
**Answer:** Observed telemetry refers to the exact bytes recorded inside our controlled trap (e.g. an automated bot guessing `root/123456`). A confirmed real attack implies a targeted breach of production infrastructure. We clearly distinguish honeypot telemetry in our reports.

---

## 🐍 SECTION 3: Python, Flask & Backend Architecture

### Q12. Why did you use Flask instead of Django?
**Answer:** Flask is lightweight, modular, and unopinionated. It gave us complete granular control over our security architecture, database lifecycle hooks, session security, and blueprint routing without the unnecessary overhead of Django's default ORM and monolithic admin interface.

### Q13. What is the Application Factory pattern (`create_app`)?
**Answer:** Instead of creating a global app object, `create_app()` instantiates and configures a new Flask app instance dynamically. This enables clean environment switching (`development`, `testing`, `production`) and isolated automated testing fixtures.

### Q14. What are Flask Blueprints and which ones did you create?
**Answer:** Blueprints modularize route handlers into distinct functional areas:
1. `auth_bp` (`/auth`): Login, logout, session guards.
2. `dashboard_bp` (`/`): SOC dashboard metrics and Chart.js telemetry API.
3. `monitoring_bp` (`/monitoring`): Paginated event table, search, filters, modal inspector.
4. `reports_bp` (`/reports`): PDF report generation and CSV dataset streaming.

### Q15. What does the `@login_required` decorator do?
**Answer:** It wraps protected route functions. Before executing the view, it checks if `g.user` or `session['user_id']` exists. If not, it flashes an authentication notice and redirects to `/auth/login?next=<path>`.

### Q16. How did you prevent Session Fixation attacks?
**Answer:** When an administrator successfully authenticates, `session.clear()` is called immediately before storing the new `session['user_id']`. This ensures any old session identifier is destroyed.

---

## 🗄️ SECTION 4: Database Design & SQL Injection Defense

### Q17. Why did you choose SQLite for the database?
**Answer:** SQLite is an embedded, zero-configuration relational database engine. It stores data in a local file (`instance/database.db`), requires zero external database server setup, supports standard SQL constraints, indexes, and transactions, making it ideal for isolated local labs and academic reviews.

### Q18. What tables exist in your database schema?
**Answer:**
1. **`users`**: Stores administrator IDs, unique usernames (`NOCASE`), and Werkzeug password hashes.
2. **`events`**: Stores normalized honeypot telemetry (timestamps, source IP, ports, protocol, event type, severity score, attempted usernames, injected commands, and raw JSON logs).
3. **`system_logs`**: Internal audit trail of admin logins, log ingestions, and report downloads.

### Q19. How did you protect the database against SQL Injection?
**Answer:** We strictly use **parameterized queries** with `?` placeholders (e.g. `query_db("SELECT * FROM events WHERE severity = ?", (severity,))`). The SQLite engine treats input parameters purely as literal values, mathematically preventing SQL injection.

### Q20. Why did you create indexes in `schema.sql`?
**Answer:** We created B-Tree indexes on `timestamp`, `source_ip`, `severity`, and `event_type`. Without indexes, the database must perform a slow full table scan for every search or filter query. Indexes allow instant, sub-millisecond retrieval.

### Q21. How are passwords stored securely?
**Answer:** Passwords are never stored in plaintext. We use `werkzeug.security.generate_password_hash()`, which applies `PBKDF2` with `SHA-256` and random cryptographic salt. During login, `check_password_hash()` compares the hash securely.

---

## 📊 SECTION 5: UI/UX, Chart.js & Reporting

### Q22. How does the SOC Dashboard render real-time charts?
**Answer:** The frontend dashboard (`dashboard.js`) makes an asynchronous `fetch()` call to the `/api/dashboard/charts` JSON endpoint. **Chart.js** then dynamically draws the Threat Severity doughnut chart and Top Attacking IPs bar chart inside HTML5 `<canvas>` elements.

### Q23. How does the Modal Telemetry Inspector work?
**Answer:** In the monitoring table, each row has an "Inspect" button with a `data-event-id` attribute. When clicked, JavaScript fetches `/monitoring/api/event/<id>` and asynchronously populates a dark SOC modal with the normalized fields and formatted raw JSON payload.

### Q24. How is the Executive PDF Report generated?
**Answer:** We use Python's **ReportLab** library in `services/report_service.py`. It builds an in-memory PDF document (`io.BytesIO`) containing executive summary metrics, threat severity percentage tables, top attacker IP lists, critical command code blocks, and research disclaimers, and streams it directly to the user as a downloadable attachment.

### Q25. What HTTP security headers did you implement?
**Answer:**
- `X-Content-Type-Options: nosniff`: Prevents browsers from MIME-sniffing a response away from the declared content type.
- `X-Frame-Options: SAMEORIGIN`: Protects the application from clickjacking by disallowing it from being embedded in foreign `<iframe>` elements.
- `X-XSS-Protection: 1; mode=block`: Instructs browsers to block response execution if an XSS attack is detected.
- `Referrer-Policy: strict-origin-when-cross-origin`: Restricts sensitive path leaks when navigating away.

---

## 🧪 SECTION 6: Testing & Quality Assurance

### Q26. What testing framework did you use and how many tests were created?
**Answer:** We used **`pytest`** and authored **48 automated unit and integration tests** covering the application factory, health API, authentication flows, SQL injection prevention, log parsing, threat analyzer rules, collector ingestion, dashboard charts API, live monitoring filters, PDF generation, CSV export, and security headers. All 48 tests pass with 100% success.

### Q27. How does the parser handle corrupted or malformed log lines?
**Answer:** The `CowrieLogParser` wraps JSON decoding in a `try...except json.JSONDecodeError` block and falls back to regex-based text extraction. If a line is completely unparseable, it skips it safely without crashing the server.

### Q28. How does the collector prevent duplicate records?
**Answer:** Before inserting an event, `HoneypotCollector` queries the database for an existing record with the same `timestamp`, `source_ip`, `event_type`, and `command`. If a match is found, it increments a skip counter and bypasses insertion.

---

## 🚀 SECTION 7: Limitations & Future Enhancements

### Q29. What are the main limitations of this system?
**Answer:**
1. Heuristic rules rely on predefined signature patterns; novel, obfuscated payloads require updating the signature dictionary.
2. The current implementation focuses on SSH and Telnet protocols (Cowrie); analyzing web attacks requires adding an HTTP honeypot adapter (e.g. Snare/Tanner).

### Q30. What would you build next if you had another 3 months?
**Answer:**
1. Integration with **MaxMind GeoLite2** IP geolocation to render interactive 3D attack origin globes on the dashboard.
2. Real-time webhook notifications (e.g. alerting security teams via Discord or Slack whenever a `CRITICAL` severity event is trapped).
3. Automated PCAP packet capture integration.
