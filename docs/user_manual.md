# Sentinel SOC User Manual & Operator Guide

## 1. System Access & Authentication

### 1.1 First-Time Setup (Creating an Administrator)
Before logging into the system, create an administrative account via the command line:

```powershell
# Syntax: flask create-admin <username> <password>
.\venv\Scripts\flask create-admin admin admin123
```

### 1.2 Accessing the Login Portal
1. Start the Flask application server:
   ```powershell
   .\venv\Scripts\python app.py
   ```
2. Navigate to `http://127.0.0.1:5000/auth/login` in your web browser.
3. Enter your administrator username and password, then click **Authenticate & Access**.
4. Upon successful authentication, your session is established, and you are redirected to the SOC Dashboard.

---

## 2. Navigating the SOC Dashboard

The main dashboard (`/`) gives a high-level operational overview of all honeypot telemetry:

- **Quick Metric Cards**:
  - **Total Observed Events**: Total count of all recorded honeypot sessions.
  - **Unique Attacker IPs**: Distinct IP addresses attempting unauthorized access.
  - **High / Critical Threats**: Count of elevated attacks (brute-force logins, successful trapped sessions, and dangerous payloads).
  - **Honeypot Trap Status**: Indicates whether the honeypot listener is actively monitored.
- **Threat Severity Breakdown (Doughnut Chart)**:
  - Visual breakdown color-coded by severity (Green = LOW, Amber = MEDIUM, Orange = HIGH, Red = CRITICAL).
- **Top Attacker IP Addresses (Bar Chart)**:
  - Top 5 source IPs ranked by total interaction frequency.
- **Top Attempted Usernames (Brute-Force)**:
  - Most common usernames dictionary-attacked by unauthorized clients (e.g. `root`, `admin`, `ubuntu`, `support`).
- **Top Executed Shell Commands**:
  - Most frequent CLI commands executed inside the trapped honeypot shell.
- **Recent Telemetry Stream**:
  - Real-time tabular feed showing the latest observed interactions with payload previews.

---

## 3. Live Monitoring & Telemetry Explorer

Navigate to **Live Telemetry** (`/monitoring/`) in the sidebar:

### 3.1 Multi-Field Search
- Type any IP address (e.g. `198.51.100.24`), username (e.g. `root`), or command keyword (e.g. `miner`, `cat`) into the search bar and click **Filter**.

### 3.2 Filtering by Threat Severity
- Filter records by choosing `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` from the **Severity** dropdown.

### 3.3 Inspecting Detailed Payloads (Modal Inspector)
- Click the **Inspect** button on any event row to open the **Honeypot Telemetry Inspector**:
  - View normalized fields (Event ID, Timestamps, Source IP, Target Port, Protocol, Severity score).
  - View attempted credentials and injected commands.
  - Review the complete raw JSON telemetry payload formatted with syntax highlighting.

---

## 4. Generating Reports & Exporting Telemetry

Navigate to **Security Reports** (`/reports/`) in the sidebar:

### 4.1 Generating an Executive PDF Report
- Click **Generate & Download PDF Report**.
- A formal ReportLab document will download containing executive summaries, threat percentage tables, top attacker rankings, critical command snippets, and academic research disclaimers.

### 4.2 Exporting Telemetry to CSV
- Click **Export Telemetry Dataset (.CSV)**.
- A standardized CSV file containing all normalized database records will download for spreadsheet analysis and archiving.

### 4.3 Reviewing the Security Audit Trail
- The audit trail table at the bottom of the reports view displays timestamped internal events (admin logins, log ingestion batches, and report generation events) recorded in SQLite `system_logs`.
