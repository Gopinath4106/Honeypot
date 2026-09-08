# System Architecture & Technical Specifications

## Component Architecture

```
[ Attacker Traffic / Mock Telemetry ]
                │
                ▼
[ Isolated Cowrie Honeypot / Sample Logs ]
                │
                ▼
[ Log Ingestion & Parsing Engine ]
                │
                ▼
[ Deterministic Rule-Based Analyzer ]
                │
                ▼
[ SQLite Database (Tables: users, events, system_logs) ]
                │
                ▼
[ Flask Application Factory & Blueprints ]
      ├── Auth Blueprint (/auth)
      ├── Dashboard Blueprint (/)
      ├── Monitoring Blueprint (/monitoring)
      └── Reports Blueprint (/reports)
                │
        ┌───────┴───────┐
        ▼               ▼
[ Responsive Web UI ]   [ PDF / CSV Reporting Engine ]
 (Bootstrap 5 & Chart.js)      (ReportLab & CSV)
```

## Module Breakdown

### Module 1: Honeypot Deployment & User Management
- Authentication service with Werkzeug password hashing.
- Session cookie management with HTTPOnly/SameSite restrictions.
- Honeypot configuration loader supporting both offline sample mode and live Cowrie lab mode.

### Module 2: Attack Monitoring & Analysis
- JSON log extraction and field normalization.
- Deterministic heuristic categorization.
- Aggregation of source IPs, protocols, and event frequency.
- Interactive SOC UI with Chart.js charts.

### Module 3: Reporting & Security Management
- PDF summary generation using ReportLab.
- CSV event dataset export.
- Audit logging of administrative actions.
- Input validation and parameterized SQL query execution.
