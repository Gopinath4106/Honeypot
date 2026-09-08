# Database Design & Architecture Document

## Overview
The **Honeypot-Based Attack Monitoring and Security Analysis System** utilizes **SQLite** as its lightweight, embedded relational database engine. SQLite was selected because:
1. It is zero-configuration and operates fully offline in an isolated local lab.
2. It supports standard SQL DDL, indexes, and ACID compliance.
3. It has zero external server dependencies, making it optimal for local evaluation and security reviews.

---

## Entity Relationship (ER) Concept

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

## Table Schemas & Data Dictionary

### 1. `users` Table
Stores credentials for authorized security administrators.

| Column | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique identifier for each admin user |
| `username` | TEXT | UNIQUE, NOT NULL, NOCASE | Case-insensitive administrator username |
| `password_hash` | TEXT | NOT NULL | Werkzeug-hashed password string (PBKDF2/SHA256) |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Account creation timestamp |

### 2. `events` Table
Stores normalized honeypot telemetry records and classified security events.

| Column | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique event identifier |
| `timestamp` | TEXT | NOT NULL | ISO-8601 UTC timestamp of attacker interaction |
| `source_ip` | TEXT | NOT NULL | Originating IPv4/IPv6 address of the attacker |
| `source_port` | INTEGER | NULLABLE | Attacker client source port |
| `destination_port` | INTEGER | NULLABLE | Targeted honeypot port (e.g., 2222 for Cowrie SSH) |
| `protocol` | TEXT | NOT NULL, DEFAULT 'ssh' | Interaction protocol ('ssh', 'telnet') |
| `event_type` | TEXT | NOT NULL | Honeypot event tag (e.g., `cowrie.login.failed`) |
| `severity` | TEXT | CHECK IN ('LOW','MEDIUM','HIGH','CRITICAL') | Rule-based calculated threat severity |
| `username` | TEXT | NULLABLE | Credential username attempted by attacker |
| `command` | TEXT | NULLABLE | CLI command string entered in honeypot shell |
| `raw_log` | TEXT | NULLABLE | Complete original JSON log payload |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Database ingestion timestamp |

**Indexes**:
- `idx_events_timestamp` on `timestamp` (for time-range filtering and activity charts)
- `idx_events_source_ip` on `source_ip` (for attacker grouping and top-IP queries)
- `idx_events_severity` on `severity` (for critical alert filtering)
- `idx_events_event_type` on `event_type` (for categorization summaries)

### 3. `system_logs` Table
Internal audit trails, security events, and error logs.

| Column | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Log entry identifier |
| `timestamp` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Event occurrence timestamp |
| `level` | TEXT | CHECK IN ('INFO','WARNING','ERROR','SECURITY') | Log classification level |
| `message` | TEXT | NOT NULL | Descriptive log text |

---

## Security & Parameterization Standard
To eliminate SQL Injection vulnerabilities:
- **Never** format queries via string interpolation (e.g., `f"SELECT * FROM users WHERE username = '{user}'"`).
- **Always** use parameterized placeholders `?` passed via `query_db(query, (params,))` and `modify_db(query, (params,))`.
