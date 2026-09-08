# Comprehensive Testing & Verification Plan

## 1. Overview & Test Strategy
The **Honeypot-Based Attack Monitoring and Security Analysis System** employs a multi-tiered testing strategy combining:
1. **Automated Unit & Integration Testing** using `pytest`.
2. **Manual Security & Workflow Test Cases** covering boundary conditions and user interactions.

---

## 2. Automated Test Suite Matrix (48 Test Cases)

| Test Module | Test Function | Purpose & Validation |
| :--- | :--- | :--- |
| **`tests/test_app.py`** | `test_app_creation` | Verifies Flask app factory initializes with `TESTING=True` |
| | `test_health_check_endpoint` | Verifies `/health` returns HTTP 200 with operational status JSON |
| | `test_dashboard_root_endpoint` | Verifies authenticated access to root `/` renders SOC dashboard |
| | `test_custom_404_error` | Verifies non-existent endpoints trigger custom 404 security error page |
| **`tests/test_auth.py`** | `test_login_page_renders` | Verifies GET `/auth/login` renders authentication card (HTTP 200) |
| | `test_unauthenticated_dashboard_redirects` | Verifies unauthenticated root access redirects to login (HTTP 302) |
| | `test_successful_admin_login_and_dashboard_access` | Verifies valid credentials set session and redirect to dashboard |
| | `test_invalid_password_fails` | Verifies wrong password fails, flashes error, and logs security notice |
| | `test_nonexistent_username_fails` | Verifies unknown username returns generic error without information leak |
| | `test_logout_terminates_session` | Verifies `/auth/logout` clears session and locks subsequent navigation |
| | `test_open_redirect_prevention` | Verifies external phishing URLs in `next` parameter are blocked |
| | `test_create_admin_cli` | Verifies `flask create-admin` CLI command provisions admin users |
| **`tests/test_database.py`** | `test_tables_created` | Verifies `users`, `events`, and `system_logs` tables exist |
| | `test_user_insertion_and_retrieval` | Verifies inserting and querying user records with parameterized SQL |
| | `test_event_insertion_and_severity_filtering` | Verifies inserting telemetry events and querying by severity |
| | `test_system_logging_helper` | Verifies `log_system_event()` records audit log entries |
| | `test_sql_injection_prevention` | Verifies malicious SQL strings are safely treated as literal data |
| | `test_init_db_cli` | Verifies `flask init-db` CLI command initializes database schema |
| **`tests/test_analyzer.py`** | `test_connection_event_evaluation` | Verifies TCP connect events are classified as LOW severity |
| | `test_session_lifecycle_event` | Verifies session disconnects are classified as LOW severity |
| | `test_failed_login_evaluation` | Verifies failed authentication attempts are classified as MEDIUM |
| | `test_successful_honeypot_login_evaluation` | Verifies successful honeypot login triggers HIGH severity alert |
| | `test_reconnaissance_command_analysis` | Verifies recon commands (uname, whoami, id) are classified as MEDIUM |
| | `test_critical_malicious_commands` | Verifies dangerous payloads (shadow dumping, reverse shells) are CRITICAL |
| | `test_arbitrary_unrecognized_command` | Verifies unknown shell inputs default to HIGH severity |
| **`tests/test_parser.py`** | `test_parse_valid_login_json` | Verifies Cowrie JSON parsing and field normalization |
| | `test_parse_valid_command_json` | Verifies command input parsing and severity categorization |
| | `test_parse_malformed_json_resilience` | Verifies corrupt/non-JSON text lines do not crash the parser |
| | `test_parse_empty_or_whitespace` | Verifies empty or whitespace inputs return None gracefully |
| | `test_timestamp_normalization` | Verifies normalization of ISO-8601 UTC timestamps |
| **`tests/test_collector.py`** | `test_ingest_sample_logs` | Verifies batch ingestion from sample Cowrie log files |
| | `test_ingest_duplicate_prevention` | Verifies repeated ingestion skips previously stored records |
| | `test_statistics_service_after_ingestion` | Verifies accurate metric aggregation from SQLite |
| | `test_ingest_logs_cli` | Verifies `flask ingest-logs` CLI command execution |
| **`tests/test_dashboard.py`** | `test_dashboard_authenticated_view` | Verifies dashboard renders with live statistics and activity feed |
| | `test_dashboard_charts_api` | Verifies `/api/dashboard/charts` delivers valid Chart.js JSON |
| **`tests/test_monitoring.py`** | `test_monitoring_view_authenticated` | Verifies live telemetry explorer renders event table |
| | `test_monitoring_search_filter` | Verifies multi-field search (`?q=...`) returns filtered records |
| | `test_monitoring_severity_filter` | Verifies filtering by severity (`?severity=CRITICAL`) |
| | `test_monitoring_protocol_filter` | Verifies filtering by protocol (`?protocol=telnet`) |
| | `test_event_json_api` | Verifies `/monitoring/api/event/<id>` modal telemetry API |
| | `test_event_json_api_not_found` | Verifies non-existent event ID returns HTTP 404 |
| | `test_attacker_profile_api` | Verifies `/monitoring/api/attacker/<ip>` threat profile API |
| **`tests/test_reports.py`** | `test_reports_view_authenticated` | Verifies reports center UI renders with audit trail |
| | `test_generate_pdf_report_route` | Verifies `/reports/generate/pdf` streams valid `%PDF-` binary |
| | `test_export_csv_route` | Verifies `/reports/export/csv` streams valid formatted CSV dataset |
| | `test_http_security_headers` | Verifies nosniff, SAMEORIGIN, and XSS defensive HTTP headers |
| | `test_unauthenticated_reports_access_denied`| Verifies unauthorized report requests redirect to login |

---

## 3. Manual Test Cases & Boundary Verification

| Test ID | Scenario | Procedure | Expected Result | Pass/Fail |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Valid Admin Login | Enter `admin` / `admin123` on `/auth/login` | Redirects to dashboard, flashes welcome, displays username pill | ✅ PASS |
| **TC-02** | Invalid Password | Enter `admin` / `wrongpass` | Stays on login page, flashes error, logs `SECURITY` event in SQLite | ✅ PASS |
| **TC-03** | Empty Form Fields | Submit login form with empty username/password | Form validation alerts user; no database error | ✅ PASS |
| **TC-04** | Session Logout | Click Logout in sidebar | Session terminates; dashboard redirects to login | ✅ PASS |
| **TC-05** | SQL Injection Attempt | Enter `' OR '1'='1` in login or search query | Handled purely as literal string; zero unauthorized access | ✅ PASS |
| **TC-06** | Corrupted Log Ingestion | Ingest log file containing garbage characters | Parser falls back gracefully; zero application crashes | ✅ PASS |
| **TC-07** | Duplicate Log Ingestion | Run `flask ingest-logs` twice consecutively | Ingests on first run; skips 100% duplicates on second run | ✅ PASS |
| **TC-08** | Multi-Field Search | Search for specific IP `198.51.100.24` or command `miner` | Displays matching events with accurate total count | ✅ PASS |
| **TC-09** | Modal Telemetry Inspector | Click "Inspect" on any event row in monitoring | Opens modal, loads raw JSON payload and normalized data asynchronously | ✅ PASS |
| **TC-10** | PDF Report Generation | Click "Generate & Download PDF Report" | Downloads formatted multi-page PDF document | ✅ PASS |
| **TC-11** | CSV Dataset Export | Click "Export Telemetry Dataset (.CSV)" | Downloads complete dataset with all telemetry fields | ✅ PASS |

---

## 4. How to Run Automated Tests

```powershell
# Run the complete test suite with verbose output
.\venv\Scripts\pytest -v

# Run with concise summary
.\venv\Scripts\pytest -q
```
