"""Database Layer Unit and Integration Tests

Verifies table initialization, CRUD operations, parameterized SQL queries,
and system logging.
"""

from database.db import get_db, query_db, modify_db, log_system_event


def test_tables_created(app):
    """Verify that all required tables and indexes exist in the initialized database."""
    with app.app_context():
        tables = query_db(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        table_names = {row['name'] for row in tables}
        assert 'users' in table_names
        assert 'events' in table_names
        assert 'system_logs' in table_names


def test_user_insertion_and_retrieval(app):
    """Verify inserting and selecting a user record with parameterized query."""
    with app.app_context():
        user_id = modify_db(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin_test", "pbkdf2:sha256:test_hash_value")
        )
        assert user_id > 0

        user = query_db(
            "SELECT * FROM users WHERE username = ?",
            ("admin_test",),
            one=True
        )
        assert user is not None
        assert user['username'] == 'admin_test'
        assert user['password_hash'] == 'pbkdf2:sha256:test_hash_value'


def test_event_insertion_and_severity_filtering(app):
    """Verify inserting normalized attack events and filtering by severity."""
    with app.app_context():
        # Insert a LOW severity event
        modify_db(
            """INSERT INTO events (timestamp, source_ip, source_port, destination_port, protocol, event_type, severity, raw_log)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("2026-08-23T12:00:00Z", "192.168.1.50", 43210, 2222, "ssh", "cowrie.session.connect", "LOW", '{"raw": 1}')
        )

        # Insert a CRITICAL severity event
        modify_db(
            """INSERT INTO events (timestamp, source_ip, source_port, destination_port, protocol, event_type, severity, username, command, raw_log)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("2026-08-23T12:05:00Z", "192.168.1.50", 43210, 2222, "ssh", "cowrie.command.input", "CRITICAL", "root", "cat /etc/shadow", '{"raw": 2}')
        )

        # Query all events
        all_events = query_db("SELECT * FROM events ORDER BY id ASC")
        assert len(all_events) == 2

        # Query only CRITICAL events
        critical_events = query_db("SELECT * FROM events WHERE severity = ?", ("CRITICAL",))
        assert len(critical_events) == 1
        assert critical_events[0]['command'] == "cat /etc/shadow"
        assert critical_events[0]['username'] == "root"


def test_system_logging_helper(app):
    """Verify that log_system_event safely writes audit log entries."""
    with app.app_context():
        log_system_event("SECURITY", "Unauthorized access attempt blocked from 10.0.0.99")
        log_system_event("INFO", "Honeypot collector process started")

        logs = query_db("SELECT * FROM system_logs ORDER BY id ASC")
        assert len(logs) == 2
        assert logs[0]['level'] == "SECURITY"
        assert "Unauthorized access attempt" in logs[0]['message']
        assert logs[1]['level'] == "INFO"


def test_sql_injection_prevention(app):
    """Verify that SQL injection string payloads are treated safely as literal data."""
    with app.app_context():
        # Malicious username payload designed to alter SQL logic if concatenated
        malicious_input = "' OR '1'='1"
        modify_db(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (malicious_input, "hash_abc")
        )

        # Parameterized query must strictly match the literal string
        user = query_db("SELECT * FROM users WHERE username = ?", (malicious_input,), one=True)
        assert user is not None
        assert user['username'] == "' OR '1'='1"

        # Searching for normal name should not return the injected row
        other_user = query_db("SELECT * FROM users WHERE username = ?", ("admin",), one=True)
        assert other_user is None


def test_init_db_cli(runner, monkeypatch):
    """Verify that the flask init-db command executes successfully."""
    result = runner.invoke(args=['init-db'])
    assert result.exit_code == 0
    assert 'Database schema successfully initialized' in result.output
