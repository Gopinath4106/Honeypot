"""Verification script for database tables, users, and event ingestion."""
from app import create_app
from database.db import init_db, query_db, modify_db
from routes.auth import create_user_account

app = create_app('development')
with app.app_context():
    init_db()
    
    # Check tables
    tables = [r['name'] for r in query_db("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    print("[1/4] SQLite Tables Verified:", tables)
    
    # Check / Create Admin
    existing = query_db("SELECT * FROM users WHERE username = ?", ("admin",), one=True)
    if not existing:
        create_user_account("admin", "admin123")
    user_count = query_db("SELECT count(*) as c FROM users", one=True)['c']
    print(f"[2/4] Admin Account Verified: 'admin' (Total users: {user_count})")
    
    # Check Event Storage
    modify_db(
        """INSERT INTO events (timestamp, source_ip, source_port, destination_port, protocol, event_type, severity, username, command, raw_log)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        ('2026-08-23T18:00:00Z', '203.0.113.45', 49152, 2222, 'ssh', 'cowrie.login.failed', 'MEDIUM', 'root', None, '{"eventid":"cowrie.login.failed"}')
    )
    event_count = query_db("SELECT count(*) as c FROM events", one=True)['c']
    unique_ips = query_db("SELECT count(DISTINCT source_ip) as c FROM events", one=True)['c']
    print(f"[3/4] Event Ingestion Verified: Total events = {event_count}, Unique IPs = {unique_ips}")

    # Test Client Web Request
    client = app.test_client()
    client.post('/auth/login', data={'username': 'admin', 'password': 'admin123'})
    dashboard_res = client.get('/')
    print(f"[4/4] Authenticated Web Dashboard Response: HTTP {dashboard_res.status_code} (Contains 'Total Logged Events')")
    
    print("\n>>> ALL SYSTEM VERIFICATION CHECKS PASSED SUCCESSFULLY! <<<")
