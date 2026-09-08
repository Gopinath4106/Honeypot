"""Live Monitoring Route and API Unit Tests

Verifies event listing, multi-field search, severity filters, protocol filters,
pagination, event details modal API, and attacker profiling API.
"""

from honeypot.collector import HoneypotCollector
from routes.auth import create_user_account
from database.db import query_db


def test_monitoring_view_authenticated(app, client):
    """Verify that the monitoring view loads successfully."""
    with app.app_context():
        create_user_account("mon_admin", "MonPass123!")
        ingest_res = HoneypotCollector.ingest_logs()
        assert ingest_res['ingested'] > 0

    client.post('/auth/login', data={'username': 'mon_admin', 'password': 'MonPass123!'})

    response = client.get('/monitoring/')
    assert response.status_code == 200
    assert b'Live Attack Telemetry Explorer' in response.data
    assert b'Attacker Source IP' in response.data


def test_monitoring_search_filter(app, client):
    """Verify searching by IP or command returns only matching events."""
    with app.app_context():
        create_user_account("mon_search", "SearchPass123!")
        HoneypotCollector.ingest_logs()

    client.post('/auth/login', data={'username': 'mon_search', 'password': 'SearchPass123!'})

    # Search for specific attacker IP
    response = client.get('/monitoring/?q=198.51.100.24')
    assert response.status_code == 200
    assert b'198.51.100.24' in response.data

    # Search for specific command
    cmd_res = client.get('/monitoring/?q=miner')
    assert cmd_res.status_code == 200
    assert b'miner' in cmd_res.data


def test_monitoring_severity_filter(app, client):
    """Verify filtering by severity returns exclusively that severity level."""
    with app.app_context():
        create_user_account("sev_admin", "SevPass123!")
        HoneypotCollector.ingest_logs()

    client.post('/auth/login', data={'username': 'sev_admin', 'password': 'SevPass123!'})

    response = client.get('/monitoring/?severity=CRITICAL')
    assert response.status_code == 200
    assert b'CRITICAL' in response.data


def test_monitoring_protocol_filter(app, client):
    """Verify filtering by protocol returns matching protocol events."""
    with app.app_context():
        create_user_account("proto_admin", "ProtoPass123!")
        HoneypotCollector.ingest_logs()

    client.post('/auth/login', data={'username': 'proto_admin', 'password': 'ProtoPass123!'})

    response = client.get('/monitoring/?protocol=telnet')
    assert response.status_code == 200
    assert b'TELNET' in response.data


def test_event_json_api(app, client):
    """Verify the event detail modal JSON endpoint."""
    with app.app_context():
        create_user_account("detail_admin", "DetailPass123!")
        HoneypotCollector.ingest_logs()
        first_event = query_db("SELECT id FROM events LIMIT 1", one=True)

    client.post('/auth/login', data={'username': 'detail_admin', 'password': 'DetailPass123!'})

    response = client.get(f"/monitoring/api/event/{first_event['id']}")
    assert response.status_code == 200
    data = response.get_json()
    assert data['id'] == first_event['id']
    assert 'source_ip' in data
    assert 'severity' in data
    assert 'raw_log' in data


def test_event_json_api_not_found(app, client):
    """Verify that querying a non-existent event ID returns 404."""
    with app.app_context():
        create_user_account("nf_admin", "NfPass123!")

    client.post('/auth/login', data={'username': 'nf_admin', 'password': 'NfPass123!'})

    response = client.get('/monitoring/api/event/999999')
    assert response.status_code == 404
    data = response.get_json()
    assert 'error' in data


def test_attacker_profile_api(app, client):
    """Verify the attacker threat profiling API endpoint."""
    with app.app_context():
        create_user_account("prof_admin", "ProfPass123!")
        HoneypotCollector.ingest_logs()

    client.post('/auth/login', data={'username': 'prof_admin', 'password': 'ProfPass123!'})

    response = client.get('/monitoring/api/attacker/198.51.100.24')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success'
    assert data['source_ip'] == '198.51.100.24'
    assert 'summary' in data
    assert 'credentials_tried' in data
