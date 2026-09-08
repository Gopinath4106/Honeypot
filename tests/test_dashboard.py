"""SOC Dashboard View and Charts API Tests

Verifies that the dashboard loads accurately with statistical summaries
and that the Chart.js JSON telemetry API delivers valid data structures.
"""

from honeypot.collector import HoneypotCollector
from routes.auth import create_user_account


def test_dashboard_authenticated_view(app, client):
    """Verify that the dashboard view loads with aggregated statistics."""
    with app.app_context():
        create_user_account("soc_analyst", "AnalystPass123!")
        HoneypotCollector.ingest_logs()

    # Log in
    client.post('/auth/login', data={'username': 'soc_analyst', 'password': 'AnalystPass123!'})

    response = client.get('/')
    assert response.status_code == 200
    assert b'Security Operations Center Dashboard' in response.data
    assert b'Total Observed Events' in response.data
    assert b'Threat Severity Distribution' in response.data


def test_dashboard_charts_api(app, client):
    """Verify that /api/dashboard/charts returns structured JSON for Chart.js."""
    with app.app_context():
        create_user_account("chart_admin", "ChartPass123!")
        HoneypotCollector.ingest_logs()

    client.post('/auth/login', data={'username': 'chart_admin', 'password': 'ChartPass123!'})

    response = client.get('/api/dashboard/charts')
    assert response.status_code == 200
    data = response.get_json()

    assert data['status'] == 'success'
    assert 'severity' in data
    assert 'labels' in data['severity']
    assert 'counts' in data['severity']
    assert len(data['severity']['counts']) == 4

    assert 'top_ips' in data
    assert len(data['top_ips']['labels']) > 0

    assert 'event_types' in data
    assert len(data['event_types']['labels']) > 0
