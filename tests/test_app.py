"""Basic Application Smoke and Route Tests

Verifies that the Flask application initializes properly and serves essential endpoints.
"""


def test_app_creation(app):
    """Verify that the Flask app initializes in testing mode."""
    assert app is not None
    assert app.config['TESTING'] is True


def test_health_check_endpoint(client):
    """Verify that the /health endpoint returns HTTP 200 with healthy status JSON."""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data is not None
    assert data.get('status') == 'healthy'
    assert data.get('system') == 'Honeypot Attack Monitor'


def test_dashboard_root_endpoint(app, client):
    """Verify that the root / route returns HTTP 200 and renders HTML when authenticated."""
    from routes.auth import create_user_account
    with app.app_context():
        create_user_account("test_admin", "AdminPass123!")

    # Log in first
    client.post('/auth/login', data={'username': 'test_admin', 'password': 'AdminPass123!'})

    response = client.get('/')
    assert response.status_code == 200
    assert b'SENTINEL' in response.data
    assert b'Security Operations Center Dashboard' in response.data


def test_custom_404_error(client):
    """Verify that visiting a non-existent route returns 404 with custom error page."""
    response = client.get('/non-existent-endpoint-test')
    assert response.status_code == 404
    assert b'404' in response.data
    assert b'Resource not found' in response.data
