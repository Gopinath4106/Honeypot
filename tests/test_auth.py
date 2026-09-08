"""Authentication and Authorization Unit Tests

Verifies login views, password hashing, session creation/destruction,
route protection guards, open redirect defense, and CLI admin creation.
"""

from routes.auth import create_user_account
from database.db import query_db


def test_login_page_renders(client):
    """Verify that the login form loads properly with HTTP 200."""
    response = client.get('/auth/login')
    assert response.status_code == 200
    assert b'SENTINEL MONITOR' in response.data
    assert b'Username' in response.data
    assert b'Password' in response.data


def test_unauthenticated_dashboard_redirects(client):
    """Verify that accessing protected root / without login redirects to /auth/login."""
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 302
    assert '/auth/login' in response.headers['Location']


def test_successful_admin_login_and_dashboard_access(app, client):
    """Verify that valid admin credentials create an authenticated session."""
    with app.app_context():
        create_user_account("secadmin", "Secur3P@ssw0rd!")

    # Attempt POST login
    response = client.post('/auth/login', data={
        'username': 'secadmin',
        'password': 'Secur3P@ssw0rd!'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Welcome back, secadmin' in response.data
    assert b'Security Operations Center Dashboard' in response.data
    assert b'secadmin' in response.data


def test_invalid_password_fails(app, client):
    """Verify that incorrect passwords fail and record a security log."""
    with app.app_context():
        create_user_account("admin_user", "CorrectPassword")

    response = client.post('/auth/login', data={
        'username': 'admin_user',
        'password': 'WrongPassword123'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Invalid username or password' in response.data

    with app.app_context():
        logs = query_db("SELECT * FROM system_logs WHERE level = 'SECURITY'")
        assert any("Failed administrative login attempt" in row['message'] for row in logs)


def test_nonexistent_username_fails(client):
    """Verify that unknown usernames fail gracefully with generic error."""
    response = client.post('/auth/login', data={
        'username': 'ghost_user',
        'password': 'any_password'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Invalid username or password' in response.data


def test_logout_terminates_session(app, client):
    """Verify that logging out clears session and prevents subsequent dashboard access."""
    with app.app_context():
        create_user_account("operator1", "Operat0rPass!")

    # Log in
    client.post('/auth/login', data={
        'username': 'operator1',
        'password': 'Operat0rPass!'
    })

    # Log out
    logout_res = client.get('/auth/logout', follow_redirects=True)
    assert logout_res.status_code == 200
    assert b'You have been logged out successfully' in logout_res.data

    # Attempting to access dashboard must now redirect back to login
    dash_res = client.get('/', follow_redirects=False)
    assert dash_res.status_code == 302
    assert '/auth/login' in dash_res.headers['Location']


def test_open_redirect_prevention(app, client):
    """Verify that malicious next query params (external URLs) are ignored."""
    with app.app_context():
        create_user_account("admin_guard", "GuardPass123!")

    # Attempt login with external URL in next parameter
    response = client.post('/auth/login?next=https://malicious-phishing.com', data={
        'username': 'admin_guard',
        'password': 'GuardPass123!'
    }, follow_redirects=False)

    assert response.status_code == 302
    # Should redirect to internal index '/' rather than external domain
    assert response.headers['Location'] == '/'


def test_create_admin_cli(runner, app):
    """Verify creating an admin via the Flask CLI command `create-admin`."""
    result = runner.invoke(args=['create-admin', 'cli_superadmin', 'StrongCliPass99!'])
    assert result.exit_code == 0
    assert "Administrator 'cli_superadmin' created successfully" in result.output

    with app.app_context():
        user = query_db("SELECT * FROM users WHERE username = ?", ("cli_superadmin",), one=True)
        assert user is not None
        assert user['username'] == 'cli_superadmin'
