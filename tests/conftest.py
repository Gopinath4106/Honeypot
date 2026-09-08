import os
import tempfile
import pytest
from app import create_app
from database.db import init_db


@pytest.fixture
def app():
    """Create and configure a new Flask app instance with an isolated database for each test."""
    db_fd, db_path = tempfile.mkstemp(suffix='.db')

    application = create_app('testing')
    application.config.update({
        'DATABASE_PATH': db_path,
        'TESTING': True,
    })

    with application.app_context():
        init_db()

    yield application

    os.close(db_fd)
    if os.path.exists(db_path):
        try:
            os.unlink(db_path)
        except PermissionError:
            pass


@pytest.fixture
def client(app):
    """A test client for sending HTTP requests to the application."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test runner for CLI commands."""
    return app.test_cli_runner()

