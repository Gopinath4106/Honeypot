"""Database Connection and Lifecycle Management Module

Manages SQLite connection pooling per Flask application context,
schema initialization, and parameterized query execution to prevent SQL injection.
"""

import sqlite3
from pathlib import Path
import click
from flask import current_app, g
from flask.cli import with_appcontext


def get_db():
    """Get or establish the SQLite database connection for the active request context.

    Returns:
        sqlite3.Connection: SQLite database connection configured with Row factory.
    """
    if 'db' not in g:
        db_path = current_app.config['DATABASE_PATH']
        
        # Connect to SQLite database
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # Enable column access by name (dict-like row objects)
        g.db.row_factory = sqlite3.Row
        
        # Enforce foreign key constraints
        g.db.execute("PRAGMA foreign_keys = ON;")

    return g.db


def close_db(e=None):
    """Close the SQLite database connection at the end of the request context.

    Args:
        e (Exception, optional): Exception that caused request teardown, if any.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database tables using the DDL schema defined in schema.sql."""
    db = get_db()
    schema_path = Path(__file__).resolve().parent / 'schema.sql'

    with open(schema_path, mode='r', encoding='utf-8') as schema_file:
        db.executescript(schema_file.read())
    db.commit()


@click.command('init-db')
@with_appcontext
def init_db_command():
    """Flask CLI command to initialize database schema: `flask init-db`."""
    init_db()
    click.echo('Database schema successfully initialized.')


def init_app(app):
    """Register database lifecycle hooks and CLI commands with the Flask app.

    Args:
        app (Flask): The Flask application instance.
    """
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)


def query_db(query, args=(), one=False):
    """Execute a parameterized SELECT query safely against the database.

    Args:
        query (str): SQL query with '?' placeholders.
        args (tuple/list): Parameter values matching placeholders.
        one (bool): If True, returns a single row; else returns a list of rows.

    Returns:
        sqlite3.Row | list[sqlite3.Row] | None: Query results.
    """
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def modify_db(query, args=()):
    """Execute a parameterized INSERT, UPDATE, or DELETE query and commit changes.

    Args:
        query (str): SQL statement with '?' placeholders.
        args (tuple/list): Parameter values matching placeholders.

    Returns:
        int: The last inserted row ID (if INSERT) or number of affected rows.
    """
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id


def log_system_event(level, message):
    """Record an internal system or security audit event in the system_logs table.

    Args:
        level (str): Log level ('INFO', 'WARNING', 'ERROR', 'SECURITY').
        message (str): Log message describing the event.
    """
    try:
        valid_levels = {'INFO', 'WARNING', 'ERROR', 'SECURITY'}
        normalized_level = level.upper() if level.upper() in valid_levels else 'INFO'
        modify_db(
            "INSERT INTO system_logs (level, message) VALUES (?, ?)",
            (normalized_level, message)
        )
    except Exception as err:
        # Fallback print to prevent logger crash if database is unavailable
        print(f"[SYSTEM_LOG_FALLBACK] {level}: {message} (DB Error: {err})")
