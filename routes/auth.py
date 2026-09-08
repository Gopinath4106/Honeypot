"""Authentication and User Management Route Blueprint

Provides secure administrator authentication, password hashing with Werkzeug,
session lifecycle management, route protection decorators, and security audit logging.
"""

import functools
import click
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from flask.cli import with_appcontext
from werkzeug.security import check_password_hash, generate_password_hash

from database.db import query_db, modify_db, log_system_event

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


def login_required(view):
    """View decorator that redirects unauthenticated requests to the login page."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Authentication required. Please log in to access the security console.", "warning")
            return redirect(url_for('auth.login', next=request.path))
        return view(**kwargs)
    return wrapped_view


@auth_bp.before_app_request
def load_logged_in_user():
    """Load the current authenticated user record into Flask's `g` context before each request."""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = query_db(
            "SELECT id, username, created_at FROM users WHERE id = ?",
            (user_id,),
            one=True
        )


@auth_bp.route('/login', methods=('GET', 'POST'))
def login():
    """Handle administrator login with secure hash verification and session creation."""
    # If user is already authenticated, redirect straight to dashboard
    if g.user is not None:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        next_page = request.args.get('next')

        error = None
        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."

        if error is None:
            user = query_db(
                "SELECT * FROM users WHERE username = ?",
                (username,),
                one=True
            )

            if user is None or not check_password_hash(user['password_hash'], password):
                error = "Invalid username or password."
                log_system_event(
                    "SECURITY",
                    f"Failed administrative login attempt for username: '{username}' from IP: {request.remote_addr}"
                )
            else:
                # Login successful: clear prior session data to prevent session fixation
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']

                log_system_event(
                    "SECURITY",
                    f"Administrator '{user['username']}' authenticated successfully from IP: {request.remote_addr}"
                )
                flash(f"Welcome back, {user['username']}. Security monitoring active.", "success")

                # Validate redirect target to prevent Open Redirect vulnerabilities
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard.index'))

        flash(error, "danger")

    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    """Log out the current user, terminate the session, and record an audit log."""
    username = session.get('username', 'Anonymous')
    log_system_event("INFO", f"Administrator '{username}' logged out.")
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('auth.login'))


def create_user_account(username, password):
    """Helper function to create a new administrator account with hashed password.

    Args:
        username (str): Administrator username.
        password (str): Plaintext password (will be hashed).

    Returns:
        int: Inserted user ID.
    """
    password_hash = generate_password_hash(password)
    return modify_db(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )


@click.command('create-admin')
@click.argument('username')
@click.argument('password')
@with_appcontext
def create_admin_command(username, password):
    """Flask CLI command to create an administrator user: `flask create-admin <user> <pass>`."""
    try:
        user_id = create_user_account(username, password)
        log_system_event("SECURITY", f"CLI: Administrator account '{username}' created (ID: {user_id}).")
        click.echo(f"Administrator '{username}' created successfully (ID: {user_id}).")
    except Exception as e:
        click.echo(f"Error creating user '{username}': {e}", err=True)
