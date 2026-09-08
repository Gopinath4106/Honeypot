"""Main Flask Application Factory

Honeypot-Based Attack Monitoring and Security Analysis System
Entrypoint and application factory pattern.
"""

import os
from flask import Flask, render_template, jsonify
from config import get_config
from database import db
from routes import auth, dashboard, monitoring, reports
from honeypot import collector


def create_app(config_name=None):
    """Application factory for creating and configuring the Flask app instance.

    Args:
        config_name (str, optional): Configuration environment ('development', 'testing', 'production').

    Returns:
        Flask: The configured Flask application instance.
    """
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    cfg = get_config(config_name)
    app.config.from_object(cfg)

    # Ensure the instance and reports directories exist
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config.get('REPORTS_DIR', 'reports'), exist_ok=True)

    # Initialize Database Lifecycle Hooks
    db.init_app(app)

    # Register Blueprints & CLI Commands
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(dashboard.dashboard_bp)
    app.register_blueprint(monitoring.monitoring_bp)
    app.register_blueprint(reports.reports_bp)
    app.cli.add_command(auth.create_admin_command)
    app.cli.add_command(collector.ingest_logs_command)

    # Security Hardening: Inject standard defensive HTTP security headers
    @app.after_request
    def set_security_headers(response):
        """Inject defensive HTTP headers to guard against clickjacking, sniffing, and XSS."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    # Health check endpoint for system monitoring
    @app.route('/health')
    def health_check():
        """Health check endpoint to verify backend status."""
        return jsonify({
            'status': 'healthy',
            'system': 'Honeypot Attack Monitor',
            'version': '1.0.0',
            'environment': app.config.get('ENV', 'development'),
            'honeypot_mode': app.config.get('HONEYPOT_MODE', 'sample')
        }), 200

    # Register Error Handlers
    @app.errorhandler(404)
    def not_found_error(error):
        """Custom 404 Not Found error handler."""
        return render_template('error.html', error_code=404, message="Resource not found"), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Custom 500 Internal Server Error handler."""
        return render_template('error.html', error_code=500, message="An internal system error occurred"), 500

    @app.errorhandler(403)
    def forbidden_error(error):
        """Custom 403 Forbidden error handler."""
        return render_template('error.html', error_code=403, message="Access denied: unauthorized request"), 403

    return app


if __name__ == '__main__':
    application = create_app()
    # Run locally on 127.0.0.1:5000 in debug mode
    application.run(host='127.0.0.1', port=5000, debug=True)
