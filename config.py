"""Application Configuration Module

Defines configuration settings for different environments (Development, Testing, Production).
Loads environment variables from .env file if available.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env file if present
load_dotenv(BASE_DIR / '.env')


class Config:
    """Base configuration with default settings."""

    # Security: Secret key for signing session cookies
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-insecure-key-change-in-production-3a8f9c1b')

    # Database Configuration
    DATABASE_PATH = os.environ.get(
        'DATABASE_PATH',
        str(BASE_DIR / 'instance' / 'database.db')
    )

    # Honeypot Integration Mode ('sample' for offline/dev, 'real' for isolated Cowrie lab)
    HONEYPOT_MODE = os.environ.get('HONEYPOT_MODE', 'sample')
    HONEYPOT_LOG_PATH = os.environ.get(
        'HONEYPOT_LOG_PATH',
        str(BASE_DIR / 'honeypot' / 'sample_logs' / 'cowrie.sample.json')
    )

    # Reports output directory
    REPORTS_DIR = os.environ.get(
        'REPORTS_DIR',
        str(BASE_DIR / 'reports')
    )

    # Session Security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour session lifetime


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing environment configuration."""
    DEBUG = False
    TESTING = True
    DATABASE_PATH = ':memory:'  # In-memory SQLite for automated tests
    SECRET_KEY = 'test-secret-key-for-automated-suites'


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True  # Enforce HTTPS cookies in production


# Config mapping dictionary
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config(config_name=None):
    """Retrieve configuration object based on environment name."""
    if not config_name:
        config_name = os.environ.get('FLASK_ENV', 'development').lower()
    return config_by_name.get(config_name, DevelopmentConfig)
