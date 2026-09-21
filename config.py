"""
config.py — Application Configuration
--------------------------------------
Stores all app-level settings in one place.
In a real production app, SECRET_KEY would come from
an environment variable, not be hardcoded.
"""

import os


class Config:
    # -------------------------------------------------------
    # Flask secret key — used to sign session cookies.
    # Change this to a long random string in production.
    # -------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production-please-use-env-var")

    # -------------------------------------------------------
    # SQLite database file stored next to this config file.
    # -------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = "sqlite:///auth_system.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Suppresses a deprecation warning

    # -------------------------------------------------------
    # JWT settings
    # -------------------------------------------------------
    JWT_ALGORITHM = "HS256"                 # HMAC-SHA256 signing algorithm
    JWT_ISSUER    = "SecureAuthSystem"      # Identifies who issued the token
    JWT_EXPIRY_MINUTES = 15                 # Token is only valid for 15 minutes

    # -------------------------------------------------------
    # Account lockout settings
    # -------------------------------------------------------
    MAX_FAILED_ATTEMPTS = 3                 # Lock account after this many failures
