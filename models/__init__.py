"""
models/__init__.py
Exposes the SQLAlchemy db instance and the User model.
"""

from flask_sqlalchemy import SQLAlchemy

# Single shared db instance — imported by app.py and models
db = SQLAlchemy()
