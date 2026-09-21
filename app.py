
"""
app.py — Application Entry Point
----------------------------------
Creates the Flask application, connects the database,
registers blueprints (route groups), and starts the server.

Run with:
    python app.py
"""

from datetime import datetime, timezone

from flask import Flask

from config                        import Config
from models                        import db
from models.user                   import User          # noqa: F401 — needed so SQLAlchemy sees the model
from controllers.auth_controller   import auth_bp


def create_app() -> Flask:
    """
    Application factory — builds and configures the Flask app.

    Using a factory function (instead of a global app object) makes
    testing easier and is considered best practice for Flask projects.
    """

    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Load settings from config.py
    app.config.from_object(Config)

    # Initialise SQLAlchemy with this app instance
    db.init_app(app)

    # Register route blueprints
    app.register_blueprint(auth_bp)

    # ── Custom Jinja2 filter ──────────────────────────────────
    # Converts a Unix timestamp integer to a human-readable UTC string.
    # Used in verify_token.html to display iat/exp claim values.
    @app.template_filter("timestamp_to_str")
    def timestamp_to_str(ts: int) -> str:
        try:
            return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return str(ts)

    # Create all database tables if they don't exist yet
    with app.app_context():
        db.create_all()

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()
    # debug=True enables auto-reload and the debugger — disable in production!
    app.run(debug=True, port=5000)
