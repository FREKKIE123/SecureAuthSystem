"""
controllers/auth_controller.py — Authentication Routes
--------------------------------------------------------
Handles all HTTP routes related to user authentication:
  GET  /              — Landing page
  GET  /register      — Show registration form
  POST /register      — Process registration
  GET  /login         — Show login form
  POST /login         — Process login, issue JWT
  GET  /dashboard     — Protected dashboard (requires valid session)
  GET  /verify        — Show token verification form
  POST /verify        — Validate a submitted token
  GET  /logout        — Log the user out and revoke token
"""

from flask import (
    Blueprint, render_template, request,
    redirect, url_for, session, flash
)

from models        import db
from models.user   import User
from controllers.token_controller import generate_token, validate_token, revoke_token
from config        import Config

# Blueprint groups all auth routes under one object, registered in app.py
auth_bp = Blueprint("auth", __name__)


# =============================================================================
# LANDING PAGE
# =============================================================================

@auth_bp.route("/")
def index():
    """Show the public landing / home page."""
    return render_template("index.html")


# =============================================================================
# REGISTER
# =============================================================================

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    GET  — Render the registration form.
    POST — Validate input, create user, redirect to login.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm  = request.form.get("confirm_password", "").strip()

        # ---- Input validation ----
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        # ---- Check for duplicate username ----
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username already taken. Please choose another.", "error")
            return render_template("register.html")

        # ---- Create and persist the user ----
        new_user = User(username=username, role="user")
        new_user.set_password(password)   # bcrypt hash happens here
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


# =============================================================================
# LOGIN
# =============================================================================

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    GET  — Render the login form.
    POST — Verify credentials, issue JWT on success, track failures on failure.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # ---- Basic input check ----
        if not username or not password:
            flash("Please enter your username and password.", "error")
            return render_template("login.html")

        # ---- Look up user ----
        user = User.query.filter_by(username=username).first()

        if not user:
            # Don't reveal whether the username exists (security best practice)
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        # ---- Account lockout check ----
        if user.is_locked:
            flash(
                "Your account has been locked after too many failed attempts. "
                "Please contact an administrator.",
                "error"
            )
            return render_template("login.html")

        # ---- Verify password ----
        if not user.check_password(password):
            # Increment failure counter
            user.failed_attempts += 1

            # Lock the account if the threshold is reached
            if user.failed_attempts >= Config.MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                db.session.commit()
                flash(
                    f"Account locked after {Config.MAX_FAILED_ATTEMPTS} failed attempts. "
                    "Contact an administrator to unlock.",
                    "error"
                )
            else:
                remaining = Config.MAX_FAILED_ATTEMPTS - user.failed_attempts
                db.session.commit()
                flash(
                    f"Invalid username or password. "
                    f"{remaining} attempt(s) remaining before lockout.",
                    "error"
                )
            return render_template("login.html")

        # ---- Successful login ----
        # Reset failed attempt counter on a good login
        user.failed_attempts = 0
        db.session.commit()

        # Generate a JWT for this user
        token = generate_token(user.id, user.role)

        # Store minimal info in the server-side session (Flask signs this cookie)
        session["user_id"]  = user.id
        session["username"] = user.username
        session["role"]     = user.role
        session["token"]    = token   # stored so we can revoke it on logout

        return redirect(url_for("auth.dashboard"))

    return render_template("login.html")


# =============================================================================
# DASHBOARD
# =============================================================================

@auth_bp.route("/dashboard")
def dashboard():
    """
    Protected dashboard — only accessible after login.
    Shows the user's JWT and account details.
    """
    # Check that the user has an active session
    if "user_id" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for("auth.login"))

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        token=session.get("token"),
    )


# =============================================================================
# TOKEN VERIFICATION
# =============================================================================

@auth_bp.route("/verify", methods=["GET", "POST"])
def verify():
    """
    GET  — Render the token verification form (pre-fill with session token if present).
    POST — Validate the submitted token and display the result.
    """
    result       = None
    token_input  = session.get("token", "")   # Pre-fill the form for convenience

    if request.method == "POST":
        token_input = request.form.get("token", "").strip()

        if not token_input:
            flash("Please paste a token to verify.", "error")
        else:
            result = validate_token(token_input)

    return render_template("verify_token.html", result=result, token_input=token_input)


# =============================================================================
# LOGOUT
# =============================================================================

@auth_bp.route("/logout")
def logout():
    """
    Revoke the user's JWT and clear the server-side session.
    After this, the token is blacklisted and will be rejected by validate_token().
    """
    token = session.get("token")
    if token:
        revoke_token(token)   # Add jti to the revocation set

    session.clear()           # Remove all session data

    flash("You have been logged out successfully.", "success")
    return redirect(url_for("auth.index"))
