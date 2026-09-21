"""
models/user.py — User Model
-----------------------------
Defines the User table and all password-related logic.

IMPORTANT SECURITY NOTES:
  - Passwords are NEVER stored as plaintext.
  - bcrypt hashes the password and automatically generates a unique salt.
  - The salt is embedded inside the hash, so no separate salt column is needed.
"""

import bcrypt
from models import db


class User(db.Model):
    """
    Represents a registered user in the database.

    Columns:
        id             — auto-incrementing primary key
        username       — unique login name
        password_hash  — bcrypt hash of the user's password (never plaintext!)
        role           — either "user" or "admin"
        failed_attempts— how many consecutive wrong passwords the user has entered
        is_locked      — True if the account has been locked due to too many failures
    """

    __tablename__ = "users"

    id              = db.Column(db.Integer,  primary_key=True)
    username        = db.Column(db.String(80), unique=True, nullable=False)
    password_hash   = db.Column(db.String(200), nullable=False)   # bcrypt hash
    role            = db.Column(db.String(20), default="user")
    failed_attempts = db.Column(db.Integer,  default=0)
    is_locked       = db.Column(db.Boolean,  default=False)

    # Password hashing
    
    def set_password(self, plaintext_password: str) -> None:
        """
        Hash and store the password using bcrypt.

        How bcrypt works:
          1. A random 'salt' is generated (makes every hash unique, even for the
             same password — prevents rainbow table attacks).
          2. The password + salt are run through the bcrypt algorithm many times
             (work factor controls how slow/expensive this is).
          3. The resulting hash includes the salt, so we only need one column.

        We store the hash as a string for SQLite compatibility.
        """
        # bcrypt.gensalt() automatically creates a secure random salt.
        # The default work factor (12) is a good balance of security vs speed.
        salt          = bcrypt.gensalt()
        hashed_bytes  = bcrypt.hashpw(plaintext_password.encode("utf-8"), salt)
        self.password_hash = hashed_bytes.decode("utf-8")  # store as text

    def check_password(self, plaintext_password: str) -> bool:
        """
        Compare a plaintext password against the stored bcrypt hash.

        bcrypt.checkpw() extracts the salt from the stored hash, re-hashes
        the candidate password with the same salt, and compares the results
        in constant time (preventing timing attacks).

        Returns True if the password matches, False otherwise.
        """
        return bcrypt.checkpw(
            plaintext_password.encode("utf-8"),
            self.password_hash.encode("utf-8")
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"
