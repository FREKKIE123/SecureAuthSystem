"""
CET324 - Advanced Cyber Security | Assignment 2
Authentication Token System
Author: Student
Description: A token-based authentication system using bcrypt password hashing,
             RSA encryption, and HMAC-SHA256 signing for token integrity.
"""

import json
import time
import hmac
import hashlib
import base64
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DB_PATH = Path(__file__).parent / "users.db"
ISSUER = "CET324-AuthServer"
TOKEN_LIFETIME_SECONDS = 3600          # 1 hour
RSA_KEY_SIZE = 2048
BCRYPT_ROUNDS = 12                     # Work factor – slow enough to resist brute force

# Permitted access levels (lowest → highest privilege)
ACCESS_LEVELS = ("guest", "user", "moderator", "admin")


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

class KeyManager:
    """Generates and holds an RSA key-pair for the lifetime of the server."""

    def __init__(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()

    # -- private helpers ----------------------------------------------------

    def _private(self):
        return self._private_key

    def _public(self):
        return self._public_key

    # -- public interface ---------------------------------------------------

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt *data* with the RSA public key (OAEP + SHA-256 padding)."""
        return self._public().encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt *ciphertext* with the RSA private key."""
        return self._private().decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def sign(self, data: bytes) -> bytes:
        """Create a PSS-RSA-SHA256 digital signature over *data*."""
        return self._private().sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Return True if *signature* is valid for *data*; False otherwise."""
        try:
            self._public().verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

class UserDatabase:
    """Thin wrapper around SQLite for persistent user storage."""

    def __init__(self, db_path: Path = DB_PATH):
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._create_table()

    def _create_table(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username    TEXT PRIMARY KEY,
                pass_hash   BLOB NOT NULL,
                access_level TEXT NOT NULL DEFAULT 'user',
                created_at  REAL NOT NULL
            )
        """)
        self._conn.commit()

    def add_user(self, username: str, pass_hash: bytes, access_level: str) -> bool:
        """Insert a new user. Returns False if the username already exists."""
        try:
            self._conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?)",
                (username, pass_hash, access_level, time.time())
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> dict | None:
        """Fetch user record or None if not found."""
        cur = self._conn.execute(
            "SELECT username, pass_hash, access_level FROM users WHERE username = ?",
            (username,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {"username": row[0], "pass_hash": row[1], "access_level": row[2]}

    def close(self):
        self._conn.close()


# ---------------------------------------------------------------------------
# Token engine
# ---------------------------------------------------------------------------

class TokenEngine:
    """
    Builds and validates authentication tokens.

    Token structure (three base64url segments joined by '.'):
        1. HEADER  – algorithm / token type (base64url JSON, plaintext)
        2. PAYLOAD – encrypted JSON claims (RSA-OAEP)
        3. SIGNATURE – RSA-PSS digital signature over HEADER.PAYLOAD
    """

    def __init__(self, key_manager: KeyManager):
        self._km = key_manager

    # -- private helpers ----------------------------------------------------

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        # Restore stripped padding
        padding_needed = 4 - len(s) % 4
        if padding_needed != 4:
            s += "=" * padding_needed
        return base64.urlsafe_b64decode(s)

    # -- public interface ---------------------------------------------------

    def create_token(self, username: str, access_level: str) -> str:
        """
        Create a signed, encrypted authentication token.

        The PAYLOAD (containing username and permissions) is RSA-encrypted
        so it cannot be read without the private key. A PSS digital signature
        is appended so any tampering is detectable.
        """
        issued_at = int(time.time())
        expires_at = issued_at + TOKEN_LIFETIME_SECONDS

        # Build header (not sensitive – left as visible metadata)
        header = {
            "alg": "RSA-OAEP-PSS",
            "typ": "AUTH-TOKEN"
        }

        # Build payload (sensitive – will be encrypted)
        payload = {
            "sub": username,
            "access": access_level,
            "iss": ISSUER,
            "iat": issued_at,
            "exp": expires_at
        }

        header_b64 = self._b64url_encode(json.dumps(header).encode())
        payload_bytes = json.dumps(payload).encode()

        # RSA-encrypt the payload so only the server can read it
        encrypted_payload = self._km.encrypt(payload_bytes)
        payload_b64 = self._b64url_encode(encrypted_payload)

        # Sign HEADER.PAYLOAD to prevent tampering
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = self._km.sign(signing_input)
        signature_b64 = self._b64url_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def validate_token(self, token: str) -> dict:
        """
        Validate a token and return a result dictionary.

        Returns:
            {"valid": True, "claims": {...}}
          or
            {"valid": False, "reason": "<human-readable explanation>"}
        """
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {"valid": False, "reason": "Malformed token – wrong number of segments."}

        header_b64, payload_b64, signature_b64 = parts

        # 1. Verify signature integrity
        signing_input = f"{header_b64}.{payload_b64}".encode()
        try:
            signature = self._b64url_decode(signature_b64)
        except Exception:
            return {"valid": False, "reason": "Token signature could not be decoded."}

        if not self._km.verify_signature(signing_input, signature):
            return {"valid": False, "reason": "Signature verification FAILED – token has been tampered with."}

        # 2. Decrypt payload
        try:
            encrypted_payload = self._b64url_decode(payload_b64)
            payload_bytes = self._km.decrypt(encrypted_payload)
            claims = json.loads(payload_bytes.decode())
        except Exception:
            return {"valid": False, "reason": "Payload decryption FAILED – token may be corrupt or forged."}

        # 3. Check expiry
        now = int(time.time())
        if now > claims.get("exp", 0):
            expired_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            return {"valid": False, "reason": f"Token expired at {expired_at}."}

        # 4. Check issuer
        if claims.get("iss") != ISSUER:
            return {"valid": False, "reason": "Token issuer is unrecognised."}

        return {"valid": True, "claims": claims}


# ---------------------------------------------------------------------------
# Authentication service (business logic layer)
# ---------------------------------------------------------------------------

class AuthService:
    """
    High-level authentication service.
    Coordinates user management, password verification and token lifecycle.
    """

    def __init__(self):
        self._db = UserDatabase()
        self._km = KeyManager()
        self._token_engine = TokenEngine(self._km)

    # -- private helpers ----------------------------------------------------

    @staticmethod
    def _validate_username(username: str) -> bool:
        """Allow only alphanumeric + underscore, 3–32 chars. Prevents injection."""
        return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username))

    @staticmethod
    def _validate_password(password: str) -> tuple[bool, str]:
        """Enforce a minimum password policy."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one digit."
        return True, "OK"

    @staticmethod
    def _hash_password(password: str) -> bytes:
        """Hash a password with bcrypt (auto-generates a random salt internally)."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    @staticmethod
    def _check_password(password: str, stored_hash: bytes) -> bool:
        """Constant-time comparison of the supplied password against the stored hash."""
        return bcrypt.checkpw(password.encode(), stored_hash)

    # -- public interface ---------------------------------------------------

    def register(self, username: str, password: str, access_level: str = "user") -> dict:
        """Register a new user. Returns a status dict."""
        if not self._validate_username(username):
            return {"success": False, "message": "Invalid username. Use 3–32 alphanumeric/underscore chars."}

        ok, msg = self._validate_password(password)
        if not ok:
            return {"success": False, "message": msg}

        if access_level not in ACCESS_LEVELS:
            return {"success": False, "message": f"Invalid access level. Choose from: {ACCESS_LEVELS}"}

        pass_hash = self._hash_password(password)
        added = self._db.add_user(username, pass_hash, access_level)
        if not added:
            return {"success": False, "message": "Username already exists."}

        return {"success": True, "message": f"User '{username}' registered with access level '{access_level}'."}

    def login(self, username: str, password: str) -> dict:
        """
        Authenticate a user and issue a token.
        Returns a dict with the token on success, or an error message.
        """
        if not self._validate_username(username):
            return {"success": False, "message": "Invalid username format."}

        user = self._db.get_user(username)
        # Use the same error message whether the user exists or not (prevents enumeration)
        if user is None or not self._check_password(password, bytes(user["pass_hash"])):
            return {"success": False, "message": "Invalid username or password."}

        token = self._token_engine.create_token(username, user["access_level"])
        expires_at = datetime.fromtimestamp(time.time() + TOKEN_LIFETIME_SECONDS, tz=timezone.utc)
        return {
            "success": True,
            "message": "Login successful.",
            "token": token,
            "access_level": user["access_level"],
            "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        }

    def validate_token(self, token: str) -> dict:
        """Validate an existing token and return its claims if valid."""
        return self._token_engine.validate_token(token)

    def close(self):
        self._db.close()


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def print_banner():
    print("=" * 60)
    print("  CET324 Authentication Token System")
    print(f"  Issuer: {ISSUER}")
    print("=" * 60)


def print_menu():
    print("\nOptions:")
    print("  1. Register")
    print("  2. Login")
    print("  3. Validate token")
    print("  4. Exit")
    print("-" * 40)


def format_claims(claims: dict) -> str:
    iat = datetime.fromtimestamp(claims["iat"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    exp = datetime.fromtimestamp(claims["exp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"  Subject    : {claims['sub']}\n"
        f"  Access     : {claims['access']}\n"
        f"  Issuer     : {claims['iss']}\n"
        f"  Issued at  : {iat}\n"
        f"  Expires at : {exp}"
    )


def run_cli():
    print_banner()
    service = AuthService()
    print("\n[INFO] RSA key-pair generated. Server is ready.\n")

    try:
        while True:
            print_menu()
            choice = input("Enter choice: ").strip()

            if choice == "1":
                print("\n-- Register --")
                username = input("Username: ").strip()
                password = input("Password: ").strip()
                print(f"Access levels: {ACCESS_LEVELS}")
                access_level = input("Access level (default=user): ").strip() or "user"
                result = service.register(username, password, access_level)
                status = "✓" if result["success"] else "✗"
                print(f"\n{status} {result['message']}")

            elif choice == "2":
                print("\n-- Login --")
                username = input("Username: ").strip()
                password = input("Password: ").strip()
                result = service.login(username, password)
                if result["success"]:
                    print(f"\n✓ {result['message']}")
                    print(f"  Access level : {result['access_level']}")
                    print(f"  Expires at   : {result['expires_at']}")
                    print(f"\n  Token:\n{result['token']}\n")
                else:
                    print(f"\n✗ {result['message']}")

            elif choice == "3":
                print("\n-- Validate Token --")
                token = input("Paste token: ").strip()
                result = service.validate_token(token)
                if result["valid"]:
                    print("\n✓ Token is VALID.")
                    print(format_claims(result["claims"]))
                else:
                    print(f"\n✗ Token is INVALID: {result['reason']}")

            elif choice == "4":
                print("\nGoodbye.")
                break
            else:
                print("Invalid option. Please choose 1–4.")

    finally:
        service.close()


if __name__ == "__main__":
    run_cli()
