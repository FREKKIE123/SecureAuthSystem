"""
controllers/token_controller.py — JWT Token Logic
---------------------------------------------------
Handles creation and validation of JSON Web Tokens (JWTs).

What is a JWT?
  A JWT is a compact, URL-safe token made of three Base64-encoded parts:
    Header.Payload.Signature

  - Header:    algorithm used (HS256) and token type (JWT)
  - Payload:   the claims (data we want to convey, e.g. user_id, role)
  - Signature: HMAC-SHA256(base64(header) + "." + base64(payload), SECRET_KEY)

  The signature makes tampering impossible — any change to the header or
  payload produces a completely different signature, which we detect on
  validation.

IMPORTANT: The payload is Base64-encoded, NOT encrypted. Anyone can decode
it.  Therefore we NEVER put sensitive data (passwords, emails) in the payload.
"""

import uuid
from datetime import datetime, timezone, timedelta

import jwt                         # PyJWT library
from flask import current_app      # Access Flask app config at runtime


# Token generation
def generate_token(user_id: int, role: str) -> str:
    """
    Create a signed JWT for an authenticated user.
    Claims included in the payload:
      sub  — subject: who the token is about (user_id as string, not username)
      role — the user's role ("user" or "admin")
      iss  — issuer: identifies the system that created the token
      iat  — issued-at: when the token was created (Unix timestamp)
      exp  — expiration: when the token becomes invalid (Unix timestamp)
      jti  — JWT ID: a unique identifier for this specific token (for revocation)
    The token is signed with HMAC-SHA256 using the app's SECRET_KEY.
    PyJWT automatically adds iat and exp handling.
    """

    config = current_app.config

    now        = datetime.now(timezone.utc)
    expiry     = now + timedelta(minutes=config["JWT_EXPIRY_MINUTES"])
    unique_id  = str(uuid.uuid4())   # Unique token identifier (for revocation lists)

    payload = {
        "sub":  str(user_id),           # Subject — user_id only, NOT username
        "role": role,                   # Role for authorisation checks
        "iss":  config["JWT_ISSUER"],   # Issuer
        "iat":  now,                    # Issued-at time
        "exp":  expiry,                 # Expiration time
        "jti":  unique_id,              # Unique JWT identifier
    }

    # jwt.encode() signs the payload using HS256 + SECRET_KEY
    # and returns the final "header.payload.signature" string.
    token = jwt.encode(
        payload,
        config["SECRET_KEY"],
        algorithm=config["JWT_ALGORITHM"]
    )

    return token


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

# In-memory set of revoked JTIs (token unique IDs).
# In production this would be stored in Redis or the database.
_revoked_jtis: set = set()

def revoke_token(token: str) -> None:
    """
    Add a token's unique ID (jti) to the revocation list.
    After revocation, validate_token() will reject this token.

    Called during logout.
    """
    try:
        # Decode without verifying expiry so we can still revoke expired tokens
        payload = jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=[current_app.config["JWT_ALGORITHM"]],
            options={"verify_exp": False}
        )
        jti = payload.get("jti")
        if jti:
            _revoked_jtis.add(jti)
    except Exception:
        pass   # If the token is already malformed, there is nothing to revoke


def validate_token(token: str) -> dict:
    """
    Validate a JWT and return a result dictionary.

    Checks performed:
      1. Signature validity  — was the token signed with our SECRET_KEY?
      2. Expiry              — is the token still within its validity window?
      3. Revocation          — has the token been explicitly invalidated?

    Returns a dict:
      { "valid": True,  "payload": {...} }           — on success
      { "valid": False, "error":   "reason string" } — on failure
    """

    try:
        # jwt.decode() verifies BOTH the signature and the expiry claim.
        # If either check fails it raises an exception — we handle each separately.
        payload = jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=[current_app.config["JWT_ALGORITHM"]],
            issuer=current_app.config["JWT_ISSUER"],
        )

        # Check if this specific token has been revoked (e.g. user logged out)
        jti = payload.get("jti")
        if jti and jti in _revoked_jtis:
            return {"valid": False, "error": "Token has been revoked (user logged out)."}

        return {"valid": True, "payload": payload}

    except jwt.ExpiredSignatureError:
        # The exp claim is in the past — token has expired normally
        return {"valid": False, "error": "Token has expired. Please log in again."}

    except jwt.InvalidIssuerError:
        # The iss claim doesn't match — token is from a different system
        return {"valid": False, "error": "Token is invalid or tampered — issuer mismatch."}

    except jwt.InvalidTokenError:
        # Catches: bad signature, malformed token, invalid structure, etc.
        return {"valid": False, "error": "Token is invalid or tampered. Verification failed."}

    except Exception as e:
        # Catch-all — never let an unexpected error crash the app
        return {"valid": False, "error": f"An unexpected error occurred: {str(e)}"}
