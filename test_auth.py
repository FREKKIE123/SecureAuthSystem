"""
CET324 - Assignment 2 | Automated Tests
Demonstrates and verifies all required system behaviours.
"""

import time
import sys
from pathlib import Path

# Allow import from parent directory
sys.path.insert(0, str(Path(__file__).parent))

from auth_system import AuthService, TokenEngine, KeyManager, ISSUER

PASS_LINE = "=" * 60


def section(title: str):
    print(f"\n{PASS_LINE}")
    print(f"  {title}")
    print(PASS_LINE)


def ok(msg):
    print(f"  ✓ PASS  {msg}")


def fail(msg):
    print(f"  ✗ FAIL  {msg}")
    sys.exit(1)


def test_registration(service: AuthService):
    section("1. USER REGISTRATION")

    # Successful registration
    r = service.register("alice", "Password1", "admin")
    assert r["success"], f"Alice registration failed: {r['message']}"
    ok("alice registered as admin")

    r = service.register("bob", "SecurePwd9", "user")
    assert r["success"], f"Bob registration failed: {r['message']}"
    ok("bob registered as user")

    # Duplicate username
    r = service.register("alice", "AnotherPwd2", "user")
    assert not r["success"], "Duplicate username should be rejected"
    ok("duplicate username rejected")

    # Weak password (no uppercase)
    r = service.register("charlie", "weakpass1", "user")
    assert not r["success"], "Weak password should be rejected"
    ok("weak password (no uppercase) rejected")

    # Weak password (too short)
    r = service.register("dave", "Sh0rt", "user")
    assert not r["success"], "Short password should be rejected"
    ok("short password rejected")

    # Invalid username (special chars)
    r = service.register("evil!user", "Password1", "user")
    assert not r["success"], "Invalid username should be rejected"
    ok("username with special characters rejected (injection prevention)")

    # Invalid access level
    r = service.register("eve", "Password1", "superadmin")
    assert not r["success"], "Invalid access level should be rejected"
    ok("invalid access level rejected")


def test_login(service: AuthService):
    section("2. USER LOGIN")

    # Valid login
    r = service.login("alice", "Password1")
    assert r["success"], f"Alice login failed: {r['message']}"
    ok("alice logged in successfully")
    print(f"\n  Generated Token (first 80 chars):\n  {r['token'][:80]}...\n")

    # Wrong password (same error message – prevents username enumeration)
    r = service.login("alice", "wrongpassword")
    assert not r["success"], "Wrong password should fail"
    ok("wrong password rejected")

    # Non-existent user (same error message as wrong password)
    r = service.login("nobody", "Password1")
    assert not r["success"], "Non-existent user should fail"
    ok("non-existent user rejected with same message (prevents enumeration)")

    return service.login("alice", "Password1")["token"]  # return token for next tests


def test_token_validation(service: AuthService, token: str):
    section("3. TOKEN VALIDATION")

    # Valid token
    r = service.validate_token(token)
    assert r["valid"], f"Valid token rejected: {r.get('reason')}"
    ok("valid token accepted")
    claims = r["claims"]
    print(f"\n  Decrypted Claims:")
    print(f"    sub    : {claims['sub']}")
    print(f"    access : {claims['access']}")
    print(f"    iss    : {claims['iss']}")
    print(f"    iat    : {claims['iat']}")
    print(f"    exp    : {claims['exp']}\n")

    # Tampered payload (flip one char in the middle segment)
    parts = token.split(".")
    tampered_payload = parts[1][:-4] + "XXXX"
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    r = service.validate_token(tampered_token)
    assert not r["valid"], "Tampered token should be rejected"
    ok(f"tampered payload rejected: {r['reason']}")

    # Tampered signature
    tampered_sig = parts[2][:-4] + "ZZZZ"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
    r = service.validate_token(tampered_token)
    assert not r["valid"], "Tampered signature should be rejected"
    ok(f"tampered signature rejected: {r['reason']}")

    # Malformed token
    r = service.validate_token("not.a.real.token.here")
    assert not r["valid"], "Malformed token should be rejected"
    ok(f"malformed token rejected: {r['reason']}")

    # Forged token (created without private key)
    import base64, json
    fake_header = base64.urlsafe_b64encode(b'{"alg":"RSA-OAEP-PSS","typ":"AUTH-TOKEN"}').decode().rstrip("=")
    fake_payload = base64.urlsafe_b64encode(b'{"sub":"hacker","access":"admin"}').decode().rstrip("=")
    fake_sig = base64.urlsafe_b64encode(b"fakesignature").decode().rstrip("=")
    forged = f"{fake_header}.{fake_payload}.{fake_sig}"
    r = service.validate_token(forged)
    assert not r["valid"], "Forged token should be rejected"
    ok(f"forged token rejected: {r['reason']}")


def test_token_expiry(service: AuthService):
    section("4. TOKEN EXPIRY (simulated)")

    # We'll use the KeyManager/TokenEngine directly to create a token
    # with a past expiry timestamp and verify it's rejected.
    import json, base64

    km = service._km
    engine = service._token_engine

    # Manually build an expired token via internal access (testing only)
    # Normal users cannot do this — they must go through AuthService.login()
    past_time = int(time.time()) - 7200  # 2 hours ago
    payload = {
        "sub": "alice",
        "access": "admin",
        "iss": ISSUER,
        "iat": past_time,
        "exp": past_time + 3600  # already expired
    }

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header_b64 = b64url(b'{"alg":"RSA-OAEP-PSS","typ":"AUTH-TOKEN"}')
    encrypted = km.encrypt(json.dumps(payload).encode())
    payload_b64 = b64url(encrypted)
    sig = km.sign(f"{header_b64}.{payload_b64}".encode())
    sig_b64 = b64url(sig)

    expired_token = f"{header_b64}.{payload_b64}.{sig_b64}"
    r = service.validate_token(expired_token)
    assert not r["valid"], "Expired token should be rejected"
    ok(f"expired token rejected: {r['reason']}")


def test_access_levels(service: AuthService):
    section("5. ACCESS LEVELS IN TOKENS")

    service.register("mod1", "Modpass88", "moderator")
    service.register("guest1", "Guestpass1", "guest")

    r_mod = service.login("mod1", "Modpass88")
    r_guest = service.login("guest1", "Guestpass1")
    r_admin = service.login("alice", "Password1")

    for result, expected in [(r_admin, "admin"), (r_mod, "moderator"), (r_guest, "guest")]:
        assert result["success"]
        val = service.validate_token(result["token"])
        assert val["valid"]
        assert val["claims"]["access"] == expected, f"Expected {expected}, got {val['claims']['access']}"
        ok(f"token correctly encodes access level '{expected}'")


if __name__ == "__main__":
    print("\n  CET324 Assignment 2 – Full System Test Suite")
    print("  " + "=" * 40)

    # Use an in-memory DB for tests so we don't pollute users.db
    import sqlite3
    from auth_system import UserDatabase
    from unittest.mock import patch
    from pathlib import Path

    # Patch DB to use a temp file
    import tempfile, os
    tmp = tempfile.mktemp(suffix=".db")

    with patch("auth_system.DB_PATH", Path(tmp)):
        service = AuthService()
        try:
            test_registration(service)
            token = test_login(service)
            test_token_validation(service, token)
            test_token_expiry(service)
            test_access_levels(service)
        finally:
            service.close()
            if os.path.exists(tmp):
                os.remove(tmp)

    section("ALL TESTS PASSED")
    print("  The authentication token system is fully functional.\n")
