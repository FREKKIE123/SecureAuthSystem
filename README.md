# SecureAuth System

A cybersecurity project demonstrating **token-based authentication** using industry-standard tools: JWT, bcrypt, Flask, and SQLite.

---

## Overview

SecureAuth is a complete, end-to-end authentication system that demonstrates:

- **Secure password storage** via bcrypt hashing with automatic salting
- **Stateless authentication** via JSON Web Tokens (JWT)
- **HMAC-SHA256 token signing** to prevent tampering
- **Account lockout** after repeated failed login attempts
- **Token revocation** on logout

The system is built with the MVC pattern and is intentionally straightforward — clean enough to understand and extend, but correct enough to serve as a real-world reference.

---

## Features

| Feature | Detail |
|---|---|
| Registration | bcrypt-hashed passwords, duplicate-username check, input validation |
| Login | Credential check, failed-attempt tracking, lockout at 3 failures |
| JWT Generation | HS256 signed, includes sub, role, iss, iat, exp, jti |
| Dashboard | Displays token, role badge, JWT structure breakdown |
| Token Verification | Checks signature, expiry, issuer, and revocation |
| Logout | Revokes token via jti blacklist, clears session |
| Dark / Light Mode | CSS custom properties, localStorage preference saved |

---

## Project Structure

```
auth_system/
├── app.py                    # Flask application factory + entry point
├── config.py                 # Centralised configuration (keys, settings)
├── requirements.txt          # Python dependencies
├── models/
│   ├── __init__.py           # SQLAlchemy db instance
│   └── user.py               # User model (no plaintext passwords)
├── controllers/
│   ├── __init__.py
│   ├── auth_controller.py    # All HTTP routes (register, login, logout, etc.)
│   └── token_controller.py   # JWT generation, validation, revocation
├── templates/
│   ├── base.html             # Shared layout (nav, flash messages, footer)
│   ├── index.html            # Landing page
│   ├── register.html         # Registration form
│   ├── login.html            # Login form
│   ├── dashboard.html        # Protected dashboard + token display
│   └── verify_token.html     # Token verification form + result
└── static/
    └── style.css             # Dark/light theme, full component styles
```

---

## Setup Instructions

### 1. Prerequisites

- Python 3.10 or newer
- pip

### 2. Clone or copy the project

```bash
cd auth_system
```

### 3. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

### 6. Open in your browser

Navigate to: **http://127.0.0.1:5000**

> The SQLite database (`auth_system.db`) is created automatically on first run.

---

## Usage Walkthrough

```
1. Home page    → Click "Create Account"
2. Register     → Enter username + password
3. Login        → Enter credentials
4. Dashboard    → View your JWT token (3 coloured sections explained)
5. Verify Token → Your token is pre-filled; click Verify
6. Logout       → Token is revoked; session cleared
```

---

## Security Explanation

### Password Hashing (bcrypt)

Passwords are **never stored in plaintext**. When a user registers:

1. `bcrypt.gensalt()` generates a unique random salt (128-bit).
2. The salt + password are passed through the bcrypt key derivation function with a work factor of 12 (meaning 2¹² = 4096 iterations).
3. The resulting hash (which contains the salt) is stored in the database.

On login, `bcrypt.checkpw()` re-derives the hash using the stored salt and compares in constant time, preventing timing attacks.

### JWT Token Generation

After a successful login, a JWT is created with these claims:

| Claim | Purpose |
|---|---|
| `sub` | Subject — the user's numeric ID (not username) |
| `role` | User's role for authorisation decisions |
| `iss` | Issuer — identifies this system |
| `iat` | Issued-at — Unix timestamp of creation |
| `exp` | Expiry — 15 minutes after `iat` |
| `jti` | JWT ID — unique UUID for revocation |

The token is signed with **HMAC-SHA256** (`HS256`) using the application's `SECRET_KEY`. Any modification to the header or payload produces a completely different signature, which is detected immediately on validation.

### Why the Payload is Not Sensitive

The JWT payload is Base64-encoded, **not encrypted** — anyone can decode it. This is why we only store `user_id` (not the username or email) and the `role`. No sensitive personal data goes into the token.

### Token Revocation

On logout, the token's `jti` (unique ID) is added to an in-memory blacklist. `validate_token()` checks this blacklist before accepting any token. In a production system, this would be stored in Redis or the database to survive server restarts.

### Account Lockout

After **3 consecutive failed login attempts**, the `is_locked` flag on the user record is set to `True`. Locked accounts are rejected even with the correct password, requiring administrator intervention. This prevents brute-force attacks.

### Input Validation

All form inputs are validated before processing:
- Username and password are required and stripped of whitespace.
- Minimum lengths are enforced (3 chars for username, 8 for password).
- Password confirmation must match.
- SQLAlchemy's parameterised queries prevent SQL injection.

---

## Configuration

Edit `config.py` to change:

```python
SECRET_KEY          = "..."   # Use a long random string in production
JWT_EXPIRY_MINUTES  = 15      # How long tokens stay valid
MAX_FAILED_ATTEMPTS = 3       # Login attempts before lockout
```

In production, set `SECRET_KEY` via an environment variable:

```bash
export SECRET_KEY="your-very-long-random-secret"
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Database | SQLite via SQLAlchemy |
| Password Hashing | bcrypt |
| Token Signing | PyJWT (HS256) |
| Frontend | HTML5, CSS3 (no frameworks) |
| Fonts | Syne + JetBrains Mono (Google Fonts) |

---

