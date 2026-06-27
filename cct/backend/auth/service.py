"""
Authentication
================
Login/session system using Flask's built-in signed-cookie sessions plus
werkzeug's password hashing — no extra dependencies needed.

Roles
------
Matches the Use Case Diagram's two actors:
  - "Security Analyst" : can view everything, transition incidents through
                          the state machine, and trigger Response Engine
                          decisions.
  - "SOC Manager"       : everything an analyst can do, PLUS triggering the
                           Attack Propagation Engine's "Simulate Attack"
                           use case (matches the diagram, where Simulate
                           Attack is a SOC Manager-only use case).

This is a real, working login: passwords are hashed (never stored or
compared in plaintext), sessions are Flask's signed cookies (tamper-evident,
no server-side session store needed for a project this size), and routes
are protected with a `login_required` decorator. It is, however, scoped
for a local single-machine demo, not internet-facing production use — see
the README for what that distinction means in practice (HTTPS, CSRF
protection, rate limiting, etc. would need to be added for real deployment).
"""

from __future__ import annotations

from functools import wraps

from flask import jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash

from db.schema import get_connection


def create_user(username: str, password: str, role: str = "Security Analyst") -> dict:
    if role not in ("Security Analyst", "SOC Manager"):
        raise ValueError(f"Invalid role: {role}")

    conn = get_connection()
    try:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise ValueError(f"Username '{username}' already exists")

        password_hash = generate_password_hash(password)
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        conn.commit()
        return {"id": cursor.lastrowid, "username": username, "role": role}
    finally:
        conn.close()


def verify_login(username: str, password: str) -> dict | None:
    """Returns the user dict (without password_hash) if credentials are
    valid, else None."""
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return None
        if not check_password_hash(row["password_hash"], password):
            return None
        return {"id": row["id"], "username": row["username"], "role": row["role"]}
    finally:
        conn.close()


def current_user() -> dict | None:
    """Read the logged-in user from the Flask session, if any."""
    if "user_id" not in session:
        return None
    return {
        "id": session["user_id"],
        "username": session.get("username"),
        "role": session.get("role"),
    }


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return jsonify({"error": "authentication required"}), 401
        return fn(*args, **kwargs)
    return wrapper


def role_required(*roles: str):
    """Decorator factory: restrict a route to specific roles (e.g.
    @role_required('SOC Manager') for the Simulate Attack use case)."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                return jsonify({"error": "authentication required"}), 401
            if user["role"] not in roles:
                return jsonify({"error": f"requires role: {' or '.join(roles)}"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def ensure_demo_users() -> None:
    """Create the two demo accounts (one per role from the Use Case
    Diagram) if no users exist yet, so the project is demoable out of the
    box without a separate registration step. Credentials are printed to
    the console on first run only."""
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    finally:
        conn.close()

    if count > 0:
        return

    create_user("analyst", "analyst123", role="Security Analyst")
    create_user("manager", "manager123", role="SOC Manager")
    print("Demo accounts created:")
    print("  Security Analyst -> username: analyst  password: analyst123")
    print("  SOC Manager      -> username: manager  password: manager123")


if __name__ == "__main__":
    ensure_demo_users()
    print()
    print("Verify login:", verify_login("analyst", "analyst123"))
    print("Wrong password:", verify_login("analyst", "wrong"))
    print("Unknown user:", verify_login("nobody", "x"))
