"""
Authentication — User Directory & Session Helpers
=====================================================
Lightweight, dependency-free auth layer for the CCT demo backend.

Why this design
-----------------
The project brief calls for roles straight from the stakeholder
analysis in the proposal: Security Analyst, Incident Responder, and SOC
Manager — a three-tier escalation hierarchy (Tier 1 -> Tier 2 -> Tier 3).
There is no real user-management requirement (no signup, no external
IdP), so a small in-memory user directory with salted-hash passwords +
Flask's built-in signed session cookie is the right amount of
engineering — it behaves like real auth (passwords are never stored or
compared in plaintext, sessions are signed, role checks gate real
endpoints) without pulling in a database or a third-party auth provider
for a demo project.

Passwords are hashed with PBKDF2-HMAC-SHA256 (via Python's stdlib
`hashlib`), so nothing here depends on packages outside requirements.txt.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
ROLE_ANALYST   = "analyst"
ROLE_RESPONDER = "responder"
ROLE_MANAGER   = "manager"
ALL_ROLES = (ROLE_ANALYST, ROLE_RESPONDER, ROLE_MANAGER)

ROLE_LABELS = {
    ROLE_ANALYST:   "Security Analyst",
    ROLE_RESPONDER: "Incident Responder",
    ROLE_MANAGER:   "SOC Manager",
}

# ---------------------------------------------------------------------------
# Escalation chain
# ---------------------------------------------------------------------------
# Who a role hands an incident off to. Analyst -> Responder -> Manager;
# Manager has no entry, since they're the top of the hierarchy (mirrors
# escalate_incident being False for ROLE_MANAGER in auth/permissions.py —
# same rule expressed two ways: whether you *can* escalate, and *to whom*).
ESCALATION_TARGET_ROLE: dict[str, str] = {
    ROLE_ANALYST:   ROLE_RESPONDER,
    ROLE_RESPONDER: ROLE_MANAGER,
}


@dataclass
class User:
    username: str
    display_name: str
    role: str
    password_hash: str
    password_salt: str
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_public_dict(self) -> dict:
        """Never include password material in anything sent to the client."""
        return {
            "username": self.username,
            "display_name": self.display_name,
            "role": self.role,
            "role_label": ROLE_LABELS.get(self.role, self.role),
        }


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return digest.hex(), salt.hex()


def _verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    salt = bytes.fromhex(password_salt)
    candidate_hash, _ = _hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, password_hash)


# ---------------------------------------------------------------------------
# User directory
# ---------------------------------------------------------------------------
# Demo accounts matching the project's stakeholder roles (see
# "3.1 Stakeholder Analysis" in the project proposal). In a production
# deployment these would live in a real user table; for this simulation
# platform a small in-memory directory keeps the demo self-contained.

def _build_directory() -> dict[str, User]:
    seed = [
        ("analyst",   "Security Analyst",   ROLE_ANALYST,   "analyst123"),
        ("responder", "Incident Responder", ROLE_RESPONDER, "responder123"),
        ("manager",   "SOC Manager",        ROLE_MANAGER,   "manager123"),
    ]
    directory: dict[str, User] = {}
    for username, display_name, role, password in seed:
        pw_hash, pw_salt = _hash_password(password)
        directory[username] = User(
            username=username,
            display_name=display_name,
            role=role,
            password_hash=pw_hash,
            password_salt=pw_salt,
        )
    return directory


_USERS: dict[str, User] = _build_directory()


def get_user(username: str) -> Optional[User]:
    return _USERS.get(username)


def get_user_on_call(role: str) -> Optional[User]:
    """
    Resolve who a role's escalations land on — e.g. an analyst's target
    is whichever ROLE_RESPONDER account exists; a responder's target is
    whichever ROLE_MANAGER account exists.

    There's no on-call rotation or shift schedule in this demo directory,
    so this returns the first account found for that role — a stand-in
    for "whoever real infra would page." Returns None if no account of
    that role exists (defensive; the seeded directory always has one of
    each).
    """
    for user in _USERS.values():
        if user.role == role:
            return user
    return None


def list_demo_accounts() -> list[dict]:
    """Non-secret demo-account info for the login screen's helper panel."""
    return [
        {"username": "analyst",   "password": "analyst123",   "role": ROLE_ANALYST,   "role_label": ROLE_LABELS[ROLE_ANALYST]},
        {"username": "responder", "password": "responder123", "role": ROLE_RESPONDER, "role_label": ROLE_LABELS[ROLE_RESPONDER]},
        {"username": "manager",   "password": "manager123",   "role": ROLE_MANAGER,   "role_label": ROLE_LABELS[ROLE_MANAGER]},
    ]


def authenticate(username: str, password: str) -> Optional[User]:
    user = _USERS.get(username)
    if not user:
        return None
    if not _verify_password(password, user.password_hash, user.password_salt):
        return None
    return user


def register(
    username: str,
    display_name: str,
    role: str,
    password: str,
) -> tuple[Optional[User], Optional[str]]:
    """
    Create a new account in the in-memory directory.

    Returns (user, None) on success, or (None, error_message) on failure.
    Mirrors the validation the frontend already does client-side, but is
    re-checked here since the client can't be trusted.
    """
    username = (username or "").strip()
    display_name = (display_name or "").strip()
    role = (role or "").strip() or ROLE_ANALYST

    if not username:
        return None, "Username is required."
    if len(username) < 3:
        return None, "Username must be at least 3 characters."
    if not all(c.isalnum() or c in "_-." for c in username):
        return None, "Username can only contain letters, numbers, underscores, hyphens, and periods."
    if username in _USERS:
        return None, "An account with that username already exists."
    if role not in ALL_ROLES:
        return None, f"Role must be one of: {', '.join(ALL_ROLES)}."
    if not password:
        return None, "Password is required."
    if len(password) < 6:
        return None, "Password must be at least 6 characters."

    pw_hash, pw_salt = _hash_password(password)
    user = User(
        username=username,
        display_name=display_name or username,
        role=role,
        password_hash=pw_hash,
        password_salt=pw_salt,
    )
    _USERS[username] = user
    return user, None
