"""
Authentication — User Directory & Session Helpers
=====================================================
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
ROLE_ANALYST = "analyst"
ROLE_MANAGER = "manager"
ALL_ROLES    = (ROLE_ANALYST, ROLE_MANAGER)

ROLE_LABELS = {
    ROLE_ANALYST: "Security Analyst",
    ROLE_MANAGER: "SOC Manager",
}


@dataclass
class User:
    username:      str
    display_name:  str
    role:          str
    password_hash: str
    password_salt: str
    created_at:    str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_public_dict(self) -> dict:
        """Never include password material in anything sent to the client."""
        return {
            "username":     self.username,
            "display_name": self.display_name,
            "role":         self.role,
            "role_label":   ROLE_LABELS.get(self.role, self.role),
        }


# ---------------------------------------------------------------------------
# Password hashing  (PBKDF2-HMAC-SHA256, stdlib only)
# ---------------------------------------------------------------------------
_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    salt   = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return digest.hex(), salt.hex()


def _verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    salt           = bytes.fromhex(password_salt)
    candidate_hash, _ = _hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, password_hash)


# ---------------------------------------------------------------------------
# In-memory user directory
# ---------------------------------------------------------------------------
def _build_directory() -> dict[str, User]:
    seed = [
        ("analyst", "Security Analyst", ROLE_ANALYST, "analyst123"),
        ("manager", "SOC Manager",      ROLE_MANAGER, "manager123"),
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


def authenticate(username: str, password: str) -> Optional[User]:
    user = _USERS.get(username)
    if not user:
        return None
    if not _verify_password(password, user.password_hash, user.password_salt):
        return None
    return user


# ---------------------------------------------------------------------------
# Register  — creates a new account and adds it to the in-memory directory
# ---------------------------------------------------------------------------
def register(
    username:     str,
    display_name: str,
    role:         str,
    password:     str,
) -> tuple[Optional[User], Optional[str]]:
    """
    Validate and create a new user.

    Returns
    -------
    (User, None)       on success
    (None, error_msg)  on validation failure
    """
    username = username.strip().lower()

    if not username:
        return None, "Username is required."
    if len(username) < 3:
        return None, "Username must be at least 3 characters."
    if not username.isalnum() and "_" not in username:
        return None, "Username can only contain letters, numbers, and underscores."
    if username in _USERS:
        return None, "Username already exists. Please choose another."
    if role not in ALL_ROLES:
        return None, f"Invalid role. Choose: {', '.join(ALL_ROLES)}."
    if not password:
        return None, "Password is required."
    if len(password) < 6:
        return None, "Password must be at least 6 characters."

    display_name = display_name.strip() or username

    pw_hash, pw_salt = _hash_password(password)
    user = User(
        username=username,
        display_name=display_name,
        role=role,
        password_hash=pw_hash,
        password_salt=pw_salt,
    )
    _USERS[username] = user
    return user, None


# ---------------------------------------------------------------------------
# Demo accounts helper (shown on the login screen)
# ---------------------------------------------------------------------------
def list_demo_accounts() -> list[dict]:
    return [
        {"username": "analyst", "password": "analyst123",
         "role": ROLE_ANALYST, "role_label": ROLE_LABELS[ROLE_ANALYST]},
        {"username": "manager", "password": "manager123",
         "role": ROLE_MANAGER, "role_label": ROLE_LABELS[ROLE_MANAGER]},
    ]
