"""
Audit Log
==========
A real, server-side record of meaningful actions taken in the system —
logins, incident status changes, report exports, searches. This backs
the frontend's "Audit Trail" view with actual events instead of
hard-coded rows.

Storage is an in-memory ring buffer. That's a deliberate scope decision:
this is a simulation platform that re-derives all of its data from a
static CSV on every restart (see ingestion/loader.py), so persisting the
audit log to disk/DB would be inconsistent with how every other module
already behaves — restart the server and the "world" resets. If this
were ever deployed for real, this module is exactly where you'd swap in
a database-backed implementation without touching any call sites.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

MAX_ENTRIES = 500


@dataclass
class AuditEntry:
    timestamp: str
    actor: str          # username
    actor_role: str      # role_label, e.g. "SOC Manager"
    action: str          # short verb phrase, e.g. "Changed incident status"
    target: str          # what it was done to, e.g. an incident_id
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


_LOG: deque[AuditEntry] = deque(maxlen=MAX_ENTRIES)


def record(actor: str, actor_role: str, action: str, target: str = "", detail: str = "") -> AuditEntry:
    entry = AuditEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        actor=actor,
        actor_role=actor_role,
        action=action,
        target=target,
        detail=detail,
    )
    _LOG.appendleft(entry)  # newest first
    return entry


def get_log(limit: Optional[int] = None) -> list[dict]:
    entries = list(_LOG)
    if limit is not None:
        entries = entries[:limit]
    return [e.to_dict() for e in entries]
