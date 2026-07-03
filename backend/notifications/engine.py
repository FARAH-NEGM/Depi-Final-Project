"""
Escalation Notification Queue
==============================
A tiny in-memory "you were just escalated something" queue, keyed by
role.

Why this exists instead of a client-side (BroadcastChannel/localStorage)
approach: the Flask session here is a single signed cookie for the whole
browser (see auth/users.py + app.py's session usage), not per-tab. That
means you can't actually be signed in as two different roles in two tabs
of the same browser at once — logging in as `responder` in tab B just
replaces tab A's session too. So there's no reliable moment where an
"analyst" tab and a "responder" tab are both live in the same browser to
notify between client-side.

Routing the alert through the server sidesteps that entirely: whichever
browser/session is signed in as the target role picks the notification
up on its next poll of GET /api/notifications, regardless of which
browser/session raised it. Same in-memory-cache caveat as the rest of
this demo (correlation cache, audit log, response mode) — not
persisted, not multi-process safe, fine for a single dev server.
"""

from __future__ import annotations

import itertools
from datetime import datetime

_counter = itertools.count(1)

# role -> list of pending notification dicts
_QUEUE: dict[str, list[dict]] = {}


def push(role: str, title: str, message: str, incident_id: str | None = None) -> dict:
    """Enqueue a notification for whichever session(s) are signed in as `role`."""
    note = {
        "id":          next(_counter),
        "title":       title,
        "message":     message,
        "incident_id": incident_id,
        "created_at":  datetime.utcnow().isoformat(),
    }
    _QUEUE.setdefault(role, []).append(note)
    return note


def pull(role: str) -> list[dict]:
    """
    Return and clear all pending notifications for `role` — consume-once,
    so a toast doesn't reappear on the next poll after it's been shown.
    """
    pending = _QUEUE.get(role, [])
    _QUEUE[role] = []
    return pending
