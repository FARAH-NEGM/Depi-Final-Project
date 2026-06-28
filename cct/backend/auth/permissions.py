"""
Role Permissions
==================
Maps each role to what it's allowed to see/do. Used in two places:

  1. app.py route decorators (`@require_role(...)`) — the real
     enforcement boundary. A 403 here is what actually protects data.
  2. The `/api/auth/me` response — tells the frontend which nav items
     and panels to render, so the UI doesn't show a manager-only chart
     to an analyst (then have it 403).

Per the project's own stakeholder analysis: a Security Analyst's job is
to monitor and triage incidents; a SOC Manager's job is to evaluate
overall system/team performance. So manager-only capability is
performance-oriented (Trust Score leaderboard, MTTD/MTTR metrics),
while day-to-day incident work (viewing incidents, changing their
status, searching, viewing the audit trail) is shared by both roles.
"""

from __future__ import annotations

from auth.users import ROLE_ANALYST, ROLE_MANAGER

PERMISSIONS: dict[str, dict[str, bool]] = {
    ROLE_ANALYST: {
        "view_incidents":        True,
        "change_incident_status": True,
        "view_graph":             True,
        "view_mitre":             True,
        "view_live_feed":         True,
        "view_audit_log":         True,
        "search":                 True,
        "view_trust_scores":      False,
        "view_metrics":           False,
    },
    ROLE_MANAGER: {
        "view_incidents":        True,
        "change_incident_status": True,
        "view_graph":             True,
        "view_mitre":             True,
        "view_live_feed":         True,
        "view_audit_log":         True,
        "search":                 True,
        "view_trust_scores":      True,
        "view_metrics":           True,
    },
}


def permissions_for(role: str) -> dict[str, bool]:
    return PERMISSIONS.get(role, {})


def can(role: str, capability: str) -> bool:
    return PERMISSIONS.get(role, {}).get(capability, False)
