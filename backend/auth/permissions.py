"""
Role Permissions
==================
Maps each role to what it's allowed to see/do. Used in two places:

  1. app.py route decorators (`@require_role(...)`) — the real
     enforcement boundary. A 403 here is what actually protects data.
  2. The `/api/auth/me` response — tells the frontend which nav items
     and panels to render, so the UI doesn't show a manager-only chart
     to an analyst (then have it 403).

Three-tier hierarchy, per the project's stakeholder analysis:
  - Security Analyst (Tier 1) — monitors and triages incidents.
  - Incident Responder (Tier 2) — takes action on escalated incidents
    (protective/containment response) and can escalate further if it's
    still above their authority (data breach, exec/legal notification).
  - SOC Manager (Tier 3) — evaluates overall system/team performance and
    is the ceiling of the escalation chain.

So day-to-day incident work (viewing incidents, changing their status,
searching, viewing the audit trail) is shared by all three roles.
Performance-oriented capability (Trust Score leaderboard, MTTD/MTTR
metrics) stays manager-only — that's evaluation of the team, not
incident work, and neither Tier 1 nor Tier 2 needs it to do their job.

`manage_response_mode` (taking protective/containment action, toggling
enforce mode) belongs to whoever actually *acts* on incidents day to
day — Responder and Manager, not Analyst. A Tier-1 analyst validates,
scopes, and classifies, but doesn't push the "contain now" button
themselves; that's the handoff *to* Tier 2.

`escalate_incident` is granted to Analyst and Responder, not Manager —
Manager is the top of the hierarchy, so there's no one for them to
escalate *to*. Who a given role escalates *to* is a separate mapping
(see ESCALATION_TARGET_ROLE in auth/users.py) — this dict only answers
*whether* a role can escalate at all, and both rules gate the real API
route, not just a button.
"""

from __future__ import annotations

from auth.users import ROLE_ANALYST, ROLE_RESPONDER, ROLE_MANAGER

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
        "view_system_health":     False,
        "manage_response_mode":   False,
        "escalate_incident":      True,
    },
    ROLE_RESPONDER: {
        "view_incidents":        True,
        "change_incident_status": True,
        "view_graph":             True,
        "view_mitre":             True,
        "view_live_feed":         True,
        "view_audit_log":         True,
        "search":                 True,
        "view_trust_scores":      False,
        "view_metrics":           False,
        "view_system_health":     False,
        "manage_response_mode":   True,
        "escalate_incident":      True,
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
        "view_system_health":     True,
        "manage_response_mode":   True,
        "escalate_incident":      False,
    },
}


def permissions_for(role: str) -> dict[str, bool]:
    return PERMISSIONS.get(role, {})


def can(role: str, capability: str) -> bool:
    return PERMISSIONS.get(role, {}).get(capability, False)
