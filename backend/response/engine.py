"""
Response Engine — turns detection into (simulated) protective action.
=======================================================================
Two modes, held as in-memory runtime state (mirrors how the rest of this
demo backend is a cached, in-memory derivation of the static dataset —
see correlation/engine.py's _CACHE):

  "notify"   (default) — incidents are only surfaced to analysts via the
                          dashboard/audit log. Nothing about the incident
                          changes on its own. This is the current/original
                          behavior of the system.

  "enforce"             — when an incident crosses a severity threshold,
                          the system immediately simulates a containment
                          action (block / quarantine) and updates the
                          incident's status + action_taken fields, the
                          same way a human analyst would.

Either mode, a manual per-incident trigger is always available via
apply_response() so an analyst can act on a single incident without
flipping the global switch.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from correlation.engine import Incident

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
VALID_MODES = ["notify", "enforce"]

# Which simulated action fits which attack type — mirrors real playbooks
# (network-layer attacks get blocked at the source; host/account-level
# attacks get quarantined/isolated).
ACTION_BY_ATTACK_TYPE: dict[str, str] = {
    "Intrusion":     "Blocked",
    "SQL Injection": "Blocked",
    "XSS":           "Blocked",
    "DDoS":          "Blocked",
    "Phishing":      "Quarantined",
    "Malware":       "Quarantined",
    "Ransomware":    "Quarantined",
}
DEFAULT_ACTION = "Quarantined"

# Only auto-act on incidents worth acting on. Auto-response never fires on
# Medium/Low or on incidents a human has already started working.
ENFORCE_SEVERITIES = {"Critical", "High"}
ENFORCE_ELIGIBLE_STATUSES = {"Open"}

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
_MODE = "notify"


def get_mode() -> str:
    return _MODE


def set_mode(mode: str) -> str:
    if mode not in VALID_MODES:
        raise ValueError(f"invalid mode: {mode!r}, expected one of {VALID_MODES}")
    global _MODE
    _MODE = mode
    return _MODE


# ---------------------------------------------------------------------------
# Decision + action
# ---------------------------------------------------------------------------
def should_auto_respond(incident: "Incident") -> bool:
    """True if the *current* global mode says this incident should be
    auto-contained right now. Callers should still record an audit entry
    themselves, since this module has no dependency on auth/audit.py."""
    return (
        _MODE == "enforce"
        and incident.severity in ENFORCE_SEVERITIES
        and incident.status in ENFORCE_ELIGIBLE_STATUSES
    )


def apply_response(incident: "Incident", actor: str = "system") -> dict:
    """
    Simulates taking a protective action against an incident: mutates the
    incident in place (status -> Contained, action_taken -> Blocked /
    Quarantined) and returns a small dict describing what happened, for
    the caller to audit-log.
    """
    action = ACTION_BY_ATTACK_TYPE.get(incident.attack_type, DEFAULT_ACTION)
    incident.action_taken = action
    incident.status = "Contained"
    return {
        "incident_id": incident.incident_id,
        "attack_type": incident.attack_type,
        "action":      action,
        "actor":       actor,
        "automatic":   actor == "system",
    }


def auto_respond_all(incidents: list["Incident"], audit_fn=None) -> list[dict]:
    """
    Sweeps a list of incidents and auto-responds to any that qualify under
    the current mode. `audit_fn`, if given, is called as
    audit_fn(incident, result) for every action taken, so app.py can wire
    this into auth/audit.py without this module importing it directly.
    Returns the list of action results (empty if mode is "notify").
    """
    results = []
    if _MODE != "enforce":
        return results
    for incident in incidents:
        if should_auto_respond(incident):
            result = apply_response(incident, actor="system")
            results.append(result)
            if audit_fn:
                audit_fn(incident, result)
    return results
