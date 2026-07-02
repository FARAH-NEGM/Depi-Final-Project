"""
SOC Response Playbooks
======================
Small in-memory response module used by the graduation demo.
It makes the project closer to a real SOC/SIEM tool by giving each
incident recommended response actions, action execution history, and
analyst notes without adding database complexity.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class ResponseActionEntry:
    timestamp: str
    incident_id: str
    action_id: str
    action_label: str
    actor: str
    actor_role: str
    result: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalystNote:
    timestamp: str
    incident_id: str
    author: str
    author_role: str
    note: str

    def to_dict(self) -> dict:
        return asdict(self)


_ACTION_HISTORY: dict[str, list[ResponseActionEntry]] = {}
_NOTES: dict[str, list[AnalystNote]] = {}


def _incident_value(incident: Any, name: str, default: Any = None) -> Any:
    if isinstance(incident, dict):
        return incident.get(name, default)
    return getattr(incident, name, default)


def _base_action(
    action_id: str,
    label: str,
    description: str,
    phase: str,
    target_status: str | None = None,
    effort: str = "Medium",
) -> dict:
    return {
        "id": action_id,
        "label": label,
        "description": description,
        "phase": phase,
        "target_status": target_status,
        "effort": effort,
    }


def build_playbook(incident: Any) -> dict:
    """Return a realistic but simulated SOC response playbook."""
    attack_type = str(_incident_value(incident, "attack_type", "Unknown"))
    severity = str(_incident_value(incident, "severity", "Medium"))
    risk_score = float(_incident_value(incident, "risk_score", 0) or 0)
    hostname = str(_incident_value(incident, "hostname", "affected endpoint") or "affected endpoint")
    source_ip = str(_incident_value(incident, "source_ip", "source IP") or "source IP")
    user = str(_incident_value(incident, "user", "affected user") or "affected user")
    incident_id = str(_incident_value(incident, "incident_id", "") or "")

    attack_l = attack_type.lower()
    actions: list[dict] = [
        _base_action(
            "open_investigation",
            "Open investigation case",
            "Assign ownership, confirm affected asset, and start the evidence timeline.",
            "Triage",
            target_status="Investigating",
            effort="Low",
        ),
        _base_action(
            "collect_evidence",
            "Collect evidence package",
            "Export event timeline, MITRE mapping, source/destination IPs, and affected user context.",
            "Investigation",
            effort="Medium",
        ),
    ]

    if risk_score >= 60 or severity in {"Critical", "High"}:
        actions.extend([
            _base_action(
                "isolate_endpoint",
                f"Isolate {hostname}",
                "Simulate network isolation for the endpoint to stop lateral movement while preserving forensic data.",
                "Containment",
                target_status="Contained",
                effort="High",
            ),
            _base_action(
                "block_source_ip",
                f"Block {source_ip}",
                "Add the source IP to a simulated firewall block list and monitor for repeat attempts.",
                "Containment",
                effort="Low",
            ),
        ])

    if "phishing" in attack_l:
        actions.extend([
            _base_action(
                "reset_user_password",
                f"Reset password for {user}",
                "Force credential reset and revoke active sessions for the affected identity.",
                "Containment",
                effort="Medium",
            ),
            _base_action(
                "email_sweep",
                "Search mailbox for similar messages",
                "Simulate an email-security sweep for same sender, subject, URL, and attachment hash.",
                "Investigation",
                effort="Medium",
            ),
        ])
    elif "malware" in attack_l or "ransomware" in attack_l:
        actions.extend([
            _base_action(
                "run_edr_scan",
                "Run endpoint malware scan",
                "Simulate EDR scan for malicious process, persistence, and suspicious file hashes.",
                "Investigation",
                effort="Medium",
            ),
            _base_action(
                "restore_backup_check",
                "Check backup readiness",
                "Confirm clean restore point and recovery priority in case containment fails.",
                "Recovery",
                effort="Medium",
            ),
        ])
    elif "sql" in attack_l or "xss" in attack_l:
        actions.extend([
            _base_action(
                "enable_waf_rule",
                "Enable WAF rule",
                "Simulate a web application firewall rule for the detected injection pattern.",
                "Containment",
                effort="Low",
            ),
            _base_action(
                "notify_appsec",
                "Notify application security owner",
                "Create an escalation note for code review, input validation, and patch verification.",
                "Escalation",
                effort="Low",
            ),
        ])
    elif "ddos" in attack_l:
        actions.extend([
            _base_action(
                "rate_limit_traffic",
                "Apply rate limiting",
                "Simulate rate limiting and upstream filtering for high-volume source traffic.",
                "Containment",
                effort="Medium",
            ),
        ])
    else:
        actions.append(_base_action(
            "monitor_for_recurrence",
            "Monitor for recurrence",
            "Keep the incident open and watch related users, IPs, and MITRE techniques for repeated activity.",
            "Monitoring",
            effort="Low",
        ))

    actions.append(_base_action(
        "close_with_lessons",
        "Close with lessons learned",
        "Document root cause, final status, and recommended control improvement.",
        "Recovery",
        target_status="Resolved",
        effort="Low",
    ))

    if risk_score >= 80:
        priority = "P1 - Critical"
        rationale = "High risk score requires immediate containment, evidence collection, and manager visibility."
    elif risk_score >= 60:
        priority = "P2 - High"
        rationale = "High-risk incident should be investigated and contained before it spreads."
    elif risk_score >= 30:
        priority = "P3 - Medium"
        rationale = "Moderate risk; investigate, validate impact, and monitor for recurrence."
    else:
        priority = "P4 - Low"
        rationale = "Low-risk activity; monitor and close when no recurrence is observed."

    return {
        "incident_id": incident_id,
        "priority": priority,
        "rationale": rationale,
        "actions": actions,
        "history": get_action_history(incident_id),
    }


def execute_action(incident: Any, action_id: str, actor: str, actor_role: str) -> tuple[dict | None, str | None]:
    playbook = build_playbook(incident)
    action = next((a for a in playbook["actions"] if a["id"] == action_id), None)
    if not action:
        return None, "unknown action"

    incident_id = playbook["incident_id"]
    entry = ResponseActionEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        incident_id=incident_id,
        action_id=action_id,
        action_label=action["label"],
        actor=actor,
        actor_role=actor_role,
        result=f"Simulated SOC action completed: {action['description']}",
    )
    _ACTION_HISTORY.setdefault(incident_id, []).insert(0, entry)
    return entry.to_dict(), None


def get_action_history(incident_id: str) -> list[dict]:
    return [entry.to_dict() for entry in _ACTION_HISTORY.get(incident_id, [])]


def add_note(incident_id: str, author: str, author_role: str, note: str) -> tuple[dict | None, str | None]:
    clean_note = (note or "").strip()
    if not clean_note:
        return None, "note cannot be empty"
    if len(clean_note) > 1200:
        return None, "note must be 1200 characters or less"

    entry = AnalystNote(
        timestamp=datetime.now(timezone.utc).isoformat(),
        incident_id=incident_id,
        author=author,
        author_role=author_role,
        note=clean_note,
    )
    _NOTES.setdefault(incident_id, []).insert(0, entry)
    return entry.to_dict(), None


def get_notes(incident_id: str) -> list[dict]:
    return [note.to_dict() for note in _NOTES.get(incident_id, [])]
