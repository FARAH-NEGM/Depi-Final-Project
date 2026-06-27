"""
Response Engine
================
Rule-based containment decisions for incidents.
Produces a human-readable decision + reasoning for each incident.
"""
from __future__ import annotations

PLAYBOOKS = [
    {
        "id": "pb-block-critical",
        "name": "Auto-Block Critical Threats",
        "description": "Immediately block the source IP and quarantine the user account for any Critical severity incident.",
        "trigger": "severity == Critical",
        "action": "Block + Quarantine",
    },
    {
        "id": "pb-escalate-high",
        "name": "Escalate High Severity",
        "description": "Escalate to SOC Manager and assign to on-call analyst for High severity events.",
        "trigger": "severity == High",
        "action": "Escalate + Assign",
    },
    {
        "id": "pb-log-medium",
        "name": "Log & Monitor Medium",
        "description": "Log the event, increase monitoring frequency, and flag for analyst review within 4 hours.",
        "trigger": "severity == Medium",
        "action": "Log + Monitor",
    },
    {
        "id": "pb-watch-low",
        "name": "Watchlist Low Events",
        "description": "Add source IP to watchlist. Alert if 3 or more Low events from same source within 24h.",
        "trigger": "severity == Low",
        "action": "Watchlist",
    },
    {
        "id": "pb-ransomware",
        "name": "Ransomware Containment",
        "description": "Isolate affected host, snapshot disk, notify IR team, and preserve forensic evidence.",
        "trigger": "attack_type == Ransomware",
        "action": "Isolate + Snapshot",
    },
    {
        "id": "pb-exfil",
        "name": "Exfiltration Response",
        "description": "Block outbound connections from source IP, identify data classification, notify DPO.",
        "trigger": "attack_type == Data Exfiltration",
        "action": "Block Outbound + Notify DPO",
    },
]

REASONING_MAP = {
    "Critical": "Critical severity triggers immediate containment per policy P-001.",
    "High": "High severity requires escalation and analyst assignment within 1 hour.",
    "Medium": "Medium severity: log, monitor, and schedule analyst review.",
    "Low": "Low severity: watchlist the source and correlate with future events.",
}

DECISION_MAP = {
    "Critical": "Block source IP and quarantine user account immediately.",
    "High": "Escalate to SOC Manager. Assign to on-call analyst.",
    "Medium": "Log event. Increase monitoring frequency. Flag for review.",
    "Low": "Add source IP to watchlist. Alert on repeat occurrences.",
}

ATTACK_OVERRIDES = {
    "Ransomware": "Isolate host, take disk snapshot, notify Incident Response team.",
    "Data Exfiltration": "Block all outbound from source IP. Notify Data Protection Officer.",
    "Privilege Escalation": "Revoke elevated permissions immediately. Force re-authentication.",
    "Lateral Movement": "Segment the network. Block east-west traffic from source IP.",
}


def make_response_decision(incident_id: str, severity: str, attack_type: str) -> dict:
    decision = ATTACK_OVERRIDES.get(attack_type) or DECISION_MAP.get(severity, "Log and monitor.")
    reasoning = REASONING_MAP.get(severity, "Standard escalation policy applies.")
    return {
        "incident_id": incident_id,
        "decision": decision,
        "reasoning": reasoning,
    }


def get_playbooks() -> list[dict]:
    return PLAYBOOKS
