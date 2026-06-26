"""
MITRE ATT&CK Mapping Layer
===========================
Maps the dataset's free-text `Attack Type` field onto real MITRE ATT&CK
(Enterprise Matrix) tactics & techniques, so incidents can be displayed on a
proper ATT&CK heatmap.

This is a deliberately simple *lookup* mapping (attack-type -> technique).
A production SOC would map at the individual-indicator level, but for a
dataset whose only attack-relevant field is a coarse category, a curated
lookup table is the honest and correct approach — and it's exactly what the
project proposal calls for ("MITRE mapping module").
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str  # MITRE ATT&CK tactic (kill-chain stage)


# Curated mapping: dataset Attack Type -> one or more representative
# MITRE ATT&CK techniques. Picked for being the most common/representative
# technique(s) analysts associate with each attack category.
ATTACK_TYPE_TO_MITRE: dict[str, list[MitreTechnique]] = {
    "Ransomware": [
        MitreTechnique("T1486", "Data Encrypted for Impact", "Impact"),
        MitreTechnique("T1490", "Inhibit System Recovery", "Impact"),
    ],
    "Intrusion": [
        MitreTechnique("T1190", "Exploit Public-Facing Application", "Initial Access"),
        MitreTechnique("T1078", "Valid Accounts", "Initial Access"),
    ],
    "SQL Injection": [
        MitreTechnique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ],
    "DDoS": [
        MitreTechnique("T1498", "Network Denial of Service", "Impact"),
    ],
    "Phishing": [
        MitreTechnique("T1566", "Phishing", "Initial Access"),
    ],
    "XSS": [
        MitreTechnique("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution"),
    ],
    "Malware": [
        MitreTechnique("T1204", "User Execution", "Execution"),
        MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution"),
    ],
}

# Fallback for any attack type not in the table above (keeps the system
# robust if new categories show up in a different dataset).
DEFAULT_TECHNIQUE = [MitreTechnique("T1583", "Acquire Infrastructure", "Resource Development")]


def map_attack_type(attack_type: str) -> list[MitreTechnique]:
    return ATTACK_TYPE_TO_MITRE.get(attack_type, DEFAULT_TECHNIQUE)


def all_tactics_summary() -> dict[str, int]:
    """Count how many techniques fall under each tactic, for reference/UI legends."""
    counts: dict[str, int] = {}
    for techniques in ATTACK_TYPE_TO_MITRE.values():
        for t in techniques:
            counts[t.tactic] = counts.get(t.tactic, 0) + 1
    return counts


if __name__ == "__main__":
    for attack, techs in ATTACK_TYPE_TO_MITRE.items():
        print(attack, "->", [(t.technique_id, t.tactic) for t in techs])
