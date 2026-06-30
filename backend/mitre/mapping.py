"""
MITRE ATT&CK Mapping Layer  — Dynamic v2
==========================================
v2 changes vs v1
-----------------
- Dynamic technique selection based on attack_type + attack_signature +
  protocol + severity (not just attack_type).
- Each result includes sub_technique and confidence_score.
- MITRE Tactic Chain (mitre_chain) built from the event context.
- Full backward compatibility: map_attack_type(attack_type) still works.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class MitreTechnique:
    technique_id:    str
    technique_name:  str
    tactic:          str
    sub_technique:   str   = ""       # e.g. "T1059.003"
    confidence_score: float = 1.0     # 0.0 – 1.0


# ---------------------------------------------------------------------------
# Static Catalog  (superset of v1)
# ---------------------------------------------------------------------------

ATTACK_TYPE_TO_MITRE: dict[str, list[MitreTechnique]] = {
    "Ransomware": [
        MitreTechnique("T1486",     "Data Encrypted for Impact",  "Impact",    confidence_score=0.95),
        MitreTechnique("T1490",     "Inhibit System Recovery",    "Impact",    confidence_score=0.85),
        MitreTechnique("T1204",     "User Execution",             "Execution", confidence_score=0.7),
    ],
    "Intrusion": [
        MitreTechnique("T1190",     "Exploit Public-Facing Application", "Initial Access",       confidence_score=0.9),
        MitreTechnique("T1078",     "Valid Accounts",                    "Initial Access",       confidence_score=0.8),
        MitreTechnique("T1046",     "Network Service Discovery",         "Discovery",            confidence_score=0.65),
    ],
    "SQL Injection": [
        MitreTechnique("T1190",     "Exploit Public-Facing Application", "Initial Access",       confidence_score=0.95),
        MitreTechnique("T1059.006", "Python",                            "Execution",            sub_technique="T1059.006", confidence_score=0.6),
    ],
    "DDoS": [
        MitreTechnique("T1498",     "Network Denial of Service",         "Impact",               confidence_score=0.95),
        MitreTechnique("T1499",     "Endpoint Denial of Service",        "Impact",               confidence_score=0.75),
    ],
    "Phishing": [
        MitreTechnique("T1566",     "Phishing",                          "Initial Access",       confidence_score=0.95),
        MitreTechnique("T1566.001", "Spearphishing Attachment",          "Initial Access",       sub_technique="T1566.001", confidence_score=0.7),
        MitreTechnique("T1078",     "Valid Accounts",                    "Defense Evasion",      confidence_score=0.6),
    ],
    "XSS": [
        MitreTechnique("T1059.007", "JavaScript",                        "Execution",            sub_technique="T1059.007", confidence_score=0.9),
        MitreTechnique("T1185",     "Browser Session Hijacking",         "Collection",           confidence_score=0.75),
    ],
    "Malware": [
        MitreTechnique("T1204",     "User Execution",                    "Execution",            confidence_score=0.9),
        MitreTechnique("T1059",     "Command and Scripting Interpreter", "Execution",            confidence_score=0.8),
        MitreTechnique("T1055",     "Process Injection",                 "Defense Evasion",      confidence_score=0.65),
    ],
}

DEFAULT_TECHNIQUE = [MitreTechnique("T1583", "Acquire Infrastructure", "Resource Development", confidence_score=0.3)]

# ---------------------------------------------------------------------------
# Signature → Technique overrides
# ---------------------------------------------------------------------------
# These boost or swap the primary technique based on the attack_signature
# field (Known Pattern A/B/C, Zero-Day, etc.)

SIGNATURE_OVERRIDES: dict[str, dict] = {
    "Known Pattern A": {
        "confidence_boost": 0.05,
        "extra_technique":  MitreTechnique("T1027", "Obfuscated Files or Information", "Defense Evasion", confidence_score=0.6),
    },
    "Known Pattern B": {
        "confidence_boost": 0.05,
        "extra_technique":  MitreTechnique("T1036", "Masquerading", "Defense Evasion", confidence_score=0.55),
    },
    "Known Pattern C": {
        "confidence_boost": 0.03,
        "extra_technique":  MitreTechnique("T1071", "Application Layer Protocol", "Command and Control", confidence_score=0.6),
    },
    "Zero-Day": {
        "confidence_boost": -0.15,          # unknown signature = lower confidence
        "extra_technique":  MitreTechnique("T1203", "Exploitation for Client Execution", "Execution", confidence_score=0.5),
    },
}

# ---------------------------------------------------------------------------
# Protocol → Technique modifiers
# ---------------------------------------------------------------------------
PROTOCOL_MODIFIERS: dict[str, MitreTechnique | None] = {
    "ICMP": MitreTechnique("T1095", "Non-Application Layer Protocol", "Command and Control", confidence_score=0.55),
    "UDP":  MitreTechnique("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", confidence_score=0.5),
    "TCP":  None,   # no additional technique
}

# ---------------------------------------------------------------------------
# Severity → confidence multiplier
# ---------------------------------------------------------------------------
SEVERITY_CONF_MULTIPLIER = {
    "Critical": 1.10,
    "High":     1.05,
    "Medium":   1.00,
    "Low":      0.90,
}

# ---------------------------------------------------------------------------
# Tactic → MITRE tactic chain order
# ---------------------------------------------------------------------------
TACTIC_CHAIN_ORDER: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


# ---------------------------------------------------------------------------
# Dynamic Mapping
# ---------------------------------------------------------------------------

def map_attack_dynamic(
    attack_type:      str,
    attack_signature: str = "",
    protocol:         str = "",
    severity:         str = "Medium",
    payload:          str = "",
) -> list[MitreTechnique]:
    """
    Dynamic technique selection. Returns list of MitreTechnique, each with
    a context-adjusted confidence_score.
    """
    base = list(ATTACK_TYPE_TO_MITRE.get(attack_type, DEFAULT_TECHNIQUE))

    # Clone so we don't mutate global state
    techniques = [
        MitreTechnique(
            t.technique_id, t.technique_name, t.tactic,
            t.sub_technique, t.confidence_score
        )
        for t in base
    ]

    # Severity multiplier
    sev_mult = SEVERITY_CONF_MULTIPLIER.get(severity, 1.0)
    for t in techniques:
        t.confidence_score = round(min(1.0, t.confidence_score * sev_mult), 3)

    # Signature overrides
    override = SIGNATURE_OVERRIDES.get(attack_signature)
    if override:
        boost = override["confidence_boost"]
        for t in techniques:
            t.confidence_score = round(min(1.0, max(0.0, t.confidence_score + boost)), 3)
        extra = override.get("extra_technique")
        if extra and not any(t.technique_id == extra.technique_id for t in techniques):
            techniques.append(MitreTechnique(
                extra.technique_id, extra.technique_name, extra.tactic,
                extra.sub_technique, round(min(1.0, extra.confidence_score * sev_mult), 3)
            ))

    # Protocol modifier
    proto_tech = PROTOCOL_MODIFIERS.get(protocol.upper())
    if proto_tech and not any(t.technique_id == proto_tech.technique_id for t in techniques):
        techniques.append(MitreTechnique(
            proto_tech.technique_id, proto_tech.technique_name, proto_tech.tactic,
            proto_tech.sub_technique, round(min(1.0, proto_tech.confidence_score * sev_mult), 3)
        ))

    # Sort by confidence descending
    techniques.sort(key=lambda t: t.confidence_score, reverse=True)
    return techniques


def map_attack_type(attack_type: str) -> list[MitreTechnique]:
    """Backward-compatible simple lookup (v1 signature)."""
    return map_attack_dynamic(attack_type)


def build_mitre_tactic_chain(techniques: list[MitreTechnique]) -> list[str]:
    """
    Build an ordered tactic flow from a list of techniques.
    Returns tactics in kill-chain order, deduplicated.
    """
    tactics_in_order: list[str] = []
    seen: set[str] = set()
    for tactic in TACTIC_CHAIN_ORDER:
        if any(t.tactic == tactic for t in techniques) and tactic not in seen:
            tactics_in_order.append(tactic)
            seen.add(tactic)
    # Append any tactics not in our order list
    for t in techniques:
        if t.tactic not in seen:
            tactics_in_order.append(t.tactic)
            seen.add(t.tactic)
    return tactics_in_order


def all_tactics_summary() -> dict[str, int]:
    counts: dict[str, int] = {}
    for techniques in ATTACK_TYPE_TO_MITRE.values():
        for t in techniques:
            counts[t.tactic] = counts.get(t.tactic, 0) + 1
    return counts


if __name__ == "__main__":
    print("=== Dynamic Mapping Tests ===\n")
    cases = [
        ("Ransomware",   "Known Pattern A", "TCP",  "Critical"),
        ("Phishing",     "Zero-Day",        "ICMP", "High"),
        ("SQL Injection","Known Pattern B", "UDP",  "Medium"),
        ("DDoS",         "Known Pattern C", "UDP",  "High"),
    ]
    for attack, sig, proto, sev in cases:
        techs = map_attack_dynamic(attack, sig, proto, sev)
        chain = build_mitre_tactic_chain(techs)
        print(f"{attack} | {sig} | {proto} | {sev}")
        for t in techs:
            print(f"  {t.technique_id:12s} {t.tactic:25s} conf={t.confidence_score}")
        print(f"  tactic_chain: {chain}\n")
