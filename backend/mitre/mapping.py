"""
MITRE ATT&CK Mapping Layer — Production v3
============================================
Designed for: Cyber Control Tower SOC Dashboard
Author note : Reviewed and redesigned against MITRE ATT&CK Enterprise v14.

v3 changes vs v2
-----------------
- Removed technically incorrect mappings (T1059.006 for SQLi, T1046 as primary
  for Intrusion, T1059.007 at 0.9 for XSS).
- Added role field (primary / secondary / optional) to MitreTechnique so the
  dashboard can render techniques at the right prominence.
- Confidence scores now represent mapping accuracy, NOT event severity.
  Severity is handled separately as a priority signal.
- Protocol modifiers are now attack-type-aware (no more "UDP → Exfiltration"
  for every UDP event regardless of context).
- Signature overrides now swap/add technique sets, not just boost confidence.
- Payload pattern matching drives sub-technique selection.
- Tactic chain validation flags out-of-order kill-chain progressions.
- Full backward compatibility: map_attack_type(attack_type) unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class MitreTechnique:
    """
    Represents a single MITRE ATT&CK technique or sub-technique.

    Fields
    ------
    technique_id     : Official ATT&CK ID (e.g. "T1566", "T1566.001")
    technique_name   : Official ATT&CK name
    tactic           : ATT&CK tactic (e.g. "Initial Access")
    sub_technique    : Sub-technique ID when applicable, else ""
    confidence_score : 0.0–1.0 — how certain we are this technique matches
                       the observed behavior.  Severity does NOT affect this.
    role             : "primary" | "secondary" | "optional"
                       primary   → almost always present for this attack type
                       secondary → present given typical attack patterns
                       optional  → possible but requires corroborating evidence
    reason           : Human-readable justification (used in SOC analyst UI)
    """
    technique_id:     str
    technique_name:   str
    tactic:           str
    sub_technique:    str   = ""
    confidence_score: float = 1.0
    role:             str   = "primary"      # primary | secondary | optional
    reason:           str   = ""


# ---------------------------------------------------------------------------
# Technique Catalog — Reviewed Against ATT&CK Enterprise v14
# ---------------------------------------------------------------------------
#
# Design rationale per attack type is documented inline.
# Each list is ordered: primary → secondary → optional.
#
# ---------------------------------------------------------------------------

ATTACK_TYPE_TO_MITRE: dict[str, list[MitreTechnique]] = {

    # ── RANSOMWARE ────────────────────────────────────────────────────────
    # Evidence chain: encrypt files → delete backups → stop recovery services
    # T1204 (User Execution) demoted to optional: it's a delivery mechanism,
    # not ransomware behavior.  We cannot assume delivery vector from
    # the ransomware event alone without a signature or payload confirming it.
    "Ransomware": [
        MitreTechnique(
            "T1486", "Data Encrypted for Impact", "Impact",
            confidence_score=0.95, role="primary",
            reason="Core ransomware behavior: files encrypted for extortion."
        ),
        MitreTechnique(
            "T1490", "Inhibit System Recovery", "Impact",
            confidence_score=0.88, role="secondary",
            reason="Ransomware families routinely delete VSS/shadow copies "
                   "and disable recovery tools before or after encryption."
        ),
        MitreTechnique(
            "T1489", "Service Stop", "Impact",
            confidence_score=0.75, role="secondary",
            reason="Ransomware stops backup agents, AV, and database services "
                   "to unlock files before encryption."
        ),
        MitreTechnique(
            "T1083", "File and Directory Discovery", "Discovery",
            confidence_score=0.70, role="secondary",
            reason="Ransomware must enumerate files/directories to target "
                   "before encryption begins."
        ),
        MitreTechnique(
            "T1204", "User Execution", "Execution",
            confidence_score=0.55, role="optional",
            reason="Common delivery mechanism (malicious attachment/link), "
                   "but not inferable from the ransomware event itself "
                   "without a dropper signature in the payload."
        ),
    ],

    # ── INTRUSION ─────────────────────────────────────────────────────────
    # "Intrusion" is a broad category.  Without signature/protocol context,
    # confidence must stay moderate.  T1046 (Network Service Discovery)
    # was incorrect as a primary — discovery follows access; it is not
    # evidence of the intrusion itself.
    "Intrusion": [
        MitreTechnique(
            "T1190", "Exploit Public-Facing Application", "Initial Access",
            confidence_score=0.72, role="primary",
            reason="Broad intrusion events most commonly map to exploitation "
                   "of internet-facing services.  Confidence is moderate "
                   "because 'Intrusion' alone does not confirm the vector."
        ),
        MitreTechnique(
            "T1078", "Valid Accounts", "Initial Access",
            confidence_score=0.60, role="secondary",
            reason="Credential-based intrusions are frequent; mapped as "
                   "secondary because a signature or auth-log correlation "
                   "is needed to confirm over exploitation."
        ),
        MitreTechnique(
            "T1133", "External Remote Services", "Initial Access",
            confidence_score=0.55, role="secondary",
            reason="VPN/RDP/Citrix abuse is a common intrusion vector, "
                   "especially when the protocol field confirms it."
        ),
        MitreTechnique(
            "T1046", "Network Service Discovery", "Discovery",
            confidence_score=0.45, role="optional",
            reason="Discovery activity may follow initial access, but cannot "
                   "be inferred from the intrusion event alone.  Map only "
                   "when post-access scanning is observed."
        ),
    ],

    # ── SQL INJECTION ─────────────────────────────────────────────────────
    # T1059.006 (Python) was incorrect — SQLi is a web exploit technique;
    # Python execution is unrelated.  Added T1005 (data theft) and
    # T1505.003 (web shell) as realistic post-SQLi outcomes.
    "SQL Injection": [
        MitreTechnique(
            "T1190", "Exploit Public-Facing Application", "Initial Access",
            confidence_score=0.95, role="primary",
            reason="SQL Injection is a textbook exploitation of a web "
                   "application exposed to the internet."
        ),
        MitreTechnique(
            "T1005", "Data from Local System", "Collection",
            confidence_score=0.65, role="secondary",
            reason="Data exfiltration is the primary motivation for SQLi; "
                   "attacker reads from the database (local to the server)."
        ),
        MitreTechnique(
            "T1505.003", "Web Shell", "Persistence",
            sub_technique="T1505.003",
            confidence_score=0.45, role="optional",
            reason="Blind/stacked SQLi can write a web shell via SELECT "
                   "INTO OUTFILE or xp_cmdshell. Map only when payload "
                   "contains shell-write indicators."
        ),
        MitreTechnique(
            "T1059.003", "Windows Command Shell", "Execution",
            sub_technique="T1059.003",
            confidence_score=0.35, role="optional",
            reason="xp_cmdshell enables OS command execution on MSSQL. "
                   "Confidence is low until payload confirms this path."
        ),
    ],

    # ── DDOS ─────────────────────────────────────────────────────────────
    # T1499 (Endpoint DoS) added conditionally; at the catalog level it is
    # optional because volumetric attacks target the network, not endpoints.
    # Sub-techniques added: T1498.001 (Direct Flood), T1498.002 (Reflection).
    "DDoS": [
        MitreTechnique(
            "T1498", "Network Denial of Service", "Impact",
            confidence_score=0.95, role="primary",
            reason="DDoS is the canonical Network DoS technique."
        ),
        MitreTechnique(
            "T1498.001", "Direct Network Flood", "Impact",
            sub_technique="T1498.001",
            confidence_score=0.75, role="secondary",
            reason="Volumetric floods (SYN, UDP, ICMP) are the most common "
                   "DDoS sub-type. Mapped as secondary pending protocol "
                   "confirmation."
        ),
        MitreTechnique(
            "T1498.002", "Reflection Amplification", "Impact",
            sub_technique="T1498.002",
            confidence_score=0.50, role="optional",
            reason="DNS/NTP/memcached amplification. Map when source IPs "
                   "are spoofed or the protocol is UDP with unusual "
                   "amplification factors."
        ),
        MitreTechnique(
            "T1499", "Endpoint Denial of Service", "Impact",
            confidence_score=0.45, role="optional",
            reason="Application-layer DoS (HTTP floods, SSL exhaustion). "
                   "Map when protocol is TCP/HTTP and the target is an "
                   "application endpoint, not a network device."
        ),
    ],

    # ── PHISHING ─────────────────────────────────────────────────────────
    # T1566 (parent) and T1566.001 (sub) were both listed at the same level,
    # which is structurally inconsistent.  Now: parent technique is the
    # fallback; sub-techniques are selected dynamically based on signature.
    # T1078 demoted to optional — it represents post-phishing credential use,
    # not the phishing event itself.
    "Phishing": [
        MitreTechnique(
            "T1566", "Phishing", "Initial Access",
            confidence_score=0.93, role="primary",
            reason="Phishing is the direct and certain mapping."
        ),
        MitreTechnique(
            "T1204.002", "Malicious File", "Execution",
            sub_technique="T1204.002",
            confidence_score=0.68, role="secondary",
            reason="The victim must open the attachment for the phishing "
                   "payload to execute — this is the expected execution "
                   "path for attachment-based phishing."
        ),
        MitreTechnique(
            "T1566.001", "Spearphishing Attachment", "Initial Access",
            sub_technique="T1566.001",
            confidence_score=0.60, role="secondary",
            reason="Most phishing uses attachments; mapped as secondary "
                   "pending signature confirmation of attachment vs. link."
        ),
        MitreTechnique(
            "T1566.002", "Spearphishing Link", "Initial Access",
            sub_technique="T1566.002",
            confidence_score=0.55, role="optional",
            reason="Link-based phishing is equally common; should be "
                   "selected when payload/signature indicates URL delivery."
        ),
        MitreTechnique(
            "T1078", "Valid Accounts", "Defense Evasion",
            confidence_score=0.35, role="optional",
            reason="Phishing aims to harvest credentials for later use. "
                   "Map only when post-phishing lateral movement or "
                   "auth events are correlated."
        ),
    ],

    # ── XSS ──────────────────────────────────────────────────────────────
    # T1059.007 at 0.9 was incorrect.  In ATT&CK, T1059.007 means the
    # adversary *runs* JavaScript as part of attack execution on a system
    # they control.  XSS *injects* JS into a victim's browser — the
    # detection event is the injection attempt.  The correct primary
    # technique for the web application perspective is T1190 (if the XSS
    # exploits the app) or T1189 (Drive-by, if the app serves XSS to users).
    # T1059.007 retained as optional (possible outcome, low confidence).
    "XSS": [
        MitreTechnique(
            "T1189", "Drive-by Compromise", "Initial Access",
            confidence_score=0.72, role="primary",
            reason="Stored XSS turns the web app into a watering hole; "
                   "visitors are compromised when they load the page. "
                   "This is the most impactful XSS scenario."
        ),
        MitreTechnique(
            "T1190", "Exploit Public-Facing Application", "Initial Access",
            confidence_score=0.68, role="secondary",
            reason="Reflected/DOM XSS exploits the application's failure "
                   "to sanitize input — maps to web app exploitation."
        ),
        MitreTechnique(
            "T1539", "Steal Web Session Cookie", "Credential Access",
            confidence_score=0.55, role="secondary",
            reason="Session cookie theft via document.cookie is a primary "
                   "XSS objective.  Confidence increases when payload "
                   "contains cookie-access patterns."
        ),
        MitreTechnique(
            "T1185", "Browser Session Hijacking", "Collection",
            confidence_score=0.40, role="optional",
            reason="Full session hijacking is possible via XSS but requires "
                   "a sophisticated payload. Map only when payload analysis "
                   "confirms session manipulation beyond cookie theft."
        ),
        MitreTechnique(
            "T1059.007", "JavaScript", "Execution",
            sub_technique="T1059.007",
            confidence_score=0.35, role="optional",
            reason="XSS results in JavaScript execution in the victim "
                   "browser, but this is a consequence, not the detection "
                   "event. Map as optional/low-confidence outcome."
        ),
    ],

    # ── MALWARE ──────────────────────────────────────────────────────────
    # T1059 (generic) demoted — specific sub-techniques should be preferred.
    # Added T1547 (persistence) and T1562 (impair defenses) as they are
    # near-universal in modern malware families.
    "Malware": [
        MitreTechnique(
            "T1204", "User Execution", "Execution",
            confidence_score=0.85, role="primary",
            reason="Most malware requires user action (double-click, "
                   "macro enable) for initial execution."
        ),
        MitreTechnique(
            "T1547", "Boot or Logon Autostart Execution", "Persistence",
            confidence_score=0.72, role="secondary",
            reason="Malware almost universally establishes persistence via "
                   "registry run keys, startup folders, or scheduled tasks."
        ),
        MitreTechnique(
            "T1562", "Impair Defenses", "Defense Evasion",
            confidence_score=0.65, role="secondary",
            reason="Modern malware disables AV/EDR/logging as an early "
                   "post-execution step."
        ),
        MitreTechnique(
            "T1071", "Application Layer Protocol", "Command and Control",
            confidence_score=0.60, role="secondary",
            reason="C2 communication over HTTP/S or DNS is standard "
                   "for modern malware implants."
        ),
        MitreTechnique(
            "T1059", "Command and Scripting Interpreter", "Execution",
            confidence_score=0.50, role="optional",
            reason="Script-based malware (PowerShell, VBScript) uses this "
                   "technique. Map when signature/payload confirms scripting."
        ),
        MitreTechnique(
            "T1055", "Process Injection", "Defense Evasion",
            confidence_score=0.45, role="optional",
            reason="Advanced malware uses process injection for stealth. "
                   "Map when EDR telemetry or signature indicates hollowing/"
                   "injection behavior."
        ),
    ],
}

DEFAULT_TECHNIQUE = [
    MitreTechnique(
        "T1583", "Acquire Infrastructure", "Resource Development",
        confidence_score=0.20, role="primary",
        reason="Fallback: attack type unrecognized. Minimal confidence."
    )
]


# ---------------------------------------------------------------------------
# Signature Overrides — Technique Substitution, Not Just Confidence Boost
# ---------------------------------------------------------------------------
#
# Design: each override contains:
#   confidence_delta   — additive delta applied to ALL existing techniques
#   add_techniques     — list of MitreTechnique to inject if not already present
#   suppress_roles     — role tags to suppress (e.g., remove optionals for
#                        well-understood signatures)
# ---------------------------------------------------------------------------

@dataclass
class SignatureOverride:
    confidence_delta:  float                = 0.0
    add_techniques:    list[MitreTechnique] = field(default_factory=list)
    suppress_roles:    list[str]            = field(default_factory=list)
    reason:            str                  = ""


SIGNATURE_OVERRIDES: dict[str, SignatureOverride] = {

    "Known Pattern A": SignatureOverride(
        confidence_delta=+0.05,
        add_techniques=[
            MitreTechnique(
                "T1027", "Obfuscated Files or Information", "Defense Evasion",
                confidence_score=0.60, role="secondary",
                reason="Known Pattern A is associated with obfuscation-heavy "
                       "loaders that encode payloads to evade signature detection."
            ),
        ],
        reason="Well-characterized signature; slight confidence boost + "
               "obfuscation technique added."
    ),

    "Known Pattern B": SignatureOverride(
        confidence_delta=+0.05,
        add_techniques=[
            MitreTechnique(
                "T1036", "Masquerading", "Defense Evasion",
                confidence_score=0.55, role="secondary",
                reason="Known Pattern B attackers rename tools to mimic "
                       "legitimate system binaries (e.g., svchost, lsass)."
            ),
        ],
        reason="Known masquerading variant; masquerade technique added."
    ),

    "Known Pattern C": SignatureOverride(
        confidence_delta=+0.03,
        add_techniques=[
            MitreTechnique(
                "T1071", "Application Layer Protocol", "Command and Control",
                confidence_score=0.60, role="secondary",
                reason="Known Pattern C tools use HTTP/S for C2 beaconing."
            ),
        ],
        reason="C2 beaconing pattern; application-layer C2 technique added."
    ),

    # Zero-Day: unknown behavior means we cannot be specific about techniques.
    # We lower confidence and add T1203 (Exploitation for Client Execution)
    # if the vector could be client-side, or keep T1190 (server-side).
    "Zero-Day": SignatureOverride(
        confidence_delta=-0.18,
        add_techniques=[
            MitreTechnique(
                "T1203", "Exploitation for Client Execution", "Execution",
                confidence_score=0.45, role="optional",
                reason="Zero-day exploits may target client applications "
                       "(browsers, Office). Added as possible execution "
                       "technique at low confidence."
            ),
        ],
        suppress_roles=["optional"],   # Remove low-confidence optionals —
                                       # they're noise when the sig is unknown
        reason="Unknown signature; confidence reduced across all techniques, "
               "optional techniques suppressed to reduce false precision."
    ),
}


# ---------------------------------------------------------------------------
# Protocol Modifiers — Context-Aware
# ---------------------------------------------------------------------------
#
# UDP does NOT imply exfiltration.  ICMP does NOT imply C2 unless the
# attack type is consistent with tunneling.
# Protocol modifiers now carry an attack_type_filter: the technique is only
# injected when the attack type matches the filter (empty list = always apply).
# ---------------------------------------------------------------------------

@dataclass
class ProtocolModifier:
    technique:          MitreTechnique
    attack_type_filter: list[str] = field(default_factory=list)  # empty = all
    reason:             str = ""


PROTOCOL_MODIFIERS: dict[str, list[ProtocolModifier]] = {

    "ICMP": [
        ProtocolModifier(
            technique=MitreTechnique(
                "T1095", "Non-Application Layer Protocol", "Command and Control",
                confidence_score=0.50, role="optional",
                reason="ICMP tunneling is a known C2 technique (e.g., Loki, "
                       "icmptunnel). Applicable when attack type suggests "
                       "C2 activity (Malware, Intrusion)."
            ),
            attack_type_filter=["Malware", "Intrusion"],
            reason="ICMP C2 only applies to malware/intrusion contexts, not DDoS."
        ),
        ProtocolModifier(
            technique=MitreTechnique(
                "T1498.001", "Direct Network Flood", "Impact",
                sub_technique="T1498.001",
                confidence_score=0.70, role="secondary",
                reason="ICMP flood is a classic direct network flood DDoS vector."
            ),
            attack_type_filter=["DDoS"],
            reason="ICMP floods are a volumetric DDoS vector."
        ),
    ],

    "UDP": [
        ProtocolModifier(
            technique=MitreTechnique(
                "T1498.001", "Direct Network Flood", "Impact",
                sub_technique="T1498.001",
                confidence_score=0.72, role="secondary",
                reason="UDP floods are a common volumetric DDoS vector."
            ),
            attack_type_filter=["DDoS"],
            reason="UDP flooding in DDoS context."
        ),
        ProtocolModifier(
            technique=MitreTechnique(
                "T1498.002", "Reflection Amplification", "Impact",
                sub_technique="T1498.002",
                confidence_score=0.60, role="optional",
                reason="DNS/NTP amplification attacks use UDP. Requires "
                       "traffic analysis to confirm spoofed sources."
            ),
            attack_type_filter=["DDoS"],
            reason="UDP amplification in DDoS context."
        ),
        # UDP alone (non-DDoS) does NOT imply exfiltration.
        # No generic UDP → exfiltration modifier.
    ],

    "TCP": [
        ProtocolModifier(
            technique=MitreTechnique(
                "T1499", "Endpoint Denial of Service", "Impact",
                confidence_score=0.55, role="optional",
                reason="TCP SYN floods and HTTP floods exhaust endpoint "
                       "resources. Only applies in DDoS context."
            ),
            attack_type_filter=["DDoS"],
            reason="TCP-based application-layer DoS."
        ),
        ProtocolModifier(
            technique=MitreTechnique(
                "T1071.001", "Web Protocols", "Command and Control",
                sub_technique="T1071.001",
                confidence_score=0.45, role="optional",
                reason="HTTP/S over TCP is the most common C2 channel. "
                       "Applied in malware/intrusion contexts."
            ),
            attack_type_filter=["Malware", "Intrusion"],
            reason="HTTP C2 in malware/intrusion context."
        ),
    ],

    "DNS": [
        ProtocolModifier(
            technique=MitreTechnique(
                "T1071.004", "DNS", "Command and Control",
                sub_technique="T1071.004",
                confidence_score=0.60, role="secondary",
                reason="DNS tunneling is used for both C2 and data "
                       "exfiltration. High value signal in malware context."
            ),
            attack_type_filter=["Malware", "Intrusion"],
            reason="DNS C2/exfiltration in malware/intrusion context."
        ),
    ],

    "HTTP": [
        ProtocolModifier(
            technique=MitreTechnique(
                "T1071.001", "Web Protocols", "Command and Control",
                sub_technique="T1071.001",
                confidence_score=0.55, role="optional",
                reason="Unencrypted HTTP C2 — less common but still observed."
            ),
            attack_type_filter=["Malware", "Intrusion"],
            reason="HTTP C2 in malware/intrusion context."
        ),
    ],

    "HTTPS": [
        ProtocolModifier(
            technique=MitreTechnique(
                "T1071.001", "Web Protocols", "Command and Control",
                sub_technique="T1071.001",
                confidence_score=0.62, role="secondary",
                reason="HTTPS C2 is the dominant channel for modern implants."
            ),
            attack_type_filter=["Malware", "Intrusion"],
            reason="HTTPS C2 in malware/intrusion context."
        ),
    ],
}


# ---------------------------------------------------------------------------
# Severity — Priority Signal Only (NOT confidence multiplier)
# ---------------------------------------------------------------------------
#
# Severity is an analyst-facing priority rating, not a measure of how
# accurately we've identified a MITRE technique.  It is returned as a
# separate field and used for incident prioritization, NOT confidence scoring.
# ---------------------------------------------------------------------------

SEVERITY_PRIORITY: dict[str, int] = {
    "Critical": 4,
    "High":     3,
    "Medium":   2,
    "Low":      1,
    "Info":     0,
}


# ---------------------------------------------------------------------------
# Payload Pattern → Sub-Technique Injectors
# ---------------------------------------------------------------------------
#
# Lightweight regex patterns on the payload field to promote optional
# techniques to secondary and add specific sub-techniques.
# Patterns are intentionally conservative to avoid false positives.
# ---------------------------------------------------------------------------

@dataclass
class PayloadPattern:
    pattern:    str          # regex applied to payload (case-insensitive)
    technique:  MitreTechnique
    reason:     str


PAYLOAD_PATTERNS: list[PayloadPattern] = [
    PayloadPattern(
        pattern=r"document\.cookie|\.cookie\s*=",
        technique=MitreTechnique(
            "T1539", "Steal Web Session Cookie", "Credential Access",
            confidence_score=0.78, role="secondary",
            reason="Payload contains document.cookie access — high confidence "
                   "of session cookie theft attempt."
        ),
        reason="Cookie theft pattern in XSS payload."
    ),
    PayloadPattern(
        pattern=r"xp_cmdshell|exec\s*\(|sp_executesql",
        technique=MitreTechnique(
            "T1059.003", "Windows Command Shell", "Execution",
            sub_technique="T1059.003",
            confidence_score=0.75, role="secondary",
            reason="Payload contains MSSQL command execution directives — "
                   "OS command execution via xp_cmdshell confirmed."
        ),
        reason="OS command via SQL detected in payload."
    ),
    PayloadPattern(
        pattern=r"select.+into\s+outfile|load_file\(",
        technique=MitreTechnique(
            "T1505.003", "Web Shell", "Persistence",
            sub_technique="T1505.003",
            confidence_score=0.70, role="secondary",
            reason="SELECT INTO OUTFILE pattern suggests file write attempt — "
                   "potential web shell drop."
        ),
        reason="File write via SQL detected — possible web shell."
    ),
    PayloadPattern(
        pattern=r"powershell|pwsh|invoke-expression|iex\(",
        technique=MitreTechnique(
            "T1059.001", "PowerShell", "Execution",
            sub_technique="T1059.001",
            confidence_score=0.80, role="secondary",
            reason="Payload or signature references PowerShell execution."
        ),
        reason="PowerShell execution pattern detected."
    ),
    PayloadPattern(
        pattern=r"cmd\.exe|/bin/sh|/bin/bash|shell\.exec",
        technique=MitreTechnique(
            "T1059.003", "Windows Command Shell", "Execution",
            sub_technique="T1059.003",
            confidence_score=0.72, role="secondary",
            reason="Command shell invocation detected in payload."
        ),
        reason="Shell command pattern detected."
    ),
    PayloadPattern(
        pattern=r"base64_decode|fromcharcode|\\x[0-9a-f]{2}|eval\(",
        technique=MitreTechnique(
            "T1027", "Obfuscated Files or Information", "Defense Evasion",
            confidence_score=0.65, role="secondary",
            reason="Payload contains encoding/obfuscation patterns "
                   "(base64, char codes, eval)."
        ),
        reason="Obfuscation pattern detected in payload."
    ),
    PayloadPattern(
        pattern=r"vssadmin|wmic shadowcopy|bcdedit|wbadmin",
        technique=MitreTechnique(
            "T1490", "Inhibit System Recovery", "Impact",
            confidence_score=0.88, role="primary",
            reason="Payload references shadow copy deletion or boot config "
                   "modification — recovery inhibition confirmed."
        ),
        reason="Recovery inhibition commands detected in payload."
    ),
]


# ---------------------------------------------------------------------------
# Kill-Chain Tactic Order
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

# Tactics that should not appear as the FIRST step in a chain
# (they imply prior access). Used for anomaly flagging.
_POST_ACCESS_TACTICS: set[str] = {
    "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
}


# ---------------------------------------------------------------------------
# Dynamic Mapping Engine
# ---------------------------------------------------------------------------

def map_attack_dynamic(
    attack_type:      str,
    attack_signature: str = "",
    protocol:         str = "",
    severity:         str = "Medium",
    payload:          str = "",
    action_taken:     str = "",    # future use: "blocked" reduces confidence slightly
) -> list[MitreTechnique]:
    """
    Context-aware MITRE ATT&CK technique mapping.

    Parameters
    ----------
    attack_type      : Category of attack (e.g. "Ransomware", "DDoS")
    attack_signature : Signature name from IDS/IPS (e.g. "Known Pattern A")
    protocol         : Network protocol (e.g. "TCP", "UDP", "ICMP")
    severity         : Event severity — used for priority, NOT confidence
    payload          : Raw or decoded payload string for pattern matching
    action_taken     : What the security control did (e.g. "blocked", "allowed")

    Returns
    -------
    List of MitreTechnique sorted by confidence (highest first).
    Severity does NOT affect confidence scores — it is a separate signal.
    """

    # 1. Base techniques from catalog
    base = ATTACK_TYPE_TO_MITRE.get(attack_type, DEFAULT_TECHNIQUE)
    techniques: list[MitreTechnique] = [
        MitreTechnique(
            t.technique_id, t.technique_name, t.tactic,
            t.sub_technique, t.confidence_score,
            t.role, t.reason
        )
        for t in base
    ]

    # 2. Apply signature override
    override = SIGNATURE_OVERRIDES.get(attack_signature)
    if override:
        # Suppress specified roles first (e.g., remove optionals for Zero-Day)
        if override.suppress_roles:
            techniques = [
                t for t in techniques if t.role not in override.suppress_roles
            ]

        # Apply confidence delta
        if override.confidence_delta != 0.0:
            for t in techniques:
                t.confidence_score = round(
                    min(1.0, max(0.05, t.confidence_score + override.confidence_delta)),
                    3
                )

        # Inject additional techniques from override
        existing_ids = {t.technique_id for t in techniques}
        for extra in override.add_techniques:
            if extra.technique_id not in existing_ids:
                # Apply the same delta to injected techniques
                adjusted_conf = round(
                    min(1.0, max(0.05, extra.confidence_score + override.confidence_delta)),
                    3
                )
                techniques.append(MitreTechnique(
                    extra.technique_id, extra.technique_name, extra.tactic,
                    extra.sub_technique, adjusted_conf, extra.role, extra.reason
                ))
                existing_ids.add(extra.technique_id)

    # 3. Apply protocol modifiers (context-aware)
    proto_upper = protocol.upper().strip()
    modifiers = PROTOCOL_MODIFIERS.get(proto_upper, [])
    existing_ids = {t.technique_id for t in techniques}
    for mod in modifiers:
        # Only inject if attack_type matches the filter (or filter is empty)
        if mod.attack_type_filter and attack_type not in mod.attack_type_filter:
            continue
        if mod.technique.technique_id not in existing_ids:
            techniques.append(MitreTechnique(
                mod.technique.technique_id, mod.technique.technique_name,
                mod.technique.tactic, mod.technique.sub_technique,
                mod.technique.confidence_score, mod.technique.role,
                mod.technique.reason
            ))
            existing_ids.add(mod.technique.technique_id)

    # 4. Apply payload pattern matching
    if payload:
        existing_ids = {t.technique_id for t in techniques}
        for pp in PAYLOAD_PATTERNS:
            if re.search(pp.pattern, payload, re.IGNORECASE):
                if pp.technique.technique_id not in existing_ids:
                    techniques.append(MitreTechnique(
                        pp.technique.technique_id, pp.technique.technique_name,
                        pp.technique.tactic, pp.technique.sub_technique,
                        pp.technique.confidence_score, pp.technique.role,
                        pp.technique.reason
                    ))
                    existing_ids.add(pp.technique.technique_id)
                else:
                    # Promote existing technique's confidence when payload confirms it
                    for t in techniques:
                        if t.technique_id == pp.technique.technique_id:
                            t.confidence_score = round(
                                min(1.0, max(t.confidence_score, pp.technique.confidence_score)),
                                3
                            )
                            t.reason += f" [Payload confirmed: {pp.reason}]"
                            break

    # 5. Sort: primary roles first, then by confidence descending
    role_order = {"primary": 0, "secondary": 1, "optional": 2}
    techniques.sort(
        key=lambda t: (role_order.get(t.role, 3), -t.confidence_score)
    )

    return techniques


def map_attack_type(attack_type: str) -> list[MitreTechnique]:
    """
    Backward-compatible simple lookup (v1/v2 API signature preserved).
    Maps attack_type only, with default context values.
    """
    return map_attack_dynamic(attack_type)


# ---------------------------------------------------------------------------
# Tactic Chain Builder + Anomaly Validator
# ---------------------------------------------------------------------------

def build_mitre_tactic_chain(
    techniques: list[MitreTechnique],
    validate: bool = True,
) -> dict:
    """
    Build an ordered tactic flow from a list of techniques.

    Returns
    -------
    dict with:
        chain          : list[str] — tactics in kill-chain order
        anomalies      : list[str] — potential out-of-order or suspicious flags
        tactic_counts  : dict[str, int] — how many techniques per tactic
    """
    tactics_in_order: list[str] = []
    seen: set[str] = set()
    tactic_counts: dict[str, int] = {}

    # Count techniques per tactic
    for t in techniques:
        tactic_counts[t.tactic] = tactic_counts.get(t.tactic, 0) + 1

    # Build ordered chain
    for tactic in TACTIC_CHAIN_ORDER:
        if tactic in tactic_counts and tactic not in seen:
            tactics_in_order.append(tactic)
            seen.add(tactic)

    # Append any non-standard tactics not in the order list
    for t in techniques:
        if t.tactic not in seen:
            tactics_in_order.append(t.tactic)
            seen.add(t.tactic)

    anomalies: list[str] = []
    if validate and tactics_in_order:
        first_tactic = tactics_in_order[0]
        # Flag if the first observed tactic implies prior access
        if first_tactic in _POST_ACCESS_TACTICS:
            anomalies.append(
                f"Tactic chain starts at '{first_tactic}' — this implies "
                f"prior Initial Access that was not detected or logged. "
                f"Consider reviewing for missed early-stage activity."
            )
        # Flag Impact-only chains (no prior access)
        if tactics_in_order == ["Impact"]:
            anomalies.append(
                "Only 'Impact' tactic detected — initial access and execution "
                "phases may have been missed or blocked upstream."
            )

    return {
        "chain":         tactics_in_order,
        "anomalies":     anomalies,
        "tactic_counts": tactic_counts,
    }


def all_tactics_summary() -> dict[str, int]:
    """Count of techniques per tactic across the full catalog (v1/v2 compat)."""
    counts: dict[str, int] = {}
    for techniques in ATTACK_TYPE_TO_MITRE.values():
        for t in techniques:
            counts[t.tactic] = counts.get(t.tactic, 0) + 1
    return counts


def get_priority(severity: str) -> int:
    """
    Return a numeric priority for an event.
    Separate from confidence — severity drives alerting, not technique accuracy.
    """
    return SEVERITY_PRIORITY.get(severity, 2)


# ---------------------------------------------------------------------------
# CLI Test Harness
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 72)
    print("MITRE ATT&CK Mapping Layer v3 — Cyber Control Tower")
    print("=" * 72)

    test_cases = [
        # (attack_type, signature,       protocol, severity,   payload)
        ("Ransomware",    "Known Pattern A", "TCP",   "Critical", "vssadmin delete shadows /all"),
        ("Phishing",      "Zero-Day",        "ICMP",  "High",     ""),
        ("SQL Injection",  "Known Pattern B", "TCP",   "Medium",   "'; exec xp_cmdshell('whoami')--"),
        ("DDoS",           "Known Pattern C", "UDP",   "High",     ""),
        ("XSS",            "",                "HTTP",  "Medium",   "<script>document.cookie='stolen='+document.cookie</script>"),
        ("Malware",        "Known Pattern A", "DNS",   "Critical", "powershell -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuA"),
        ("Intrusion",      "Zero-Day",        "TCP",   "High",     ""),
    ]

    for attack, sig, proto, sev, payload in test_cases:
        print(f"\n{'─' * 72}")
        print(f"  Attack Type : {attack}")
        print(f"  Signature   : {sig or '(none)'}")
        print(f"  Protocol    : {proto}")
        print(f"  Severity    : {sev}  (priority={get_priority(sev)})")
        print(f"  Payload     : {payload[:60] + '...' if len(payload) > 60 else payload or '(none)'}")
        print()

        techs = map_attack_dynamic(attack, sig, proto, sev, payload)
        chain_result = build_mitre_tactic_chain(techs)

        print(f"  {'ROLE':<10} {'ID':<14} {'CONFIDENCE':>10}  {'TACTIC':<28}  TECHNIQUE")
        print(f"  {'─' * 10} {'─' * 14} {'─' * 10}  {'─' * 28}  {'─' * 30}")
        for t in techs:
            flag = "  ★" if t.role == "primary" else ("  ·" if t.role == "secondary" else "   ")
            print(f"  {t.role:<10} {t.technique_id:<14} {t.confidence_score:>10.3f}  "
                  f"{t.tactic:<28}  {t.technique_name}{flag}")

        print(f"\n  Tactic Chain : {' → '.join(chain_result['chain'])}")
        for anomaly in chain_result["anomalies"]:
            print(f"  ⚠ Anomaly   : {anomaly}")

    print(f"\n{'=' * 72}")
    print("Backward-compat check: map_attack_type('Ransomware')")
    simple = map_attack_type("Ransomware")
    for t in simple:
        print(f"  {t.technique_id}  {t.technique_name}  conf={t.confidence_score}")

    print(f"\nTactics summary: {all_tactics_summary()}")