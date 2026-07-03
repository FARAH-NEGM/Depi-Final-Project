"""
Correlation Engine  — Real Event Grouping + Attack Chain Detection  v2
=======================================================================
Grouping Strategy (adapted to actual dataset characteristics):
---------------------------------------------------------------
The dataset spans 3 years with no temporal clustering on IPs (every IP
is unique) — this mirrors real-world threat-actor data where attackers
rotate infrastructure. Two complementary strategies are therefore used:

  Strategy A — User Behavioral Thread Grouping
    All events attributed to the same user are grouped into ONE incident
    regardless of time gap, because the *user account* is the persistent
    correlating artifact in behavioral analytics. This models how a real
    SOC correlates "everything this account did" into a case.
    Users with only 1 event get a single-event incident.

  Strategy B — Campaign Grouping (same attack_type within same network_segment)
    Events of the same attack_type hitting the same network_segment within
    a 72-hour campaign window are grouped (models a scanning/phishing
    campaign). This fires for attack-type clusters even across different
    user accounts.

Both strategies can fire on the same event (user wins if it already placed
the event; otherwise campaign grouping gets it).

Result: realistic incident reduction with genuine multi-event incidents,
attack chains, and a meaningful risk score distribution.
"""

from __future__ import annotations

import hashlib
import random
from collections import Counter
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from typing import Optional

from ingestion.loader import Event, get_events

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CAMPAIGN_WINDOW_HOURS = 72      # same attack_type + same segment within this window

DETECTION_DELAY_MINUTES = {
    "Critical": (1, 5),
    "High":     (3, 15),
    "Medium":   (10, 45),
    "Low":      (30, 120),
}

RESPONSE_DELAY_MINUTES = {
    "Blocked":     (2, 10),
    "Quarantined": (5, 20),
    "Logged":      (20, 90),
    "Ignored":     (60, 240),
}

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
SEVERITY_RISK  = {"Low": 15, "Medium": 40, "High": 70, "Critical": 100}

# Workflow states an incident can be moved through from the dashboard.
# Order matters for the frontend's status dropdown.
VALID_STATUSES: list[str] = ["Open", "Investigating", "Contained", "Resolved"]

# ---------------------------------------------------------------------------
# SLA targets (minutes) — standard SOC KPI targets, scaled by severity.
# An incident "breaches" a stage's SLA if the actual elapsed time for that
# stage exceeds the target.
# ---------------------------------------------------------------------------
DETECTION_SLA_MINUTES: dict[str, float] = {
    "Critical": 15, "High": 30, "Medium": 60, "Low": 120,
}
RESPONSE_SLA_MINUTES: dict[str, float] = {
    "Critical": 30, "High": 60, "Medium": 120, "Low": 240,
}
CONTAINMENT_SLA_MINUTES: dict[str, float] = {
    "Critical": 60, "High": 120, "Medium": 240, "Low": 480,
}

# Small fixed analyst roster the assignment draws from — stands in for a
# real ticketing/identity system in this demo.
ANALYST_ROSTER: list[str] = [
    "A. Chen", "R. Iyer", "M. Alvarez", "S. Okafor", "P. Novak",
]

# ---------------------------------------------------------------------------
# Multi-Stage Attack Chain Definitions
# ---------------------------------------------------------------------------
ATTACK_TYPE_TO_STAGE: dict[str, str] = {
    "Intrusion":     "Reconnaissance",
    "SQL Injection": "Exploit",
    "XSS":           "Exploit",
    "Phishing":      "Initial Access",
    "Malware":       "Execution",
    "Ransomware":    "Impact",
    "DDoS":          "Impact",
}

KILL_CHAIN: list[str] = [
    "Reconnaissance",
    "Initial Access",
    "Exploit",
    "Execution",
    "Privilege Escalation",
    "Lateral Movement",
    "Collection",
    "Data Exfiltration",
    "Impact",
]

KNOWN_CHAINS: list[list[str]] = [
    ["Reconnaissance", "Exploit", "Privilege Escalation", "Lateral Movement", "Data Exfiltration"],
    ["Initial Access", "Execution", "Lateral Movement", "Impact"],
    ["Reconnaissance", "Initial Access", "Exploit", "Execution"],
    ["Initial Access", "Exploit", "Impact"],
    ["Reconnaissance", "Initial Access", "Execution"],
    ["Exploit", "Execution", "Impact"],
]

TACTIC_CRITICALITY: dict[str, float] = {
    "Initial Access":       0.7,
    "Execution":            0.6,
    "Persistence":          0.65,
    "Privilege Escalation": 0.8,
    "Defense Evasion":      0.75,
    "Credential Access":    0.85,
    "Discovery":            0.5,
    "Lateral Movement":     0.9,
    "Collection":           0.8,
    "Exfiltration":         0.95,
    "Impact":               1.0,
    "Reconnaissance":       0.55,
    "Resource Development": 0.45,
}

STAGE_TO_TACTIC: dict[str, str] = {
    "Reconnaissance":    "Reconnaissance",
    "Initial Access":    "Initial Access",
    "Exploit":           "Initial Access",
    "Execution":         "Execution",
    "Privilege Escalation": "Privilege Escalation",
    "Lateral Movement":  "Lateral Movement",
    "Collection":        "Collection",
    "Data Exfiltration": "Exfiltration",
    "Impact":            "Impact",
}

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    # --- original fields (backward-compatible) ---
    incident_id:       str
    thread_id:         str
    event_id:          str
    source_ip:         str
    dst_ip:            str
    attack_type:       str
    severity:          str
    network_segment:   str
    user:              str
    occurred_at:       str
    detected_at:       str
    resolved_at:       str
    action_taken:      str
    mttd_minutes:      float
    mttr_minutes:      float

    # --- new fields (v2) ---
    related_events:    list[str]  = field(default_factory=list)
    event_count:       int        = 1
    start_time:        str        = ""
    end_time:          str        = ""
    affected_users:    list[str]  = field(default_factory=list)
    affected_ips:      list[str]  = field(default_factory=list)
    correlation_reason: str       = ""
    attack_chain:      list[str]  = field(default_factory=list)
    attack_stage:      str        = ""
    chain_confidence:  float      = 0.0
    mitre_chain:       list[str]  = field(default_factory=list)
    risk_score:        float      = 0.0
    risk_level:        str        = ""

    # --- workflow state (v3) ---
    # Mutated in-place by api/incident_actions.py when an analyst/manager
    # changes status through POST /api/incidents/<id>/status. Defaults to
    # a sensible starting point derived from how the event was originally
    # handled, so the incident queue isn't full of "Open" on first load.
    status:            str        = "Open"

    # --- endpoint / asset context (v4) ---
    # SOC analysts investigate endpoints, not just user accounts. Hostname,
    # asset ID, and OS are derived deterministically from the underlying
    # event's user + device fingerprint (the dataset has no native asset
    # inventory), so the same "asset" always resolves to the same identity
    # across incidents.
    hostname:          str        = ""
    device_name:       str        = ""
    asset_id:          str        = ""
    business_unit:     str        = ""
    os_name:           str        = ""

    # --- SLA (v4) ---
    detection_sla_minutes:   float = 0.0
    response_sla_minutes:    float = 0.0
    containment_sla_minutes: float = 0.0
    detection_sla_breached:  bool  = False
    response_sla_breached:   bool  = False
    containment_sla_breached: bool = False

    # --- ownership (v4) ---
    assigned_analyst: str        = "Unassigned"

    # --- correlation confidence (v4) ---
    # How confident the correlation engine is that the related_events all
    # belong to the same incident (distinct from chain_confidence, which is
    # about attack-chain/kill-chain pattern matching).
    correlation_confidence: float = 0.0

    # --- last seen (v4) ---
    # Alias of end_time exposed under a clearer name for the UI — whether
    # the underlying activity is still recent.
    last_seen:         str        = ""

    # --- escalation (v5) ---
    # A handoff, not a status. An incident can be escalated while still
    # "Open" or "Investigating" — escalated is orthogonal to `status`,
    # not a replacement value for it. Set by escalate_incident() below via
    # POST /api/incidents/<id>/escalate, analyst-only (see
    # auth/permissions.py — escalate_incident capability).
    escalated:         bool       = False
    escalated_to:      str        = ""
    escalated_by:      str        = ""
    escalation_reason: str        = ""
    escalated_at:      str        = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seeded_rng(seed_key: str) -> random.Random:
    return random.Random(seed_key)


def _dominant(items: list[str], rank_map: dict[str, int] | None = None) -> str:
    if rank_map:
        return max(set(items), key=lambda x: rank_map.get(x, 0))
    return Counter(items).most_common(1)[0][0]


def _make_incident_id(events: list[Event]) -> str:
    raw = "-".join(sorted(e.event_id for e in events))
    return "INC-" + hashlib.sha1(raw.encode()).hexdigest()[:10]


def _dominant_severity(events: list[Event]) -> str:
    return _dominant([e.severity for e in events], SEVERITY_ORDER)


def _dominant_action(events: list[Event]) -> str:
    rank = {"Blocked": 3, "Quarantined": 2, "Logged": 1, "Ignored": 0}
    return _dominant([e.action_taken for e in events], rank)


# ---------------------------------------------------------------------------
# Attack Chain
# ---------------------------------------------------------------------------

def _extract_stages(events: list[Event]) -> list[str]:
    seen: list[str] = []
    seen_set: set[str] = set()
    for e in sorted(events, key=lambda ev: ev.timestamp):
        stage = ATTACK_TYPE_TO_STAGE.get(e.attack_type)
        if stage and stage not in seen_set:
            seen.append(stage)
            seen_set.add(stage)
    return seen


def _detect_chain(stages: list[str]) -> tuple[list[str], float]:
    if not stages:
        return [], 0.0
    if len(stages) < 2:
        return stages, 0.0

    stages_set  = set(stages)
    best_chain  = stages
    best_conf   = 0.0

    for known in KNOWN_CHAINS:
        hits = sum(1 for s in known if s in stages_set)
        conf = hits / len(known)
        if conf > best_conf:
            best_conf  = round(conf, 2)
            best_chain = known

    if best_conf < 0.3:
        best_chain = stages
        best_conf  = round(len(stages) / max(len(KILL_CHAIN), 1), 2)

    return best_chain, best_conf


def _build_mitre_chain(stages: list[str]) -> list[str]:
    seen: list[str] = []
    seen_set: set[str] = set()
    for s in stages:
        tactic = STAGE_TO_TACTIC.get(s, s)
        if tactic not in seen_set:
            seen.append(tactic)
            seen_set.add(tactic)
    return seen


def _parse_os(device_info: str) -> str:
    """Best-effort OS family extraction from the raw user-agent string."""
    s = (device_info or "").lower()
    if "windows" in s:
        return "Windows"
    if "iphone" in s or "ipad" in s:
        return "iOS"
    if "macintosh" in s or "mac os x" in s:
        return "macOS"
    if "android" in s:
        return "Android"
    if "linux" in s:
        return "Linux"
    return "Unknown"


def _asset_identity(user: str, device_info: str) -> tuple[str, str, str, str, str]:
    """
    Deterministically derive endpoint context (hostname, device name, asset
    ID, business unit) from the user + device fingerprint, since the
    dataset has no native asset-inventory table. Deterministic per user, so
    the same "asset" resolves consistently across every incident it
    appears in.
    """
    seed = hashlib.sha1(user.encode()).hexdigest()
    business_units = ["Finance", "Engineering", "Sales", "HR", "Operations", "IT", "Legal", "Marketing"]
    device_kinds   = ["LAP", "WKS", "SRV"]

    bu       = business_units[int(seed[0:2], 16) % len(business_units)]
    kind     = device_kinds[int(seed[2:3], 16) % len(device_kinds)]
    num      = int(seed[3:6], 16) % 999
    device_name = f"{bu[:3].upper()}-{kind}-{num:03d}"
    hostname    = f"{device_name.lower()}.corp.local"
    asset_id    = f"AST-{seed[:6].upper()}"
    os_name     = _parse_os(device_info)

    return hostname, device_name, asset_id, bu, os_name


def _assign_analyst(incident_id: str, status: str) -> str:
    """
    Deterministic round-robin assignment: incidents still Open have no
    owner yet (mirrors a real triage queue); everything moved past Open
    has been picked up by an analyst.
    """
    if status == "Open":
        return "Unassigned"
    idx = int(hashlib.sha1(incident_id.encode()).hexdigest(), 16) % len(ANALYST_ROSTER)
    return ANALYST_ROSTER[idx]


def _correlation_confidence(group: list) -> float:
    """
    How confident the correlation engine is that every event in this group
    genuinely belongs to one incident — distinct from chain_confidence
    (which measures kill-chain pattern match). Blends attack-type and
    network-segment consistency across the group; a single-event incident
    is trivially 100% confident it is itself.
    """
    if len(group) <= 1:
        return 1.0
    dominant_type    = _dominant([e.attack_type for e in group])
    dominant_segment = _dominant([e.network_segment for e in group])
    type_consistency    = sum(1 for e in group if e.attack_type == dominant_type) / len(group)
    segment_consistency = sum(1 for e in group if e.network_segment == dominant_segment) / len(group)
    conf = 0.2 + 0.5 * type_consistency + 0.3 * segment_consistency
    return round(min(1.0, conf), 2)


def _compute_sla(
    severity: str,
    mttd_minutes: float,
    mttr_minutes: float,
    status: str,
) -> dict:
    det_target  = DETECTION_SLA_MINUTES.get(severity, 60)
    resp_target = RESPONSE_SLA_MINUTES.get(severity, 120)
    cont_target = CONTAINMENT_SLA_MINUTES.get(severity, 240)

    detection_breached = mttd_minutes > det_target
    response_breached  = mttr_minutes > resp_target
    # Containment SLA only meaningfully evaluated once an incident has
    # actually reached Contained/Resolved — total handling time vs target.
    total_handling = mttd_minutes + mttr_minutes
    containment_breached = (
        status in ("Contained", "Resolved") and total_handling > cont_target
    )

    return {
        "detection_sla_minutes":    det_target,
        "response_sla_minutes":     resp_target,
        "containment_sla_minutes":  cont_target,
        "detection_sla_breached":   detection_breached,
        "response_sla_breached":    response_breached,
        "containment_sla_breached": containment_breached,
    }


def _initial_status(action_taken: str) -> str:
    """
    Derive a sensible starting workflow status from how the underlying
    event(s) were originally handled, so the incident queue reflects real
    signal on first load instead of showing everything as "Open".
    Analysts/managers can still move incidents through the workflow via
    POST /api/incidents/<id>/status.
    """
    return {
        "Blocked":     "Contained",
        "Quarantined": "Investigating",
        "Logged":      "Open",
        "Ignored":     "Open",
    }.get(action_taken, "Open")


# ---------------------------------------------------------------------------
# Risk Score
# ---------------------------------------------------------------------------

def _compute_risk_score(
    severity:    str,
    event_count: int,
    chain:       list[str],
    mitre_chain: list[str],
    chain_conf:  float,
) -> tuple[float, str]:
    """
    Deterministic, server-side, and documented so the UI can show exactly
    how the number was derived (see tooltip in the frontend):

        Risk Score = 40% Severity
                    + 20% Event Count
                    + 20% Attack Chain Confidence
                    + 20% MITRE Criticality

    Each component is normalised to 0-100 before weighting; the final
    value is clamped to 0-100.
    """
    import math

    sev_score   = SEVERITY_RISK.get(severity, 40)
    count_score = min(100.0, 100 * math.log1p(event_count) / math.log1p(20))
    chain_score = min(100.0, (chain_conf or 0.0) * 100)
    tactic_avg  = (
        sum(TACTIC_CRITICALITY.get(t, 0.5) for t in mitre_chain) / len(mitre_chain) * 100
        if mitre_chain else 40.0
    )

    raw = (
        0.40 * sev_score +
        0.20 * count_score +
        0.20 * chain_score +
        0.20 * tactic_avg
    )
    score = round(min(100.0, max(0.0, raw)), 2)

    if   score >= 80: level = "Critical"
    elif score >= 60: level = "High"
    elif score >= 30: level = "Medium"
    else:             level = "Low"

    return score, level


# ---------------------------------------------------------------------------
# Incident Builder
# ---------------------------------------------------------------------------

def _build_incident(
    group:           list[Event],
    thread_id:       str,
    correlation_reason: str,
) -> Incident:
    group_sorted = sorted(group, key=lambda e: e.timestamp)
    primary      = group_sorted[0]

    severity = _dominant_severity(group)
    action   = _dominant_action(group)
    rng      = _seeded_rng(primary.event_id)

    det_lo, det_hi = DETECTION_DELAY_MINUTES.get(severity, (10, 60))
    mttd           = rng.uniform(det_lo, det_hi)
    detected_at    = primary.timestamp + timedelta(minutes=mttd)

    res_lo, res_hi = RESPONSE_DELAY_MINUTES.get(action, (30, 120))
    mttr           = rng.uniform(res_lo, res_hi)
    resolved_at    = detected_at + timedelta(minutes=mttr)

    stages          = _extract_stages(group)
    attack_chain, chain_conf = _detect_chain(stages)
    mitre_chain     = _build_mitre_chain(attack_chain if attack_chain else stages)
    attack_stage    = stages[0] if stages else ATTACK_TYPE_TO_STAGE.get(primary.attack_type, "Unknown")
    dominant_user   = _dominant([e.user for e in group])
    dominant_type   = _dominant([e.attack_type for e in group])

    risk_score, risk_level = _compute_risk_score(
        severity, len(group), attack_chain or stages, mitre_chain, chain_conf
    )

    status       = _initial_status(action)
    incident_id  = _make_incident_id(group)
    end_time_iso = group_sorted[-1].timestamp.isoformat()
    hostname, device_name, asset_id, business_unit, os_name = _asset_identity(
        dominant_user, primary.device_info
    )
    sla = _compute_sla(severity, mttd, mttr, status)

    return Incident(
        incident_id        = incident_id,
        thread_id          = thread_id,
        event_id           = primary.event_id,
        source_ip          = primary.src_ip,
        dst_ip             = primary.dst_ip,
        attack_type        = dominant_type,
        severity           = severity,
        network_segment    = primary.network_segment,
        user               = dominant_user,
        occurred_at        = primary.timestamp.isoformat(),
        detected_at        = detected_at.isoformat(),
        resolved_at        = resolved_at.isoformat(),
        action_taken       = action,
        mttd_minutes       = round(mttd, 2),
        mttr_minutes       = round(mttr, 2),
        related_events     = [e.event_id for e in group_sorted],
        event_count        = len(group),
        start_time         = group_sorted[0].timestamp.isoformat(),
        end_time           = end_time_iso,
        affected_users     = sorted(set(e.user   for e in group)),
        affected_ips       = sorted(set(e.src_ip for e in group) | set(e.dst_ip for e in group)),
        correlation_reason = correlation_reason,
        attack_chain       = attack_chain if attack_chain else stages,
        attack_stage       = attack_stage,
        chain_confidence   = chain_conf,
        mitre_chain        = mitre_chain,
        risk_score         = risk_score,
        risk_level         = risk_level,
        status             = status,
        hostname           = hostname,
        device_name        = device_name,
        asset_id           = asset_id,
        business_unit      = business_unit,
        os_name            = os_name,
        assigned_analyst   = _assign_analyst(incident_id, status),
        correlation_confidence = _correlation_confidence(group),
        last_seen          = end_time_iso,
        **sla,
    )


# ---------------------------------------------------------------------------
# Grouping Strategies
# ---------------------------------------------------------------------------

def _group_by_user(events: list[Event]) -> tuple[list[list[Event]], set[str]]:
    """
    Strategy A: group all events for the same user into one incident.
    Returns (groups, set of consumed event_ids).
    Only applies to users with ≥ 2 events.
    """
    user_buckets: dict[str, list[Event]] = {}
    for e in events:
        user_buckets.setdefault(e.user, []).append(e)

    groups: list[list[Event]] = []
    consumed: set[str] = set()

    for user, user_evs in user_buckets.items():
        if len(user_evs) >= 2:
            groups.append(user_evs)
            for e in user_evs:
                consumed.add(e.event_id)

    return groups, consumed


def _group_by_campaign(
    events: list[Event], consumed: set[str]
) -> list[list[Event]]:
    """
    Strategy B: same attack_type + same network_segment within 72h window.
    Only processes events not already consumed by Strategy A.
    """
    remaining = [e for e in events if e.event_id not in consumed]
    if not remaining:
        return []

    # Sort chronologically
    remaining.sort(key=lambda e: e.timestamp)
    window = timedelta(hours=CAMPAIGN_WINDOW_HOURS)

    # Key: (attack_type, network_segment)
    open_groups: dict[tuple[str, str], list[Event]] = {}

    groups: list[list[Event]] = []

    for event in remaining:
        key = (event.attack_type, event.network_segment)
        if key in open_groups:
            bucket = open_groups[key]
            last_ts = max(e.timestamp for e in bucket)
            if (event.timestamp - last_ts) <= window:
                bucket.append(event)
                continue
            else:
                # Close old bucket, start new
                if len(bucket) >= 2:
                    groups.append(bucket)
                open_groups[key] = [event]
        else:
            open_groups[key] = [event]

    # Close remaining open groups
    for bucket in open_groups.values():
        if len(bucket) >= 2:
            groups.append(bucket)

    return groups


def _thread_id_for_group(group: list[Event], counter: list[int]) -> str:
    dominant_user = _dominant([e.user for e in group])
    tid = f"THREAD-{counter[0]:04d}"
    counter[0] += 1
    return tid


def _correlation_reason_user(events: list[Event]) -> str:
    user = _dominant([e.user for e in events])
    types = sorted(set(e.attack_type for e in events))
    return f"behavioral thread — same user ({user}); attack types: {', '.join(types)}"


def _correlation_reason_campaign(events: list[Event]) -> str:
    atype   = _dominant([e.attack_type for e in events])
    segment = _dominant([e.network_segment for e in events])
    return f"campaign detection — same attack type ({atype}) in {segment} within {CAMPAIGN_WINDOW_HOURS}h window"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate_events(events: Optional[list[Event]] = None) -> list[Incident]:
    events = events if events is not None else get_events()
    events_sorted = sorted(events, key=lambda e: e.timestamp)

    counter = [1]
    incidents: list[Incident] = []

    # Strategy A: user behavioral grouping
    user_groups, consumed = _group_by_user(events_sorted)
    for group in user_groups:
        tid    = _thread_id_for_group(group, counter)
        reason = _correlation_reason_user(group)
        incidents.append(_build_incident(group, tid, reason))

    # Strategy B: campaign grouping for remaining events
    campaign_groups = _group_by_campaign(events_sorted, consumed)
    for group in campaign_groups:
        consumed.update(e.event_id for e in group)
        tid    = _thread_id_for_group(group, counter)
        reason = _correlation_reason_campaign(group)
        incidents.append(_build_incident(group, tid, reason))

    # Strategy C: single-event fallback for everything else
    for event in events_sorted:
        if event.event_id not in consumed:
            consumed.add(event.event_id)
            tid    = f"THREAD-{counter[0]:04d}"
            counter[0] += 1
            stage  = ATTACK_TYPE_TO_STAGE.get(event.attack_type, "Unknown")
            mchain = _build_mitre_chain([stage]) if stage != "Unknown" else []
            risk, rlevel = _compute_risk_score(event.severity, 1, [stage], mchain, 0.0)
            rng    = _seeded_rng(event.event_id)
            det_lo, det_hi = DETECTION_DELAY_MINUTES.get(event.severity, (10, 60))
            mttd   = rng.uniform(det_lo, det_hi)
            det_at = event.timestamp + timedelta(minutes=mttd)
            res_lo, res_hi = RESPONSE_DELAY_MINUTES.get(event.action_taken, (30, 120))
            mttr   = rng.uniform(res_lo, res_hi)
            res_at = det_at + timedelta(minutes=mttr)

            status = _initial_status(event.action_taken)
            incident_id = f"INC-{event.event_id.replace('EVT-','')}"
            end_time_iso = event.timestamp.isoformat()
            hostname, device_name, asset_id, business_unit, os_name = _asset_identity(
                event.user, event.device_info
            )
            sla = _compute_sla(event.severity, mttd, mttr, status)

            incidents.append(Incident(
                incident_id        = incident_id,
                thread_id          = tid,
                event_id           = event.event_id,
                source_ip          = event.src_ip,
                dst_ip             = event.dst_ip,
                attack_type        = event.attack_type,
                severity           = event.severity,
                network_segment    = event.network_segment,
                user               = event.user,
                occurred_at        = event.timestamp.isoformat(),
                detected_at        = det_at.isoformat(),
                resolved_at        = res_at.isoformat(),
                action_taken       = event.action_taken,
                mttd_minutes       = round(mttd, 2),
                mttr_minutes       = round(mttr, 2),
                related_events     = [event.event_id],
                event_count        = 1,
                start_time         = event.timestamp.isoformat(),
                end_time           = end_time_iso,
                affected_users     = [event.user],
                affected_ips       = [event.src_ip, event.dst_ip],
                correlation_reason = "single event — no correlated peers found",
                attack_chain       = [stage] if stage != "Unknown" else [],
                attack_stage       = stage,
                chain_confidence   = 0.0,
                mitre_chain        = mchain,
                risk_score         = risk,
                risk_level         = rlevel,
                status             = status,
                hostname           = hostname,
                device_name        = device_name,
                asset_id           = asset_id,
                business_unit      = business_unit,
                os_name            = os_name,
                assigned_analyst   = _assign_analyst(incident_id, status),
                correlation_confidence = 1.0,
                last_seen          = end_time_iso,
                **sla,
            ))

    incidents.sort(key=lambda i: i.occurred_at)
    return incidents


def get_user_threads(incidents: list[Incident]) -> dict[str, list[Incident]]:
    threads: dict[str, list[Incident]] = {}
    for inc in incidents:
        threads.setdefault(inc.thread_id, []).append(inc)
    return threads


_CACHE: list[Incident] | None = None


def get_incidents(force_reload: bool = False) -> list[Incident]:
    global _CACHE
    if _CACHE is None or force_reload:
        _CACHE = correlate_events()
    return _CACHE


def update_incident_status(incident_id: str, new_status: str) -> Incident | None:
    """
    Mutates the in-memory incident in place so the change is visible to
    every subsequent request in this server session (mirrors how the
    rest of the system is a cached, in-memory derivation of the static
    CSV — see ingestion/loader.py). Returns the updated Incident, or
    None if no incident with that id exists.
    """
    incidents = get_incidents()
    for inc in incidents:
        if inc.incident_id == incident_id:
            inc.status = new_status
            if inc.assigned_analyst == "Unassigned" and new_status != "Open":
                inc.assigned_analyst = _assign_analyst(inc.incident_id, new_status)
            sla = _compute_sla(inc.severity, inc.mttd_minutes, inc.mttr_minutes, new_status)
            inc.containment_sla_breached = sla["containment_sla_breached"]
            return inc
    return None


def escalate_incident(
    incident_id: str,
    escalated_to: str,
    reason: str,
    escalated_by: str,
) -> Incident | None:
    """
    Records a Tier-1 → Tier-2 handoff on the incident in place. Mirrors
    update_incident_status()'s in-memory mutation approach.

    Deliberately does NOT change `status` — escalation is a parallel
    "who owns this now" signal, not a workflow stage. An escalated
    incident can still move Open -> Investigating -> Contained normally;
    the escalation flag and status are independent.

    Idempotent-ish: re-escalating an already-escalated incident just
    overwrites the reason/timestamp (e.g. new information came in) rather
    than erroring — there's no product requirement yet for tracking
    escalation history, only current escalation state.
    """
    incidents = get_incidents()
    for inc in incidents:
        if inc.incident_id == incident_id:
            inc.escalated         = True
            inc.escalated_to      = escalated_to
            inc.escalated_by      = escalated_by
            inc.escalation_reason = reason
            inc.escalated_at      = datetime.utcnow().isoformat()
            return inc
    return None


def correlation_stats(events: Optional[list] = None, incidents: Optional[list[Incident]] = None) -> dict:
    """
    Surfaces *why* N raw events became M incidents — the correlation
    engine's actual value, instead of showing bare totals with no
    explanation. "Duplicate events merged" = events that were folded into
    a multi-event incident rather than standing alone.
    """
    events = events if events is not None else get_events()
    incidents = incidents if incidents is not None else get_incidents()

    total_events = len(events)
    total_incidents = len(incidents)
    merged_events = sum(i.event_count for i in incidents if i.event_count > 1)
    multi_event_incidents = sum(1 for i in incidents if i.event_count > 1)
    duplicates_merged = merged_events - multi_event_incidents  # events absorbed into an existing incident

    return {
        "raw_events": total_events,
        "correlated_incidents": total_incidents,
        "multi_event_incidents": multi_event_incidents,
        "duplicate_events_merged": duplicates_merged,
        "reduction_pct": round(100 * (1 - total_incidents / total_events), 1) if total_events else 0,
    }


if __name__ == "__main__":
    evs  = get_events()
    incs = get_incidents()
    print(f"Events: {len(evs)}  =>  Incidents: {len(incs)}  (reduction: {len(evs)-len(incs)} merged)")
    multi = [i for i in incs if i.event_count > 1]
    print(f"Multi-event incidents: {len(multi)}")
    chains = [i for i in incs if i.chain_confidence > 0.3]
    print(f"Attack chains detected: {len(chains)}")
    if multi:
        m = max(multi, key=lambda i: i.event_count)
        print(f"\nLargest group: {m.incident_id} ({m.event_count} events)")
        print(f"  Users:    {m.affected_users}")
        print(f"  Chain:    {m.attack_chain}")
        print(f"  MITRE:    {m.mitre_chain}")
        print(f"  Conf:     {m.chain_confidence}")
        print(f"  Risk:     {m.risk_score} ({m.risk_level})")
        print(f"  Reason:   {m.correlation_reason}")
