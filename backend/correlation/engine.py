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
    import math

    sev_score   = SEVERITY_RISK.get(severity, 40)
    count_score = min(100.0, 100 * math.log1p(event_count) / math.log1p(20))
    chain_score = min(100.0, (len(chain) / max(len(KILL_CHAIN), 1)) * 100 * (chain_conf or 0.1)) if chain else 0
    tactic_avg  = (
        sum(TACTIC_CRITICALITY.get(t, 0.5) for t in mitre_chain) / len(mitre_chain) * 100
        if mitre_chain else 40.0
    )

    raw = (
        0.40 * sev_score +
        0.20 * count_score +
        0.25 * chain_score +
        0.15 * tactic_avg
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

    return Incident(
        incident_id        = _make_incident_id(group),
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
        end_time           = group_sorted[-1].timestamp.isoformat(),
        affected_users     = sorted(set(e.user   for e in group)),
        affected_ips       = sorted(set(e.src_ip for e in group) | set(e.dst_ip for e in group)),
        correlation_reason = correlation_reason,
        attack_chain       = attack_chain if attack_chain else stages,
        attack_stage       = attack_stage,
        chain_confidence   = chain_conf,
        mitre_chain        = mitre_chain,
        risk_score         = risk_score,
        risk_level         = risk_level,
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
  # Prevent processing when no events exist
    if not events:
       return []
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

            incidents.append(Incident(
                incident_id        = f"INC-{event.event_id.replace('EVT-','')}",
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
                end_time           = event.timestamp.isoformat(),
                affected_users     = [event.user],
                affected_ips       = [event.src_ip, event.dst_ip],
                correlation_reason = "single event — no correlated peers found",
                attack_chain       = [stage] if stage != "Unknown" else [],
                attack_stage       = stage,
                chain_confidence   = 0.0,
                mitre_chain        = mchain,
                risk_score         = risk,
                risk_level         = rlevel,
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
