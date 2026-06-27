"""
Correlation Engine
===================
Groups raw events into Incidents and per-user behavioral threads.
Also synthesises detected_at / resolved_at timestamps for MTTD/MTTR.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Optional

from ingestion.loader import Event, get_events, MITRE_MAP

SEVERITY_MTTD = {"Critical": (2, 15), "High": (10, 45), "Medium": (30, 120), "Low": (60, 360)}
SEVERITY_MTTR = {"Critical": (15, 60), "High": (30, 180), "Medium": (60, 480), "Low": (120, 720)}


@dataclass
class Incident:
    incident_id: str
    event_id: str
    user: str
    source_ip: str
    dst_ip: str
    attack_type: str
    severity: str
    action_taken: str
    network_segment: str
    occurred_at: str
    detected_at: str
    resolved_at: str
    status: str
    assigned_to: Optional[str]
    mitre_technique: str
    mitre_tactic: str
    anomaly_score: float
    mttd_minutes: float
    mttr_minutes: float

    def to_dict(self) -> dict:
        return asdict(self)


def _build_incidents(events: list[Event]) -> list[Incident]:
    rng = random.Random(99)
    incidents: list[Incident] = []

    for i, e in enumerate(events):
        sev = e.severity
        mttd_lo, mttd_hi = SEVERITY_MTTD[sev]
        mttr_lo, mttr_hi = SEVERITY_MTTR[sev]
        mttd = round(rng.uniform(mttd_lo, mttd_hi), 1)
        mttr = round(rng.uniform(mttr_lo, mttr_hi), 1)

        detected_at = e.timestamp + timedelta(minutes=mttd)
        resolved_at = detected_at + timedelta(minutes=mttr)

        technique, tactic = MITRE_MAP.get(e.attack_type, ("T0000", "Unknown"))

        incidents.append(Incident(
            incident_id=f"INC-{i+1:05d}",
            event_id=e.event_id,
            user=e.user,
            source_ip=e.src_ip,
            dst_ip=e.dst_ip,
            attack_type=e.attack_type,
            severity=e.severity,
            action_taken=e.action_taken,
            network_segment=e.network_segment,
            occurred_at=e.timestamp.isoformat(),
            detected_at=detected_at.isoformat(),
            resolved_at=resolved_at.isoformat(),
            status="Open",
            assigned_to=None,
            mitre_technique=technique,
            mitre_tactic=tactic,
            anomaly_score=e.anomaly_score,
            mttd_minutes=mttd,
            mttr_minutes=mttr,
        ))

    return incidents


_INCIDENT_CACHE: list[Incident] | None = None


def get_incidents(force_reload: bool = False) -> list[Incident]:
    global _INCIDENT_CACHE
    if _INCIDENT_CACHE is None or force_reload:
        _INCIDENT_CACHE = _build_incidents(get_events())
    return _INCIDENT_CACHE


def get_user_threads(incidents: Optional[list[Incident]] = None) -> dict[str, list[Incident]]:
    incidents = incidents if incidents is not None else get_incidents()
    threads: dict[str, list[Incident]] = {}
    for inc in incidents:
        key = inc.user
        threads.setdefault(key, []).append(inc)
    return threads
