"""
Correlation Engine
===================
Groups raw, isolated Events into "Incidents" and links incidents that share
the same user account into "behavioral threads" — the core idea behind
moving beyond a flat log dump into attack storytelling (per the project's
Literature Review key insight).

Correlation strategy — and why
-------------------------------
The dataset has no native session/incident ID, and (we verified this
directly against the data) it has no real temporal clustering either:
every `Source IP Address` is unique, and even the same `User Information`
value tends to reappear weeks or months apart rather than in a tight burst.
A short sliding time-window would therefore either find nothing (honest but
useless for a demo) or be artificially loosened until it stops meaning
anything (dishonest).

So the model used here is the one that's actually true to the data and
still realistic for a SOC:

  1. Each individual Event becomes its own Incident. This is realistic too —
     plenty of real incidents *are* single, self-contained events (e.g. one
     blocked exploit attempt). Each Incident gets a synthesised detect/respond
     timeline (see below).
  2. Separately, every Incident is tagged with a `thread_id` shared by all
     Incidents involving the SAME user. This is the "attack story" view: it
     lets the dashboard show "this user has been involved in N incidents over
     time", which is exactly the behavioral signal the Trust Score engine
     needs, without inventing a false sense of tight temporal clustering that
     isn't in the data.

Each Incident also gets:
  - a synthesised `detected_at` timestamp (first event + simulated detection
    delay, derived from severity — higher severity = faster detection, which
    is realistic: critical alerts page analysts faster)
  - a synthesised `resolved_at` timestamp (detected_at + simulated response
    delay, derived from `action_taken` — Blocked/Quarantined resolve faster
    than Logged/Ignored)

These synthesised timestamps are what feed the MTTD / MTTR engine. This is
explicitly a SIMULATION layer (the project is an SOC *simulator*, per the
README) — not a claim that we recovered real detect/respond times from the
raw data, which doesn't contain them.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Optional

from ingestion.loader import Event, get_events

# Simulated detection delay (minutes) by severity — higher severity pages
# analysts faster in a realistic SOC.
DETECTION_DELAY_MINUTES = {
    "Critical": (1, 5),
    "High": (3, 15),
    "Medium": (10, 45),
    "Low": (30, 120),
}

# Simulated response delay (minutes) by action taken.
RESPONSE_DELAY_MINUTES = {
    "Blocked": (2, 10),
    "Quarantined": (5, 20),
    "Logged": (20, 90),
    "Ignored": (60, 240),
}


@dataclass
class Incident:
    incident_id: str
    thread_id: str  # shared across all incidents from the same user
    event_id: str
    source_ip: str
    dst_ip: str
    attack_type: str
    severity: str
    network_segment: str
    user: str
    occurred_at: str
    detected_at: str
    resolved_at: str
    action_taken: str
    mttd_minutes: float
    mttr_minutes: float

    def to_dict(self) -> dict:
        return asdict(self)


def _seeded_rng(seed_key: str) -> random.Random:
    # Deterministic per-incident randomness so repeated runs give stable demo
    # data (important for a reproducible coursework demo / grading).
    return random.Random(seed_key)


def correlate_events(events: Optional[list[Event]] = None) -> list[Incident]:
    events = events if events is not None else get_events()

    # thread_id: stable id per user so the dashboard can show "this user's
    # incident history" across the whole timeline.
    user_thread_ids: dict[str, str] = {}
    next_thread_num = 1

    incidents: list[Incident] = []

    for e in events:
        if e.user not in user_thread_ids:
            user_thread_ids[e.user] = f"THREAD-{next_thread_num:04d}"
            next_thread_num += 1

        rng = _seeded_rng(e.event_id)

        det_lo, det_hi = DETECTION_DELAY_MINUTES.get(e.severity, (10, 60))
        mttd_minutes = rng.uniform(det_lo, det_hi)
        detected_at = e.timestamp + timedelta(minutes=mttd_minutes)

        res_lo, res_hi = RESPONSE_DELAY_MINUTES.get(e.action_taken, (30, 120))
        mttr_minutes = rng.uniform(res_lo, res_hi)
        resolved_at = detected_at + timedelta(minutes=mttr_minutes)

        incidents.append(
            Incident(
                incident_id=f"INC-{e.event_id.replace('EVT-', '')}",
                thread_id=user_thread_ids[e.user],
                event_id=e.event_id,
                source_ip=e.src_ip,
                dst_ip=e.dst_ip,
                attack_type=e.attack_type,
                severity=e.severity,
                network_segment=e.network_segment,
                user=e.user,
                occurred_at=e.timestamp.isoformat(),
                detected_at=detected_at.isoformat(),
                resolved_at=resolved_at.isoformat(),
                action_taken=e.action_taken,
                mttd_minutes=round(mttd_minutes, 2),
                mttr_minutes=round(mttr_minutes, 2),
            )
        )

    incidents.sort(key=lambda i: i.occurred_at)
    return incidents


def get_user_threads(incidents: list[Incident]) -> dict[str, list[Incident]]:
    """Group incidents by thread_id (i.e. by user) for behavioral analysis."""
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
    incs = get_incidents()
    print(f"Correlated {len(incs)} incidents from {len(get_events())} events")
    threads = get_user_threads(incs)
    repeat = {tid: incs_ for tid, incs_ in threads.items() if len(incs_) > 1}
    print(f"{len(repeat)} users have repeat-incident threads (>1 incident)")
    for tid, incs_ in list(repeat.items())[:3]:
        print(tid, [(i.incident_id, i.attack_type, i.severity) for i in incs_])
