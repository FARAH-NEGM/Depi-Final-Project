"""
Event Ingestion / Loader
==========================
Generates a realistic synthetic security event dataset in memory.
No CSV file required — data is generated deterministically so every run
produces the same events (reproducible for demos/grading).

Each Event mirrors the schema expected by all downstream modules:
  event_id, timestamp, user, src_ip, dst_ip, network_segment,
  attack_type, severity, action_taken, anomaly_score
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class Event:
    event_id: str
    timestamp: datetime
    user: str
    src_ip: str
    dst_ip: str
    network_segment: str
    attack_type: str
    severity: str
    action_taken: str
    anomaly_score: float


# ── Synthetic dataset parameters ──────────────────────────────────────────────

USERS = [
    "alice.morgan", "bob.chen", "carol.james", "david.liu", "eve.patel",
    "frank.osei", "grace.kim", "henry.ross", "iris.taylor", "james.nkosi",
    "karen.wu", "liam.santos", "mia.jones", "noah.fischer", "olivia.brown",
    "peter.garcia", "quinn.walker", "rachel.ahmed", "sam.lee", "tina.clark",
]

SRC_IPS = [
    "10.0.1.10", "10.0.1.22", "10.0.2.5", "10.0.2.17", "10.0.3.8",
    "10.0.3.31", "10.0.4.14", "10.0.4.29", "192.168.1.5", "192.168.1.18",
    "192.168.2.3", "192.168.2.44", "172.16.0.7", "172.16.0.19",
]

DST_IPS = [
    "10.0.10.1", "10.0.10.2", "10.0.20.5", "10.0.20.6", "10.0.30.3",
    "10.0.30.9", "8.8.8.8", "1.1.1.1", "203.0.113.50", "198.51.100.12",
    "10.0.10.100", "10.0.20.200",
]

SEGMENTS = ["Segment A", "Segment B", "Segment C", "Segment D"]

ATTACK_TYPES = [
    "Brute Force", "SQL Injection", "Phishing", "Ransomware",
    "DDoS", "Man-in-the-Middle", "Privilege Escalation",
    "Data Exfiltration", "Lateral Movement", "Zero-Day Exploit",
]

SEVERITY_DIST = [
    ("Critical", 0.12), ("High", 0.28), ("Medium", 0.38), ("Low", 0.22)
]

ACTIONS = [
    ("Blocked", 0.35), ("Quarantined", 0.20), ("Logged", 0.30), ("Ignored", 0.15)
]

MITRE_MAP = {
    "Brute Force":            ("T1110", "Credential Access"),
    "SQL Injection":          ("T1190", "Initial Access"),
    "Phishing":               ("T1566", "Initial Access"),
    "Ransomware":             ("T1486", "Impact"),
    "DDoS":                   ("T1498", "Impact"),
    "Man-in-the-Middle":      ("T1557", "Credential Access"),
    "Privilege Escalation":   ("T1068", "Privilege Escalation"),
    "Data Exfiltration":      ("T1041", "Exfiltration"),
    "Lateral Movement":       ("T1021", "Lateral Movement"),
    "Zero-Day Exploit":       ("T1203", "Execution"),
}


def _weighted_choice(rng: random.Random, choices: list[tuple]) -> str:
    items = [c[0] for c in choices]
    weights = [c[1] for c in choices]
    return rng.choices(items, weights=weights, k=1)[0]


def _generate_events(n: int = 800, seed: int = 42) -> list[Event]:
    rng = random.Random(seed)
    start = datetime(2023, 1, 1)
    end = datetime(2024, 12, 31)
    span = (end - start).total_seconds()

    events: list[Event] = []
    for i in range(n):
        ts = start + timedelta(seconds=rng.uniform(0, span))
        user = rng.choice(USERS)
        src = rng.choice(SRC_IPS)
        dst = rng.choice(DST_IPS)
        seg = rng.choice(SEGMENTS)
        attack = rng.choice(ATTACK_TYPES)
        severity = _weighted_choice(rng, SEVERITY_DIST)
        action = _weighted_choice(rng, ACTIONS)
        anomaly = round(rng.uniform(0, 100), 2)

        events.append(Event(
            event_id=f"EVT-{i+1:05d}",
            timestamp=ts,
            user=user,
            src_ip=src,
            dst_ip=dst,
            network_segment=seg,
            attack_type=attack,
            severity=severity,
            action_taken=action,
            anomaly_score=anomaly,
        ))

    events.sort(key=lambda e: e.timestamp)
    return events


_CACHE: list[Event] | None = None


def get_events(force_reload: bool = False) -> list[Event]:
    global _CACHE
    if _CACHE is None or force_reload:
        _CACHE = _generate_events()
    return _CACHE
