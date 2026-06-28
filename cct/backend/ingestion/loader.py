"""
Log Ingestion Layer
====================
Loads raw security log data (currently: the cybersecurity_example.csv dataset)
and normalises every row into a single, consistent "Event" schema that every
downstream module (Correlation, MITRE mapping, Trust Score, MTTD/MTTR, Graph)
can rely on.

Why this layer exists
----------------------
Real SOCs pull logs from many different sources (firewalls, IDS/IPS, servers,
proxies) each with their own field names. The whole point of a "Cyber Control
Tower" is to flatten all of that into one normalised event stream. This module
is where that flattening happens — if you ever plug in a second dataset
(UNSW-NB15, CICIDS-2017, NSL-KDD — see the /notebooks folder) you only need to
write one new `*_to_events()` function here; nothing else in the system needs
to change.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Optional

import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DEFAULT_CSV = os.path.join(DATA_DIR, "cybersecurity_example.csv")


@dataclass
class Event:
    """Unified security event schema used across the whole CCT system."""

    event_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_length: int
    packet_type: str
    traffic_type: str
    payload_snippet: str
    malware_indicator: bool
    anomaly_score: float
    alert_triggered: bool
    attack_type: str
    attack_signature: str
    action_taken: str
    severity: str
    user: str
    device_info: str
    network_segment: str
    geo_location: str
    proxy_ip: Optional[str]
    firewall_logged: bool
    ids_ips_alert: bool
    log_source: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _make_event_id(row: pd.Series, idx: int) -> str:
    """Deterministic short hash so re-running ingestion gives stable IDs."""
    raw = f"{row['Timestamp']}-{row['Source IP Address']}-{row['Destination IP Address']}-{idx}"
    return "EVT-" + hashlib.sha1(raw.encode()).hexdigest()[:10]


def load_raw_csv(path: str = DEFAULT_CSV) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found at {path}")
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    return df


def csv_to_events(path: str = DEFAULT_CSV) -> list[Event]:
    """Load the cybersecurity_example dataset and normalise to Event objects."""
    df = load_raw_csv(path)
    events: list[Event] = []

    for idx, row in df.iterrows():
        ts = pd.to_datetime(row["Timestamp"])

        events.append(
            Event(
                event_id=_make_event_id(row, idx),
                timestamp=ts.to_pydatetime(),
                src_ip=row["Source IP Address"],
                dst_ip=row["Destination IP Address"],
                src_port=int(row["Source Port"]),
                dst_port=int(row["Destination Port"]),
                protocol=row["Protocol"],
                packet_length=int(row["Packet Length"]),
                packet_type=row["Packet Type"],
                traffic_type=row["Traffic Type"],
                payload_snippet=str(row["Payload Data"])[:120],
                malware_indicator=(pd.notna(row["Malware Indicators"])),
                anomaly_score=float(row["Anomaly Scores"]),
                alert_triggered=(pd.notna(row["Alerts/Warnings"])),
                attack_type=row["Attack Type"],
                attack_signature=row["Attack Signature"],
                action_taken=row["Action Taken"],
                severity=row["Severity Level"],
                user=row["User Information"],
                device_info=row["Device Information"],
                network_segment=row["Network Segment"],
                geo_location=row["Geo-location Data"],
                proxy_ip=(row["Proxy Information"] if pd.notna(row["Proxy Information"]) else None),
                firewall_logged=(pd.notna(row["Firewall Logs"])),
                ids_ips_alert=(pd.notna(row["IDS/IPS Alerts"])),
                log_source=row["Log Source"],
            )
        )

    # Chronological order matters a lot downstream (correlation windows,
    # live-feed simulation, MTTD/MTTR ordering).
    events.sort(key=lambda e: e.timestamp)
    return events


_CACHE: list[Event] | None = None


def get_events(force_reload: bool = False) -> list[Event]:
    """Cached accessor so we don't re-parse the CSV on every API call."""
    global _CACHE
    if _CACHE is None or force_reload:
        _CACHE = csv_to_events()
    return _CACHE


if __name__ == "__main__":
    evs = get_events()
    print(f"Loaded {len(evs)} events")
    print(evs[0].to_dict())
