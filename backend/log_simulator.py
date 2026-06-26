"""
CCT – Cyber Control Tower
Log Simulator
=============
Generates realistic Windows / Linux / Authentication log entries
(as described in the CCT Project Scope) and submits them to the
Log Ingestion API via POST /api/logs/ingest.

Run standalone:
    python log_simulator.py --count 50 --source IDS

Or import and call simulate_batch() from other modules.
"""

from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Literal, Optional
import requests

# ─────────────────────────────────────────────────────────────────
#  Constants — aligned with CCT dataset field values
# ─────────────────────────────────────────────────────────────────
LOG_SOURCES    = ["Firewall", "IDS", "Proxy", "Server"]
PROTOCOLS      = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "FTP"]
PACKET_TYPES   = ["SYN", "ACK", "FIN", "RST", "PSH", "SYN-ACK"]
TRAFFIC_TYPES  = ["HTTP", "HTTPS", "FTP", "DNS", "SSH", "SMTP"]
SEVERITIES     = ["Low", "Medium", "High", "Critical"]
ATTACK_TYPES   = [
    "DDoS", "Ransomware", "Phishing", "XSS",
    "SQL Injection", "Malware", "Intrusion", "Brute Force",
]
ACTIONS_TAKEN  = ["Blocked", "Logged", "Quarantined", "Ignored"]
SEGMENTS       = ["Segment A", "Segment B", "Segment C", "Segment D"]
SIGNATURES     = ["Known Pattern A", "Known Pattern B", "Unknown Pattern", "Zero-Day"]
MALWARE_FLAGS  = ["IoC Detected", None]
GEOS           = [
    "Cairo, Egypt", "New York, US", "London, UK",
    "Moscow, Russia", "Beijing, China", "Berlin, Germany",
]

# Realistic IP pools
INTERNAL_IPS = [f"192.168.{r}.{h}" for r in range(1, 5) for h in range(10, 30)]
EXTERNAL_IPS = [
    f"{a}.{b}.{c}.{d}"
    for a, b, c, d in [
        (8, 24, 56, 60), (166, 19, 156, 163), (43, 68, 136, 224),
        (222, 187, 14, 173), (91, 108, 4, 200), (104, 21, 7, 89),
    ]
]

# Windows / Linux / Auth log templates (plain-text payloads)
LOG_TEMPLATES = {
    "Firewall": [
        "DENY {proto} src={src} dst={dst} dpt={dpt}",
        "ALLOW {proto} src={src} dst={dst} sport={sport}",
    ],
    "IDS": [
        'ALERT: {attack} detected from {src} — signature "{sig}"',
        "ANOMALY: anomaly score {score:.1f} from {src} targeting {dst}",
    ],
    "Proxy": [
        "PROXY BLOCK: {src} -> {dst}:{dpt} ({proto}) — category=malware",
        "PROXY LOG: {src} -> {dst} GET / HTTP/1.1 — user={user}",
    ],
    "Server": [
        "AUTH FAILURE: user={user} ip={src} attempts=5 — brute force suspected",
        "SSH LOGIN: user={user} from {src} accepted",
        "EVENT ID 4625: Failed logon from {src} — account={user}",
    ],
}


# ─────────────────────────────────────────────────────────────────
#  Entry generators
# ─────────────────────────────────────────────────────────────────
def _random_ip(internal: bool = False) -> str:
    return random.choice(INTERNAL_IPS if internal else EXTERNAL_IPS)


def _random_port(well_known: bool = False) -> int:
    if well_known:
        return random.choice([21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080])
    return random.randint(1024, 65535)


def _random_timestamp(days_back: int = 30) -> str:
    base = datetime.now() - timedelta(days=random.randint(0, days_back))
    return base.strftime("%Y-%m-%d %H:%M:%S")


def _severity_from_score(score: float) -> str:
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    return "Low"


def generate_log_entry(
    source: Optional[str] = None,
    force_attack: bool = False,
) -> Dict:
    """
    Generate one realistic log entry matching the CCT dataset schema.

    Parameters
    ----------
    source : str | None
        Force a specific log source; random if None.
    force_attack : bool
        If True, guarantee a non-null attack type (useful for simulation scenarios).
    """
    src_ip    = _random_ip(internal=False)
    dst_ip    = _random_ip(internal=True)
    src_port  = _random_port()
    dst_port  = _random_port(well_known=True)
    proto     = random.choice(PROTOCOLS)
    log_src   = source or random.choice(LOG_SOURCES)
    score     = round(random.uniform(10, 99), 2)
    severity  = _severity_from_score(score)
    user      = random.choice(["admin", "root", "john.doe", "svc_account", "guest"])

    # Build payload from template
    template = random.choice(LOG_TEMPLATES.get(log_src, ["Generic log from {src}"]))
    payload  = template.format(
        proto=proto, src=src_ip, dst=dst_ip,
        sport=src_port, dpt=dst_port,
        attack=random.choice(ATTACK_TYPES),
        sig=random.choice(SIGNATURES),
        score=score, user=user,
    )

    attack_type = (
        random.choice(ATTACK_TYPES)
        if (force_attack or score >= 50)
        else None
    )

    entry = {
        "Timestamp":               _random_timestamp(),
        "Source IP Address":       src_ip,
        "Destination IP Address":  dst_ip,
        "Source Port":             src_port,
        "Destination Port":        dst_port,
        "Protocol":                proto,
        "Packet Length":           random.randint(64, 1500),
        "Packet Type":             random.choice(PACKET_TYPES),
        "Traffic Type":            random.choice(TRAFFIC_TYPES),
        "Payload Data":            payload,
        "Malware Indicators":      random.choice(MALWARE_FLAGS),
        "Anomaly Scores":          score,
        "Alerts/Warnings":         None if score < 50 else score,
        "Attack Type":             attack_type,
        "Attack Signature":        random.choice(SIGNATURES) if attack_type else None,
        "Action Taken":            random.choice(ACTIONS_TAKEN),
        "Severity Level":          severity,
        "User Information":        user,
        "Device Information":      f"Device-{random.randint(100, 999)}",
        "Network Segment":         random.choice(SEGMENTS),
        "Geo-location Data":       random.choice(GEOS),
        "Proxy Information":       _random_ip() if log_src == "Proxy" else None,
        "Firewall Logs":           payload if log_src == "Firewall" else None,
        "IDS/IPS Alerts":         f"Alert: {attack_type}" if log_src == "IDS" and attack_type else None,
        "Log Source":              log_src,
    }
    return entry


def simulate_batch(count: int = 20, source: Optional[str] = None) -> List[Dict]:
    """Generate a batch of log entries without sending to API."""
    return [generate_log_entry(source=source) for _ in range(count)]


# ─────────────────────────────────────────────────────────────────
#  Attack scenario presets
# ─────────────────────────────────────────────────────────────────
def simulate_ddos_attack(target_ip: str = "192.168.1.5", wave: int = 30) -> List[Dict]:
    """
    Simulate a DDoS wave: many sources → one target, all critical.
    Designed to trigger the Correlation Engine on the same destination.
    """
    entries = []
    for _ in range(wave):
        entry = generate_log_entry(source="Firewall", force_attack=True)
        entry["Attack Type"]        = "DDoS"
        entry["Destination IP Address"] = target_ip
        entry["Severity Level"]     = "Critical"
        entry["Anomaly Scores"]     = round(random.uniform(85, 99), 2)
        entries.append(entry)
    return entries


def simulate_brute_force(target_user: str = "admin", attempts: int = 10) -> List[Dict]:
    """
    Simulate repeated failed auth attempts from same source to same user.
    """
    src_ip = _random_ip(internal=False)
    entries = []
    for i in range(attempts):
        entry = generate_log_entry(source="Server", force_attack=True)
        entry["Attack Type"]       = "Brute Force"
        entry["Source IP Address"] = src_ip
        entry["User Information"]  = target_user
        entry["Severity Level"]    = "High" if i < 5 else "Critical"
        entries.append(entry)
    return entries


# ─────────────────────────────────────────────────────────────────
#  CLI — send simulated logs to the running API
# ─────────────────────────────────────────────────────────────────
def send_to_api(entries: List[Dict], api_url: str = "http://localhost:5000") -> None:
    """POST entries to the batch ingestion endpoint."""
    endpoint = f"{api_url}/api/logs/batch"
    try:
        resp = requests.post(endpoint, json=entries, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        print(
            f"[SIMULATOR] Sent {len(entries)} entries → "
            f"accepted: {data.get('accepted')}, rejected: {data.get('rejected')}"
        )
    except requests.RequestException as exc:
        print(f"[SIMULATOR] Failed to reach API: {exc}")
        print("[SIMULATOR] Dumping entries to stdout instead:")
        print(json.dumps(entries[:3], indent=2), "...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CCT Log Simulator")
    parser.add_argument("--count",    type=int, default=20,             help="Number of log entries to generate")
    parser.add_argument("--source",   type=str, default=None,           help="Force a log source (Firewall/IDS/Proxy/Server)")
    parser.add_argument("--scenario", type=str, default="random",       help="Scenario: random | ddos | brute_force")
    parser.add_argument("--api",      type=str, default="http://localhost:5000", help="API base URL")
    parser.add_argument("--dry-run",  action="store_true",              help="Print entries instead of POSTing to API")
    args = parser.parse_args()

    if args.scenario == "ddos":
        entries = simulate_ddos_attack(wave=args.count)
        print(f"[SIMULATOR] DDoS scenario: {len(entries)} entries")
    elif args.scenario == "brute_force":
        entries = simulate_brute_force(attempts=args.count)
        print(f"[SIMULATOR] Brute force scenario: {len(entries)} entries")
    else:
        entries = simulate_batch(count=args.count, source=args.source)
        print(f"[SIMULATOR] Random scenario: {len(entries)} entries")

    if args.dry_run:
        print(json.dumps(entries[:5], indent=2))
        print(f"... ({len(entries)} total entries)")
    else:
        send_to_api(entries, api_url=args.api)
