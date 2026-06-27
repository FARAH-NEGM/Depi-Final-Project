"""
Database Seeder
================
Seeds the SQLite database from in-memory events/incidents so SQL-backed
modules (auth, assets, propagation, audit) have data to query.
Only runs if the incidents table is empty (idempotent).
"""
from __future__ import annotations

from db.schema import get_connection, init_db
from ingestion.loader import get_events, SRC_IPS, DST_IPS, USERS
from correlation.engine import get_incidents
from auth.service import ensure_demo_users


def seed_incidents() -> None:
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
        if count > 0:
            return  # already seeded

        incidents = get_incidents()
        for inc in incidents:
            conn.execute("""
                INSERT OR IGNORE INTO incidents
                (incident_id, event_id, user, source_ip, dst_ip, attack_type,
                 severity, action_taken, network_segment, occurred_at, detected_at,
                 resolved_at, status, assigned_to, mitre_technique, mitre_tactic,
                 anomaly_score, mttd_minutes, mttr_minutes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                inc.incident_id, inc.event_id, inc.user, inc.source_ip, inc.dst_ip,
                inc.attack_type, inc.severity, inc.action_taken, inc.network_segment,
                inc.occurred_at, inc.detected_at, inc.resolved_at, inc.status,
                inc.assigned_to, inc.mitre_technique, inc.mitre_tactic,
                inc.anomaly_score, inc.mttd_minutes, inc.mttr_minutes,
            ))
        conn.commit()
    finally:
        conn.close()


def seed_devices() -> None:
    """One device per (user, src_ip) pair observed in events."""
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
        if count > 0:
            return

        events = get_events()
        seen: set[tuple] = set()
        device_types = ["Workstation", "Laptop", "Mobile", "Desktop", "Virtual Machine"]
        import random
        rng = random.Random(7)
        for e in events:
            key = (e.user, e.src_ip)
            if key not in seen:
                seen.add(key)
                dtype = rng.choice(device_types)
                conn.execute(
                    "INSERT OR IGNORE INTO devices (ip_address, subject_user, type) VALUES (?,?,?)",
                    (e.src_ip, e.user, dtype),
                )
        conn.commit()
    finally:
        conn.close()


def seed_servers() -> None:
    """One server per observed destination IP."""
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) c FROM servers").fetchone()["c"]
        if count > 0:
            return

        events = get_events()
        seen: set[str] = set()
        hostnames = {
            "10.0.10.1": "auth-server-01",
            "10.0.10.2": "ldap-server-01",
            "10.0.10.100": "db-server-01",
            "10.0.20.5": "web-server-01",
            "10.0.20.6": "web-server-02",
            "10.0.20.200": "api-gateway-01",
            "10.0.30.3": "file-server-01",
            "10.0.30.9": "backup-server-01",
        }
        for e in events:
            ip = e.dst_ip
            if ip not in seen:
                seen.add(ip)
                hostname = hostnames.get(ip, ip.replace(".", "-"))
                conn.execute(
                    "INSERT OR IGNORE INTO servers (ip_address, hostname) VALUES (?,?)",
                    (ip, hostname),
                )
        conn.commit()
    finally:
        conn.close()


def run_all() -> None:
    init_db()
    ensure_demo_users()
    seed_incidents()
    seed_devices()
    seed_servers()
