"""
Database Schema & Connection
==============================
SQLite database for Cyber Control Tower. Stores all persistent state:
users, incidents, audit trail, propagation results, hunt history.
Raw events come from the CSV via ingestion/loader.py and are held in memory.
"""
from __future__ import annotations

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "cct.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'Security Analyst',
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id    TEXT PRIMARY KEY,
            event_id       TEXT NOT NULL,
            user           TEXT NOT NULL,
            source_ip      TEXT NOT NULL,
            dst_ip         TEXT NOT NULL,
            attack_type    TEXT NOT NULL,
            severity       TEXT NOT NULL,
            action_taken   TEXT NOT NULL,
            network_segment TEXT NOT NULL,
            occurred_at    TEXT NOT NULL,
            detected_at    TEXT NOT NULL,
            resolved_at    TEXT NOT NULL,
            status         TEXT NOT NULL DEFAULT 'Open',
            assigned_to    TEXT,
            mitre_technique TEXT,
            mitre_tactic    TEXT,
            anomaly_score   REAL DEFAULT 0,
            mttd_minutes    REAL DEFAULT 0,
            mttr_minutes    REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS incident_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id  TEXT NOT NULL,
            from_status  TEXT,
            to_status    TEXT NOT NULL,
            changed_by   TEXT NOT NULL,
            note         TEXT,
            changed_at   TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        );

        CREATE TABLE IF NOT EXISTS responses (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id  TEXT NOT NULL,
            decision     TEXT NOT NULL,
            reasoning    TEXT,
            triggered_by TEXT NOT NULL,
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        );

        CREATE TABLE IF NOT EXISTS propagations (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id       TEXT NOT NULL,
            hop_index         INTEGER NOT NULL,
            node_id           TEXT NOT NULL,
            node_type         TEXT NOT NULL,
            probability       REAL NOT NULL,
            via_relation      TEXT,
            blast_radius_rank INTEGER NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT NOT NULL,
            action       TEXT NOT NULL,
            resource     TEXT,
            detail       TEXT,
            created_at   TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS devices (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address   TEXT NOT NULL UNIQUE,
            subject_user TEXT NOT NULL,
            type         TEXT
        );

        CREATE TABLE IF NOT EXISTS servers (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            hostname   TEXT
        );

        CREATE TABLE IF NOT EXISTS hunt_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            query_id    TEXT NOT NULL,
            run_by      TEXT NOT NULL,
            result_json TEXT,
            ran_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """)
        conn.commit()
    finally:
        conn.close()
