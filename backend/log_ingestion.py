"""
CCT – Cyber Control Tower
Backend Developer 1: Log Ingestion Module
==========================================
Responsibilities:
  • Parse and normalize raw logs from multiple sources (Firewall, IDS, Proxy, Server)
  • Validate and enrich each log entry
  • Store normalized events in the shared Events database
  • Expose RESTful APIs for log ingestion and event retrieval

Author : Backend Developer 1
Dataset: cybersecurity_example (CSV / JSONL)
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

# ─────────────────────────────────────────────────────────────────
#  App & DB setup
# ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

# SQLite for development; swap to PostgreSQL in production
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{os.path.join(BASE_DIR, 'cct_events.db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ─────────────────────────────────────────────────────────────────
#  Database Model — Event
# ─────────────────────────────────────────────────────────────────
class Event(db.Model):
    """
    Normalized security event.

    Maps to the EVENT entity in the CCT ER diagram (Section 2.1):
      id, user_id, timestamp, action, severity
    Extended with network/traffic fields from our dataset.
    """

    __tablename__ = "events"

    id               = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp        = db.Column(db.DateTime, nullable=False, index=True)
    log_source       = db.Column(db.String(50),  nullable=False)   # Firewall / IDS / Proxy / Server

    # Network identifiers
    source_ip        = db.Column(db.String(45),  nullable=True)
    destination_ip   = db.Column(db.String(45),  nullable=True)
    source_port      = db.Column(db.Integer,     nullable=True)
    destination_port = db.Column(db.Integer,     nullable=True)
    protocol         = db.Column(db.String(10),  nullable=True)

    # Traffic metadata
    packet_length    = db.Column(db.Integer,     nullable=True)
    packet_type      = db.Column(db.String(20),  nullable=True)
    traffic_type     = db.Column(db.String(20),  nullable=True)
    network_segment  = db.Column(db.String(30),  nullable=True)

    # Threat / classification fields
    attack_type      = db.Column(db.String(50),  nullable=True)
    attack_signature = db.Column(db.String(100), nullable=True)
    severity         = db.Column(db.String(20),  nullable=True, index=True)  # Low/Medium/High/Critical
    malware_indicator= db.Column(db.String(50),  nullable=True)
    anomaly_score    = db.Column(db.Float,       nullable=True)

    # Response / enrichment
    action_taken     = db.Column(db.String(30),  nullable=True)
    geo_location     = db.Column(db.String(100), nullable=True)
    user_info        = db.Column(db.String(100), nullable=True)
    device_info      = db.Column(db.String(200), nullable=True)

    # Raw log preservation (audit trail)
    raw_payload      = db.Column(db.Text,        nullable=True)

    # Ingestion metadata
    ingested_at      = db.Column(db.DateTime, default=datetime.utcnow)
    is_processed     = db.Column(db.Boolean, default=False)   # True once correlation engine picks it up

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":               self.id,
            "timestamp":        self.timestamp.isoformat() if self.timestamp else None,
            "log_source":       self.log_source,
            "source_ip":        self.source_ip,
            "destination_ip":   self.destination_ip,
            "source_port":      self.source_port,
            "destination_port": self.destination_port,
            "protocol":         self.protocol,
            "packet_length":    self.packet_length,
            "packet_type":      self.packet_type,
            "traffic_type":     self.traffic_type,
            "network_segment":  self.network_segment,
            "attack_type":      self.attack_type,
            "attack_signature": self.attack_signature,
            "severity":         self.severity,
            "malware_indicator":self.malware_indicator,
            "anomaly_score":    self.anomaly_score,
            "action_taken":     self.action_taken,
            "geo_location":     self.geo_location,
            "user_info":        self.user_info,
            "device_info":      self.device_info,
            "ingested_at":      self.ingested_at.isoformat() if self.ingested_at else None,
            "is_processed":     self.is_processed,
        }


# ─────────────────────────────────────────────────────────────────
#  Log Normalization — field mapping per source
# ─────────────────────────────────────────────────────────────────
SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

VALID_LOG_SOURCES  = {"Firewall", "IDS", "Proxy", "Server"}
VALID_PROTOCOLS    = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "FTP", "SSH"}
VALID_SEVERITIES   = set(SEVERITY_ORDER.keys())
VALID_ATTACK_TYPES = {
    "Ransomware", "Phishing", "XSS", "Intrusion",
    "SQL Injection", "Malware", "DDoS", "DoS", "Brute Force",
}


def _parse_timestamp(raw: Any) -> Optional[datetime]:
    """Try multiple formats; return None if unparseable."""
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(str(raw).strip(), fmt)
        except ValueError:
            continue
    return None


def _sanitize_ip(ip: Any) -> Optional[str]:
    """Basic IP sanity check; returns None for obviously malformed values."""
    if not ip:
        return None
    ip = str(ip).strip()
    # Accept IPv4 / IPv6 / CIDR — simple length+character guard
    if len(ip) > 45 or not all(c in "0123456789abcdefABCDEF.:/" for c in ip):
        return None
    return ip


def _sanitize_port(port: Any) -> Optional[int]:
    try:
        p = int(port)
        return p if 0 <= p <= 65535 else None
    except (TypeError, ValueError):
        return None


def normalize_log_entry(raw: Dict[str, Any]) -> Optional[Event]:
    """
    Map a raw log dictionary (CSV row or JSON object) to a normalized Event.

    Column names match the cybersecurity_example dataset exactly.
    Returns None when the entry is fundamentally invalid (missing source, bad timestamp).
    """
    # ── Required fields ───────────────────────────────────────────
    log_source = str(raw.get("Log Source", "")).strip()
    if log_source not in VALID_LOG_SOURCES:
        log_source = "Unknown"   # Accept but flag

    ts = _parse_timestamp(raw.get("Timestamp"))
    if ts is None:
        return None              # Cannot store an event with no time

    # ── Network fields ────────────────────────────────────────────
    src_ip   = _sanitize_ip(raw.get("Source IP Address"))
    dst_ip   = _sanitize_ip(raw.get("Destination IP Address"))
    src_port = _sanitize_port(raw.get("Source Port"))
    dst_port = _sanitize_port(raw.get("Destination Port"))

    protocol = str(raw.get("Protocol", "")).strip().upper()
    if protocol not in VALID_PROTOCOLS:
        protocol = None

    # ── Severity / threat fields ──────────────────────────────────
    severity = str(raw.get("Severity Level", "")).strip().title()
    if severity not in VALID_SEVERITIES:
        severity = "Low"

    attack_type = str(raw.get("Attack Type", "")).strip()
    if attack_type not in VALID_ATTACK_TYPES:
        attack_type = None

    try:
        anomaly_score = float(raw.get("Anomaly Scores", 0) or 0)
    except (TypeError, ValueError):
        anomaly_score = 0.0

    # ── Assemble Event ────────────────────────────────────────────
    event = Event(
        timestamp        = ts,
        log_source       = log_source,
        source_ip        = src_ip,
        destination_ip   = dst_ip,
        source_port      = src_port,
        destination_port = dst_port,
        protocol         = protocol,
        packet_length    = _sanitize_port(raw.get("Packet Length")),   # reuses int validator
        packet_type      = str(raw.get("Packet Type", "")).strip() or None,
        traffic_type     = str(raw.get("Traffic Type", "")).strip() or None,
        network_segment  = str(raw.get("Network Segment", "")).strip() or None,
        attack_type      = attack_type,
        attack_signature = str(raw.get("Attack Signature", "")).strip() or None,
        severity         = severity,
        malware_indicator= str(raw.get("Malware Indicators", "")).strip() or None,
        anomaly_score    = anomaly_score,
        action_taken     = str(raw.get("Action Taken", "")).strip() or None,
        geo_location     = str(raw.get("Geo-location Data", "")).strip() or None,
        user_info        = str(raw.get("User Information", "")).strip() or None,
        device_info      = str(raw.get("Device Information", "")).strip() or None,
        raw_payload      = json.dumps(raw, default=str),
    )
    return event


# ─────────────────────────────────────────────────────────────────
#  Batch Ingestion — CSV / JSONL files
# ─────────────────────────────────────────────────────────────────
def ingest_csv(filepath: str) -> Dict[str, int]:
    """
    Read a CSV log file, normalize every row, and persist to the DB.
    Returns a summary dict: {total, accepted, rejected}.
    """
    df = pd.read_csv(filepath, low_memory=False)
    records = df.to_dict(orient="records")
    return _bulk_ingest(records, source_label=os.path.basename(filepath))


def ingest_jsonl(filepath: str) -> Dict[str, int]:
    """
    Read a JSON-Lines log file, normalize, and persist.
    """
    records = []
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return _bulk_ingest(records, source_label=os.path.basename(filepath))


def _bulk_ingest(records: List[Dict], source_label: str) -> Dict[str, int]:
    total    = len(records)
    accepted = 0
    rejected = 0
    batch    = []

    for raw in records:
        event = normalize_log_entry(raw)
        if event:
            batch.append(event)
            accepted += 1
        else:
            rejected += 1

        # Flush every 500 rows to keep memory low
        if len(batch) >= 500:
            db.session.bulk_save_objects(batch)
            db.session.commit()
            batch.clear()

    if batch:
        db.session.bulk_save_objects(batch)
        db.session.commit()

    print(
        f"[INGEST] {source_label} — total: {total}, "
        f"accepted: {accepted}, rejected: {rejected}"
    )
    return {"total": total, "accepted": accepted, "rejected": rejected}


# ─────────────────────────────────────────────────────────────────
#  REST API Endpoints
# ─────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health_check():
    """Simple liveness probe."""
    return jsonify({"status": "ok", "service": "CCT Log Ingestion API", "timestamp": datetime.utcnow().isoformat()})


# ── POST /api/logs/ingest ─────────────────────────────────────────
@app.route("/api/logs/ingest", methods=["POST"])
def ingest_single_log():
    """
    Accept a single log entry as JSON.

    Request body (JSON):
    {
        "Timestamp": "2024-01-15 10:30:00",
        "Source IP Address": "192.168.1.10",
        "Destination IP Address": "10.0.0.5",
        "Source Port": 443,
        "Destination Port": 80,
        "Protocol": "TCP",
        "Packet Length": 1024,
        "Packet Type": "SYN",
        "Traffic Type": "HTTPS",
        "Attack Type": "DDoS",
        "Severity Level": "High",
        "Anomaly Scores": 87.5,
        "Log Source": "Firewall",
        ...
    }

    Returns:
        201 — event created, with event_id
        400 — validation failed (missing timestamp or bad data)
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    event = normalize_log_entry(data)
    if event is None:
        return jsonify({"error": "Invalid log entry — missing or unparseable Timestamp"}), 400

    db.session.add(event)
    db.session.commit()
    return jsonify({"message": "Event ingested", "event_id": event.id}), 201


# ── POST /api/logs/batch ──────────────────────────────────────────
@app.route("/api/logs/batch", methods=["POST"])
def ingest_batch():
    """
    Accept a list of log entries (JSON array).

    Returns summary: total / accepted / rejected counts.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "Request body must be a JSON array"}), 400

    result = _bulk_ingest(data, source_label="API batch")
    return jsonify(result), 200


# ── GET /api/events ───────────────────────────────────────────────
@app.route("/api/events", methods=["GET"])
def get_events():
    """
    Retrieve paginated list of normalized events.

    Query parameters:
        page      (int, default 1)
        per_page  (int, default 50, max 200)
        severity  (str) — filter by severity level
        log_source(str) — filter by source (Firewall / IDS / Proxy / Server)
        attack_type(str) — filter by attack type
        start     (str) — ISO datetime lower bound
        end       (str) — ISO datetime upper bound
        unprocessed(bool) — if true, return only events not yet picked up by correlation engine
    """
    page       = request.args.get("page",      1,   type=int)
    per_page   = min(request.args.get("per_page", 50,  type=int), 200)
    severity   = request.args.get("severity")
    log_source = request.args.get("log_source")
    attack_type= request.args.get("attack_type")
    start      = request.args.get("start")
    end        = request.args.get("end")
    unprocessed= request.args.get("unprocessed", "false").lower() == "true"

    q = Event.query

    if severity:
        q = q.filter(Event.severity == severity)
    if log_source:
        q = q.filter(Event.log_source == log_source)
    if attack_type:
        q = q.filter(Event.attack_type == attack_type)
    if start:
        try:
            q = q.filter(Event.timestamp >= datetime.fromisoformat(start))
        except ValueError:
            return jsonify({"error": f"Invalid start datetime: {start}"}), 400
    if end:
        try:
            q = q.filter(Event.timestamp <= datetime.fromisoformat(end))
        except ValueError:
            return jsonify({"error": f"Invalid end datetime: {end}"}), 400
    if unprocessed:
        q = q.filter(Event.is_processed == False)

    pagination = q.order_by(Event.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "page":       pagination.page,
        "per_page":   pagination.per_page,
        "total":      pagination.total,
        "pages":      pagination.pages,
        "events":     [e.to_dict() for e in pagination.items],
    })


# ── GET /api/events/<event_id> ────────────────────────────────────
@app.route("/api/events/<event_id>", methods=["GET"])
def get_event(event_id: str):
    """Retrieve a single event by its UUID."""
    event = Event.query.get(event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404
    return jsonify(event.to_dict())


# ── PATCH /api/events/<event_id>/mark-processed ──────────────────
@app.route("/api/events/<event_id>/mark-processed", methods=["PATCH"])
def mark_processed(event_id: str):
    """
    Called by the Correlation Engine (Backend Developer 2) to flag
    an event as consumed. Prevents duplicate correlation passes.
    """
    event = Event.query.get(event_id)
    if not event:
        return jsonify({"error": "Event not found"}), 404
    event.is_processed = True
    db.session.commit()
    return jsonify({"message": "Event marked as processed", "event_id": event_id})


# ── GET /api/stats ────────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def get_stats():
    """
    High-level ingestion statistics for the Dashboard (Layer 10).

    Returns event counts broken down by severity, source, and attack type.
    Also feeds the MTTD/MTTR module with raw event counts.
    """
    total = Event.query.count()
    unprocessed = Event.query.filter_by(is_processed=False).count()

    severity_counts = {
        row[0]: row[1]
        for row in db.session.query(Event.severity, db.func.count(Event.id))
                              .group_by(Event.severity).all()
    }
    source_counts = {
        row[0]: row[1]
        for row in db.session.query(Event.log_source, db.func.count(Event.id))
                              .group_by(Event.log_source).all()
    }
    attack_counts = {
        row[0]: row[1]
        for row in db.session.query(Event.attack_type, db.func.count(Event.id))
                              .filter(Event.attack_type.isnot(None))
                              .group_by(Event.attack_type).all()
    }

    return jsonify({
        "total_events":        total,
        "unprocessed_events":  unprocessed,
        "by_severity":         severity_counts,
        "by_log_source":       source_counts,
        "by_attack_type":      attack_counts,
    })


# ── POST /api/logs/upload/csv ─────────────────────────────────────
@app.route("/api/logs/upload/csv", methods=["POST"])
def upload_csv():
    """
    Accept a CSV file upload and trigger batch ingestion.
    Multipart form field name: 'file'
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    f = request.files["file"]
    if not f.filename.endswith(".csv"):
        return jsonify({"error": "Only .csv files are accepted"}), 400

    tmp_path = f"/tmp/{uuid.uuid4()}.csv"
    f.save(tmp_path)

    try:
        result = ingest_csv(tmp_path)
    finally:
        os.remove(tmp_path)

    return jsonify(result), 200


# ── POST /api/logs/upload/jsonl ───────────────────────────────────
@app.route("/api/logs/upload/jsonl", methods=["POST"])
def upload_jsonl():
    """Accept a JSONL file upload and trigger batch ingestion."""
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    f = request.files["file"]
    if not f.filename.endswith((".json", ".jsonl")):
        return jsonify({"error": "Only .json / .jsonl files are accepted"}), 400

    tmp_path = f"/tmp/{uuid.uuid4()}.jsonl"
    f.save(tmp_path)

    try:
        result = ingest_jsonl(tmp_path)
    finally:
        os.remove(tmp_path)

    return jsonify(result), 200


# ─────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("[CCT] Database tables created.")
        print("[CCT] Log Ingestion API running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
