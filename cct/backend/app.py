"""
Cyber Control Tower — Flask Application
=========================================
Main entry point. Serves the frontend static files and all /api/* routes.

Run with:   python3 app.py
Then open:  http://127.0.0.1:5000
"""
from __future__ import annotations

import json
import os
import sys

# ── Make all sibling packages importable ─────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify, redirect, request, send_from_directory, session

# ── Bootstrap DB / seed data ─────────────────────────────────────────────────
from db.seed import run_all as seed_database
seed_database()

# ── Module imports (after DB is ready) ────────────────────────────────────────
from auth.service import (
    verify_login, current_user, login_required, role_required, create_user
)
from db.schema import get_connection
from ingestion.loader import get_events
from correlation.engine import get_incidents, get_user_threads
from trust_score.engine import get_trust_scores, get_leaderboard
from metrics.engine import full_report, overall_metrics
from graph.twin import graph_to_cytoscape, get_graph
from propagation.engine import simulate_and_persist, get_propagation
from assets.inventory import get_assets, get_asset_incidents, asset_summary
from response.engine import make_response_decision, get_playbooks

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.secret_key = "cct-dev-secret-key-change-in-prod"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log_audit(action: str, resource: str = None, detail: str = None) -> None:
    user = current_user()
    username = user["username"] if user else "system"
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO audit_log (username, action, resource, detail) VALUES (?,?,?,?)",
            (username, action, resource, detail),
        )
        conn.commit()
    finally:
        conn.close()


# ── Static / page routes ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/login")
def login_page():
    return send_from_directory(FRONTEND_DIR, "login.html")

@app.route("/console")
@app.route("/console/<path:section>")
def console_page(section=None):
    return send_from_directory(FRONTEND_DIR, "console.html")

@app.route("/css/<path:filename>")
def css(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "css"), filename)

@app.route("/js/<path:filename>")
def js(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "js"), filename)

@app.route("/assets/<path:filename>")
def static_assets(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "assets"), filename)


# ── Auth API ──────────────────────────────────────────────────────────────────

@app.route("/api/auth/me")
def auth_me():
    user = current_user()
    return jsonify({"user": user})


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    user = verify_login(username, password)
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    _log_audit("LOGIN", "session", f"Logged in as {user['role']}")
    return jsonify({"user": user})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    _log_audit("LOGOUT", "session")
    session.clear()
    return jsonify({"ok": True})


# ── Summary API ───────────────────────────────────────────────────────────────

@app.route("/api/summary")
def api_summary():
    events = get_events()
    incidents = get_incidents()
    metrics = overall_metrics(incidents)
    users = {e.user for e in events}
    return jsonify({
        "total_events": len(events),
        "total_incidents": len(incidents),
        "total_users": len(users),
        "overall_mttd_mttr": {
            "mttd_mean": metrics.mttd_mean,
            "mttr_mean": metrics.mttr_mean,
        },
    })


# ── Events API ────────────────────────────────────────────────────────────────

@app.route("/api/events")
@login_required
def api_events():
    events = get_events()
    return jsonify([
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "user": e.user,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "network_segment": e.network_segment,
            "attack_type": e.attack_type,
            "severity": e.severity,
            "action_taken": e.action_taken,
            "anomaly_score": e.anomaly_score,
        }
        for e in events
    ])


# ── Incidents API ─────────────────────────────────────────────────────────────

@app.route("/api/incidents")
@login_required
def api_incidents():
    status_filter = request.args.get("status")
    conn = get_connection()
    try:
        if status_filter:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status=? ORDER BY occurred_at DESC", (status_filter,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY occurred_at DESC"
            ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/incidents/<incident_id>")
@login_required
def api_incident(incident_id):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "Not found"}), 404
        return jsonify(dict(row))
    finally:
        conn.close()


@app.route("/api/incidents/<incident_id>/history")
@login_required
def api_incident_history(incident_id):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM incident_history WHERE incident_id=? ORDER BY changed_at ASC",
            (incident_id,),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/incidents/<incident_id>/transition", methods=["POST"])
@login_required
def api_transition(incident_id):
    data = request.get_json(force=True) or {}
    to_status = data.get("to_status", "")
    note = data.get("note", "")
    valid = {"Open", "In Progress", "Resolved", "Escalated"}
    if to_status not in valid:
        return jsonify({"error": f"Invalid status. Must be one of {valid}"}), 400

    user = current_user()
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT status FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "Incident not found"}), 404
        from_status = row["status"]
        conn.execute(
            "UPDATE incidents SET status=? WHERE incident_id=?", (to_status, incident_id)
        )
        conn.execute(
            "INSERT INTO incident_history (incident_id, from_status, to_status, changed_by, note) "
            "VALUES (?,?,?,?,?)",
            (incident_id, from_status, to_status, user["username"], note),
        )
        conn.commit()
        _log_audit("TRANSITION", incident_id, f"{from_status} → {to_status}: {note}")
        updated = dict(conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone())
        return jsonify(updated)
    finally:
        conn.close()


@app.route("/api/incidents/<incident_id>/assign", methods=["POST"])
@login_required
def api_assign(incident_id):
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "username required"}), 400

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE incidents SET assigned_to=? WHERE incident_id=?", (username, incident_id)
        )
        conn.commit()
        _log_audit("ASSIGN", incident_id, f"Assigned to {username}")
        updated = dict(conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone())
        return jsonify(updated)
    finally:
        conn.close()


@app.route("/api/incidents/<incident_id>/respond", methods=["POST"])
@login_required
def api_respond(incident_id):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT severity, attack_type FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "Incident not found"}), 404

        user = current_user()
        result = make_response_decision(incident_id, row["severity"], row["attack_type"])
        conn.execute(
            "INSERT INTO responses (incident_id, decision, reasoning, triggered_by) VALUES (?,?,?,?)",
            (incident_id, result["decision"], result["reasoning"], user["username"]),
        )
        conn.commit()
        _log_audit("RESPOND", incident_id, result["decision"])
        return jsonify(result)
    finally:
        conn.close()


@app.route("/api/incidents/<incident_id>/responses")
@login_required
def api_incident_responses(incident_id):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM responses WHERE incident_id=? ORDER BY created_at DESC", (incident_id,)
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/incidents/<incident_id>/propagation")
@login_required
def api_propagation(incident_id):
    result = get_propagation(incident_id)
    return jsonify(result)


@app.route("/api/incidents/<incident_id>/simulate-attack", methods=["POST"])
@role_required("SOC Manager")
def api_simulate_attack(incident_id):
    result = simulate_and_persist(incident_id)
    _log_audit("SIMULATE_ATTACK", incident_id, f"{len(result)} propagation hops")
    return jsonify(result)


# ── Responses API ─────────────────────────────────────────────────────────────

@app.route("/api/responses")
@login_required
def api_all_responses():
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM responses ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


# ── MITRE API ─────────────────────────────────────────────────────────────────

@app.route("/api/mitre/heatmap")
@login_required
def api_mitre_heatmap():
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT mitre_technique, mitre_tactic, COUNT(*) as count, severity "
            "FROM incidents GROUP BY mitre_technique, mitre_tactic, severity"
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/mitre/catalog")
@login_required
def api_mitre_catalog():
    from ingestion.loader import MITRE_MAP, ATTACK_TYPES
    catalog = [
        {"attack_type": at, "technique": MITRE_MAP[at][0], "tactic": MITRE_MAP[at][1]}
        for at in ATTACK_TYPES
    ]
    return jsonify(catalog)


# ── Trust Scores API ──────────────────────────────────────────────────────────

@app.route("/api/trust-scores")
@login_required
def api_trust_scores():
    order = request.args.get("order", "ascending")
    board = get_leaderboard(ascending=(order == "ascending"))
    return jsonify([s.to_dict() for s in board])


@app.route("/api/trust-scores/<username>")
@login_required
def api_trust_score_user(username):
    scores = get_trust_scores()
    if username not in scores:
        return jsonify({"error": "User not found"}), 404
    return jsonify(scores[username].to_dict())


# ── Metrics API ───────────────────────────────────────────────────────────────

@app.route("/api/metrics")
@login_required
def api_metrics():
    return jsonify(full_report())


# ── Graph / Digital Twin API ──────────────────────────────────────────────────

@app.route("/api/graph")
@login_required
def api_graph():
    return jsonify(graph_to_cytoscape())


# ── Live Feed API ─────────────────────────────────────────────────────────────

@app.route("/api/live-feed")
@login_required
def api_live_feed():
    cursor = int(request.args.get("cursor", 0))
    page_size = int(request.args.get("page_size", 1))
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY occurred_at ASC LIMIT ? OFFSET ?",
            (page_size, cursor),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
        return jsonify({
            "events": [dict(r) for r in rows],
            "cursor": cursor + len(rows),
            "total": total,
            "has_more": cursor + len(rows) < total,
        })
    finally:
        conn.close()


# ── Assets API ────────────────────────────────────────────────────────────────

@app.route("/api/assets")
@login_required
def api_assets():
    return jsonify([a.to_dict() for a in get_assets()])


@app.route("/api/assets/summary")
@login_required
def api_assets_summary():
    return jsonify(asset_summary())


@app.route("/api/assets/<ip>/incidents")
@login_required
def api_asset_incidents(ip):
    return jsonify(get_asset_incidents(ip))


# ── Audit Trail API ───────────────────────────────────────────────────────────

@app.route("/api/audit")
@role_required("SOC Manager")
def api_audit():
    limit = int(request.args.get("limit", 200))
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/audit/summary")
@role_required("SOC Manager")
def api_audit_summary():
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
        by_action = conn.execute(
            "SELECT action, COUNT(*) c FROM audit_log GROUP BY action ORDER BY c DESC"
        ).fetchall()
        by_user = conn.execute(
            "SELECT username, COUNT(*) c FROM audit_log GROUP BY username ORDER BY c DESC LIMIT 10"
        ).fetchall()
        return jsonify({
            "total_events": total,
            "by_action": [dict(r) for r in by_action],
            "by_user": [dict(r) for r in by_user],
        })
    finally:
        conn.close()


# ── Threat Hunting API ────────────────────────────────────────────────────────

HUNT_QUERIES = [
    {
        "id": "hq-critical-ignored",
        "name": "Critical Incidents Not Blocked",
        "description": "Find Critical severity incidents where the action was Logged or Ignored — these represent detection gaps.",
        "category": "Detection Gap",
    },
    {
        "id": "hq-repeat-offenders",
        "name": "Repeat Offender Accounts",
        "description": "Users with 5 or more incidents, regardless of severity — indicates persistent or compromised accounts.",
        "category": "Behavioral",
    },
    {
        "id": "hq-lateral-movement",
        "name": "Lateral Movement Chains",
        "description": "Incidents tagged as Lateral Movement or Privilege Escalation within the same network segment.",
        "category": "Attack Chain",
    },
    {
        "id": "hq-high-anomaly",
        "name": "High Anomaly Score Events",
        "description": "Events with anomaly score > 80 that were not blocked — highest risk uncontained events.",
        "category": "Risk",
    },
    {
        "id": "hq-exfil-candidates",
        "name": "Exfiltration Candidates",
        "description": "Data Exfiltration incidents where the action was Logged rather than Blocked.",
        "category": "Data Loss",
    },
]


@app.route("/api/hunting/queries")
@login_required
def api_hunt_queries():
    return jsonify(HUNT_QUERIES)


@app.route("/api/hunting/queries/<query_id>/run", methods=["POST"])
@login_required
def api_run_hunt(query_id):
    user = current_user()
    conn = get_connection()
    try:
        if query_id == "hq-critical-ignored":
            rows = conn.execute(
                "SELECT * FROM incidents WHERE severity='Critical' AND action_taken IN ('Logged','Ignored') ORDER BY occurred_at DESC LIMIT 50"
            ).fetchall()
        elif query_id == "hq-repeat-offenders":
            rows = conn.execute(
                "SELECT user, COUNT(*) c FROM incidents GROUP BY user HAVING c >= 5 ORDER BY c DESC"
            ).fetchall()
        elif query_id == "hq-lateral-movement":
            rows = conn.execute(
                "SELECT * FROM incidents WHERE attack_type IN ('Lateral Movement','Privilege Escalation') ORDER BY network_segment, occurred_at LIMIT 50"
            ).fetchall()
        elif query_id == "hq-high-anomaly":
            rows = conn.execute(
                "SELECT * FROM incidents WHERE anomaly_score > 80 AND action_taken != 'Blocked' ORDER BY anomaly_score DESC LIMIT 50"
            ).fetchall()
        elif query_id == "hq-exfil-candidates":
            rows = conn.execute(
                "SELECT * FROM incidents WHERE attack_type='Data Exfiltration' AND action_taken='Logged' ORDER BY occurred_at DESC LIMIT 50"
            ).fetchall()
        else:
            return jsonify({"error": "Unknown query"}), 404

        result = [dict(r) for r in rows]
        result_json = json.dumps(result)
        conn.execute(
            "INSERT INTO hunt_results (query_id, run_by, result_json) VALUES (?,?,?)",
            (query_id, user["username"], result_json),
        )
        conn.commit()
        _log_audit("HUNT", query_id, f"{len(result)} results")
        return jsonify({"query_id": query_id, "results": result, "count": len(result)})
    finally:
        conn.close()


# ── Response Playbooks API ────────────────────────────────────────────────────

@app.route("/api/playbooks")
@login_required
def api_playbooks():
    return jsonify(get_playbooks())


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  CYBER CONTROL TOWER")
    print("  SOC Simulation Platform")
    print("="*60)
    print(f"\n  Open: http://127.0.0.1:5000\n")
    print("  Demo credentials:")
    print("    Security Analyst  →  analyst / analyst123")
    print("    SOC Manager       →  manager / manager123")
    print("="*60 + "\n")
    app.run(debug=False, port=5000, host="127.0.0.1")
