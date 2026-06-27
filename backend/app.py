"""
Cyber Control Tower — Backend Entry Point
============================================
A single Flask app that:
  1. Serves the static frontend (HTML/CSS/JS) from ../frontend
  2. Exposes a REST API that every module (ingestion, correlation, MITRE,
     trust score, MTTD/MTTR, graph, live feed) plugs into.

Run with:
    python app.py
Then open:
    http://127.0.0.1:5000
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request, send_from_directory

from ingestion.loader import get_events
from correlation.engine import get_incidents, get_user_threads
from mitre.enrichment import enrich_incidents, enrich_incident, mitre_heatmap
from mitre.mapping import ATTACK_TYPE_TO_MITRE
from trust_score.engine import get_leaderboard, get_trust_scores
from metrics.engine import full_report
from graph.twin import get_graph, graph_to_cytoscape
from api.live_feed import get_feed_page

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")


# ----------------------------------------------------------------------------
# Frontend serving — one route per page
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/dashboard")
def dashboard_page():
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.route("/incidents")
def incidents_page():
    return send_from_directory(FRONTEND_DIR, "incidents.html")


# ----------------------------------------------------------------------------
# Raw data
# ----------------------------------------------------------------------------
@app.route("/api/events")
def api_events():
    events = get_events()
    return jsonify([e.to_dict() for e in events])


# ----------------------------------------------------------------------------
# Incidents (correlated + MITRE-enriched)
# ----------------------------------------------------------------------------
@app.route("/api/incidents")
def api_incidents():
    incidents = get_incidents()
    return jsonify(enrich_incidents(incidents))


@app.route("/api/incidents/<incident_id>")
def api_incident_detail(incident_id: str):
    incidents = get_incidents()
    match = next((i for i in incidents if i.incident_id == incident_id), None)
    if not match:
        return jsonify({"error": "not found"}), 404
    return jsonify(enrich_incident(match))


# ----------------------------------------------------------------------------
# MITRE ATT&CK
# ----------------------------------------------------------------------------
@app.route("/api/mitre/heatmap")
def api_mitre_heatmap():
    return jsonify(mitre_heatmap())


@app.route("/api/mitre/catalog")
def api_mitre_catalog():
    catalog = {
        attack_type: [
            {"technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic}
            for t in techs
        ]
        for attack_type, techs in ATTACK_TYPE_TO_MITRE.items()
    }
    return jsonify(catalog)


# ----------------------------------------------------------------------------
# Trust Score
# ----------------------------------------------------------------------------
@app.route("/api/trust-scores")
def api_trust_scores():
    ascending = request.args.get("order", "ascending") == "ascending"
    board = get_leaderboard(ascending=ascending)
    return jsonify([s.to_dict() for s in board])


@app.route("/api/trust-scores/<user>")
def api_trust_score_user(user: str):
    scores = get_trust_scores()
    match = scores.get(user)
    if not match:
        return jsonify({"error": "user not found"}), 404
    return jsonify(match.to_dict())


# ----------------------------------------------------------------------------
# MTTD / MTTR metrics
# ----------------------------------------------------------------------------
@app.route("/api/metrics")
def api_metrics():
    return jsonify(full_report())


# ----------------------------------------------------------------------------
# Cyber Digital Twin (graph)
# ----------------------------------------------------------------------------
@app.route("/api/graph")
def api_graph():
    return jsonify(graph_to_cytoscape(get_graph()))


# ----------------------------------------------------------------------------
# Live feed simulator
# ----------------------------------------------------------------------------
@app.route("/api/live-feed")
def api_live_feed():
    cursor = int(request.args.get("cursor", 0))
    page_size = int(request.args.get("page_size", 1))
    return jsonify(get_feed_page(cursor=cursor, page_size=page_size))


# ----------------------------------------------------------------------------
# Summary / dashboard overview (one-call convenience endpoint)
# ----------------------------------------------------------------------------
@app.route("/api/summary")
def api_summary():
    events = get_events()
    incidents = get_incidents()
    threads = get_user_threads(incidents)
    board = get_leaderboard(ascending=True)
    report = full_report(incidents)

    severity_counts: dict[str, int] = {}
    for inc in incidents:
        severity_counts[inc.severity] = severity_counts.get(inc.severity, 0) + 1

    attack_counts: dict[str, int] = {}
    for inc in incidents:
        attack_counts[inc.attack_type] = attack_counts.get(inc.attack_type, 0) + 1

    return jsonify(
        {
            "total_events": len(events),
            "total_incidents": len(incidents),
            "total_users": len(threads),
            "repeat_offenders": sum(1 for v in threads.values() if len(v) > 1),
            "severity_breakdown": severity_counts,
            "attack_type_breakdown": attack_counts,
            "overall_mttd_mttr": report["overall"],
            "riskiest_users": [s.to_dict() for s in board[:5]],
            "most_trusted_users": [s.to_dict() for s in board[-5:]][::-1],
        }
    )


if __name__ == "__main__":
    print("Cyber Control Tower backend starting...")
    print(f"Frontend served from: {FRONTEND_DIR}")
    app.run(debug=True, port=5000)
