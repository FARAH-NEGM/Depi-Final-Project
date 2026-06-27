"""
Cyber Control Tower — Backend Entry Point  v2
==============================================
Changes vs v1:
- All incident-related endpoints now return the full enriched payload
  including: attack_chain, risk_score, mitre_chain, related_events,
  chain_confidence, correlation_reason, tactic_chain, mitre_techniques
  with sub_technique + confidence_score.
- New endpoint: /api/incidents/chains  — returns only multi-event /
  high-confidence attack chain incidents.
- New endpoint: /api/risk-summary  — risk score distribution + top risks.
- All existing endpoints preserved with 100% backward compatibility.
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


# ---------------------------------------------------------------------------
# Frontend serving
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/dashboard")
def dashboard_page():
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.route("/incidents")
def incidents_page():
    return send_from_directory(FRONTEND_DIR, "incidents.html")


# ---------------------------------------------------------------------------
# Raw data
# ---------------------------------------------------------------------------
@app.route("/api/events")
def api_events():
    events = get_events()
    return jsonify([e.to_dict() for e in events])


# ---------------------------------------------------------------------------
# Incidents (correlated + MITRE-enriched)  — backward compatible + new fields
# ---------------------------------------------------------------------------
@app.route("/api/incidents")
def api_incidents():
    incidents = get_incidents()
    enriched  = enrich_incidents(incidents)

    # Optional query filters
    severity    = request.args.get("severity")
    risk_min    = request.args.get("risk_min", type=float)
    attack_type = request.args.get("attack_type")

    if severity:
        enriched = [i for i in enriched if i.get("severity") == severity]
    if risk_min is not None:
        enriched = [i for i in enriched if i.get("risk_score", 0) >= risk_min]
    if attack_type:
        enriched = [i for i in enriched if i.get("attack_type") == attack_type]

    return jsonify(enriched)


@app.route("/api/incidents/<incident_id>")
def api_incident_detail(incident_id: str):
    incidents = get_incidents()
    match = next((i for i in incidents if i.incident_id == incident_id), None)
    if not match:
        return jsonify({"error": "not found"}), 404
    return jsonify(enrich_incident(match))


# NEW: attack chain incidents only
@app.route("/api/incidents/chains")
def api_incident_chains():
    """Returns incidents with multi-stage attack chains (confidence > 0.4)."""
    incidents = get_incidents()
    chains    = [i for i in incidents if i.chain_confidence > 0.4 or i.event_count > 1]
    return jsonify(enrich_incidents(chains))


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------
@app.route("/api/mitre/heatmap")
def api_mitre_heatmap():
    return jsonify(mitre_heatmap())


@app.route("/api/mitre/catalog")
def api_mitre_catalog():
    catalog = {
        attack_type: [
            {
                "technique_id":    t.technique_id,
                "technique_name":  t.technique_name,
                "tactic":          t.tactic,
                "sub_technique":   t.sub_technique,
                "confidence_score": t.confidence_score,
            }
            for t in techs
        ]
        for attack_type, techs in ATTACK_TYPE_TO_MITRE.items()
    }
    return jsonify(catalog)


# ---------------------------------------------------------------------------
# Trust Score
# ---------------------------------------------------------------------------
@app.route("/api/trust-scores")
def api_trust_scores():
    ascending = request.args.get("order", "ascending") == "ascending"
    board = get_leaderboard(ascending=ascending)
    return jsonify([s.to_dict() for s in board])


@app.route("/api/trust-scores/<user>")
def api_trust_score_user(user: str):
    scores = get_trust_scores()
    match  = scores.get(user)
    if not match:
        return jsonify({"error": "user not found"}), 404
    return jsonify(match.to_dict())


# ---------------------------------------------------------------------------
# MTTD / MTTR metrics
# ---------------------------------------------------------------------------
@app.route("/api/metrics")
def api_metrics():
    return jsonify(full_report())


# ---------------------------------------------------------------------------
# Cyber Digital Twin (graph)
# ---------------------------------------------------------------------------
@app.route("/api/graph")
def api_graph():
    return jsonify(graph_to_cytoscape(get_graph()))


# ---------------------------------------------------------------------------
# Live feed simulator
# ---------------------------------------------------------------------------
@app.route("/api/live-feed")
def api_live_feed():
    cursor    = int(request.args.get("cursor", 0))
    page_size = int(request.args.get("page_size", 1))
    return jsonify(get_feed_page(cursor=cursor, page_size=page_size))


# ---------------------------------------------------------------------------
# NEW: Risk summary
# ---------------------------------------------------------------------------
@app.route("/api/risk-summary")
def api_risk_summary():
    incidents = get_incidents()
    dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for i in incidents:
        dist[i.risk_level] = dist.get(i.risk_level, 0) + 1

    top = sorted(incidents, key=lambda i: i.risk_score, reverse=True)[:10]
    return jsonify({
        "risk_distribution": dist,
        "top_risk_incidents": enrich_incidents(top),
        "avg_risk_score":     round(sum(i.risk_score for i in incidents) / len(incidents), 2) if incidents else 0,
    })


# ---------------------------------------------------------------------------
# Summary / dashboard overview
# ---------------------------------------------------------------------------
@app.route("/api/summary")
def api_summary():
    events    = get_events()
    incidents = get_incidents()
    threads   = get_user_threads(incidents)
    board     = get_leaderboard(ascending=True)
    report    = full_report(incidents)

    severity_counts: dict[str, int] = {}
    attack_counts:   dict[str, int] = {}
    risk_counts:     dict[str, int] = {}

    for inc in incidents:
        severity_counts[inc.severity]   = severity_counts.get(inc.severity, 0) + 1
        attack_counts[inc.attack_type]  = attack_counts.get(inc.attack_type, 0) + 1
        risk_counts[inc.risk_level]     = risk_counts.get(inc.risk_level, 0) + 1

    multi_event = sum(1 for i in incidents if i.event_count > 1)
    chains      = sum(1 for i in incidents if i.chain_confidence > 0.5)

    return jsonify({
        "total_events":         len(events),
        "total_incidents":      len(incidents),
        "total_users":          len(threads),
        "repeat_offenders":     sum(1 for v in threads.values() if len(v) > 1),
        "multi_event_incidents": multi_event,
        "attack_chain_count":   chains,
        "severity_breakdown":   severity_counts,
        "attack_type_breakdown": attack_counts,
        "risk_level_breakdown": risk_counts,
        "overall_mttd_mttr":    report["overall"],
        "riskiest_users":       [s.to_dict() for s in board[:5]],
        "most_trusted_users":   [s.to_dict() for s in board[-5:]][::-1],
    })


if __name__ == "__main__":
    print("Cyber Control Tower backend starting (v2)...")
    print(f"Frontend served from: {FRONTEND_DIR}")
    app.run(debug=True, port=5000)
