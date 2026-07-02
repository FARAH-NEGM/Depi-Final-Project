"""
Cyber Control Tower — Backend Entry Point  v4
==============================================
Changes vs v3:
- page_login_required: /dashboard and /incidents now redirect to / when
  the user has no active session. Previously any visitor could open these
  URLs directly and get a broken dashboard (the API would 401 but the
  HTML still loaded).
- POST /api/auth/register: sign-up endpoint with full server-side
  validation. Returns the same shape as /api/auth/login so the frontend
  can auto-login the user immediately after account creation.
"""

from __future__ import annotations

import os
import secrets
from functools import wraps

from flask import Flask, jsonify, redirect, request, send_from_directory, session

from ingestion.loader import get_events
from correlation.engine import (
    get_incidents, get_user_threads, update_incident_status, VALID_STATUSES,
    correlation_stats,
)
from mitre.enrichment import enrich_incidents, enrich_incident, mitre_heatmap
from mitre.mapping import ATTACK_TYPE_TO_MITRE
from trust_score.engine import get_leaderboard, get_trust_scores
from metrics.engine import full_report
from graph.twin import get_graph, graph_to_cytoscape
from api.live_feed import get_feed_page
from search.engine import search_incidents, SUGGESTED_HUNTS

from auth.users import authenticate, get_user, list_demo_accounts, register
from auth.permissions import permissions_for, can
from auth.audit import record as record_audit, get_log as get_audit_log

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

app.secret_key = os.environ.get("CCT_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def current_user():
    username = session.get("username")
    if not username:
        return None
    return get_user(username)


def login_required(view):
    """Protects API routes — returns 401 JSON when not logged in."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "authentication required"}), 401
        return view(*args, **kwargs)
    return wrapped


def page_login_required(view):
    """
    Protects HTML page routes — redirects to / (login screen) when not
    logged in.  Different from login_required because a browser cannot
    do anything useful with a 401 JSON response when loading a page.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect("/")
        return view(*args, **kwargs)
    return wrapped


def role_required(capability: str):
    """Gate a route on a named capability (see auth/permissions.py)."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"error": "authentication required"}), 401
            if not can(user.role, capability):
                return jsonify({
                    "error":   "forbidden",
                    "message": f"This requires a capability your role ({user.role}) does not have.",
                }), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# Frontend serving
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    # Root is the login/sign-up screen — no auth check here.
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/dashboard")
@page_login_required
def dashboard_page():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/incidents")
@page_login_required
def incidents_page():
    return send_from_directory(FRONTEND_DIR, "index.html")


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    body     = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password =  body.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    user = authenticate(username, password)
    if not user:
        return jsonify({"error": "Invalid username or password."}), 401

    session.clear()
    session["username"] = user.username
    session.permanent   = True

    record_audit(user.username, user.to_public_dict()["role_label"],
                 "Signed in", target=user.username)

    return jsonify({
        "user":        user.to_public_dict(),
        "permissions": permissions_for(user.role),
    })


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    """
    Create a new account, then immediately sign the user in.
    Returns the same JSON shape as /api/auth/login.

    Expected body:
    {
        "username":     "john",
        "display_name": "John Smith",   ← optional
        "role":         "analyst",      ← "analyst" | "manager"
        "password":     "secret123"
    }
    """
    body         = request.get_json(silent=True) or {}
    username     = (body.get("username")     or "").strip()
    display_name = (body.get("display_name") or "").strip()
    role         = (body.get("role")         or "").strip()
    password     =  body.get("password")     or ""

    user, error = register(username, display_name, role, password)
    if error:
        status = 409 if "already exists" in error else 400
        return jsonify({"error": error}), status

    # Auto sign-in after successful registration
    session.clear()
    session["username"] = user.username
    session.permanent   = True

    record_audit(user.username, user.to_public_dict()["role_label"],
                 "Registered and signed in", target=user.username)

    return jsonify({
        "user":        user.to_public_dict(),
        "permissions": permissions_for(user.role),
    }), 201


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    user = current_user()
    if user:
        record_audit(user.username, user.to_public_dict()["role_label"],
                     "Signed out", target=user.username)
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/auth/me")
def api_me():
    user = current_user()
    if not user:
        return jsonify({"user": None}), 200
    return jsonify({
        "user":        user.to_public_dict(),
        "permissions": permissions_for(user.role),
    })


@app.route("/api/auth/demo-accounts")
def api_demo_accounts():
    return jsonify(list_demo_accounts())


# ---------------------------------------------------------------------------
# Raw data
# ---------------------------------------------------------------------------
@app.route("/api/events")
@login_required
def api_events():
    events = get_events()
    return jsonify([e.to_dict() for e in events])


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
@app.route("/api/incidents")
@login_required
def api_incidents():
    incidents = get_incidents()
    enriched  = enrich_incidents(incidents)

    severity    = request.args.get("severity")
    risk_min    = request.args.get("risk_min", type=float)
    attack_type = request.args.get("attack_type")
    status      = request.args.get("status")

    if severity:
        enriched = [i for i in enriched if i.get("severity") == severity]
    if risk_min is not None:
        enriched = [i for i in enriched if i.get("risk_score", 0) >= risk_min]
    if attack_type:
        enriched = [i for i in enriched if i.get("attack_type") == attack_type]
    if status:
        enriched = [i for i in enriched if i.get("status") == status]

    return jsonify(enriched)


@app.route("/api/incidents/<incident_id>")
@login_required
def api_incident_detail(incident_id: str):
    incidents = get_incidents()
    match = next((i for i in incidents if i.incident_id == incident_id), None)
    if not match:
        return jsonify({"error": "not found"}), 404
    return jsonify(enrich_incident(match))


@app.route("/api/incidents/chains")
@login_required
def api_incident_chains():
    incidents = get_incidents()
    chains    = [i for i in incidents if i.chain_confidence > 0.4 or i.event_count > 1]
    return jsonify(enrich_incidents(chains))


@app.route("/api/incidents/<incident_id>/status", methods=["POST"])
@login_required
def api_incident_status(incident_id: str):
    user       = current_user()
    body       = request.get_json(silent=True) or {}
    new_status = (body.get("status") or "").strip()

    if new_status not in VALID_STATUSES:
        return jsonify({"error": "invalid status", "valid_statuses": VALID_STATUSES}), 400

    updated = update_incident_status(incident_id, new_status)
    if not updated:
        return jsonify({"error": "not found"}), 404

    record_audit(user.username, user.to_public_dict()["role_label"],
                 "Changed incident status", target=incident_id,
                 detail=f"-> {new_status}")

    return jsonify(enrich_incident(updated))


@app.route("/api/incidents/statuses")
@login_required
def api_incident_statuses():
    return jsonify(VALID_STATUSES)


# ---------------------------------------------------------------------------
# NEW v4: correlation transparency — why N events became M incidents
# ---------------------------------------------------------------------------
@app.route("/api/correlation-stats")
@login_required
def api_correlation_stats():
    return jsonify(correlation_stats())


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------
@app.route("/api/mitre/heatmap")
@login_required
def api_mitre_heatmap():
    return jsonify(mitre_heatmap())


@app.route("/api/mitre/catalog")
@login_required
def api_mitre_catalog():
    catalog = {
        attack_type: [
            {
                "technique_id":     t.technique_id,
                "technique_name":   t.technique_name,
                "tactic":           t.tactic,
                "sub_technique":    t.sub_technique,
                "confidence_score": t.confidence_score,
            }
            for t in techs
        ]
        for attack_type, techs in ATTACK_TYPE_TO_MITRE.items()
    }
    return jsonify(catalog)


# ---------------------------------------------------------------------------
# Trust Score — SOC Manager only
# ---------------------------------------------------------------------------
@app.route("/api/trust-scores")
@role_required("view_trust_scores")
def api_trust_scores():
    ascending = request.args.get("order", "ascending") == "ascending"
    board = get_leaderboard(ascending=ascending)
    return jsonify([s.to_dict() for s in board])


@app.route("/api/trust-scores/<user>")
@role_required("view_trust_scores")
def api_trust_score_user(user: str):
    scores = get_trust_scores()
    match  = scores.get(user)
    if not match:
        return jsonify({"error": "user not found"}), 404
    return jsonify(match.to_dict())


# ---------------------------------------------------------------------------
# Metrics — SOC Manager only
# ---------------------------------------------------------------------------
@app.route("/api/metrics")
@role_required("view_metrics")
def api_metrics():
    return jsonify(full_report())


# ---------------------------------------------------------------------------
# NEW v4: System Health — implementation detail moved out of the analyst
# dashboard and behind a manager-only capability (Admin / System Health).
# ---------------------------------------------------------------------------
@app.route("/api/system-health")
@role_required("view_system_health")
def api_system_health():
    events = get_events()
    incidents = get_incidents()
    return jsonify({
        "modules": [
            {"name": "Ingestion layer",    "status": "Online", "detail": f"{len(events)} events"},
            {"name": "Correlation engine", "status": "Online", "detail": f"{len(incidents)} incidents"},
            {"name": "MITRE mapping",      "status": "Online", "detail": "dynamic per-event"},
            {"name": "Trust Score engine", "status": "Online", "detail": f"{len(get_leaderboard())} users scored"},
        ],
        "api_endpoints": [
            "GET /api/summary", "GET /api/incidents", "GET /api/incidents/<id>",
            "POST /api/incidents/<id>/status", "GET /api/mitre/heatmap",
            "GET /api/trust-scores", "GET /api/metrics", "GET /api/graph",
            "GET /api/live-feed", "GET /api/search", "GET /api/audit",
            "GET /api/correlation-stats",
        ],
    })


# ---------------------------------------------------------------------------
# Cyber Digital Twin
# ---------------------------------------------------------------------------
@app.route("/api/graph")
@login_required
def api_graph():
    return jsonify(graph_to_cytoscape(get_graph()))


# ---------------------------------------------------------------------------
# Live feed
# ---------------------------------------------------------------------------
@app.route("/api/live-feed")
@login_required
def api_live_feed():
    cursor    = int(request.args.get("cursor", 0))
    page_size = int(request.args.get("page_size", 1))
    return jsonify(get_feed_page(cursor=cursor, page_size=page_size))


# ---------------------------------------------------------------------------
# Threat hunting / search
# ---------------------------------------------------------------------------
@app.route("/api/search")
@login_required
def api_search():
    user    = current_user()
    query   = request.args.get("q", "")
    results = search_incidents(query)

    if query:
        record_audit(user.username, user.to_public_dict()["role_label"],
                     "Ran threat hunt query", target=query,
                     detail=f"{len(results)} match(es)")

    return jsonify({"query": query, "count": len(results), "results": results})


@app.route("/api/search/suggested")
@login_required
def api_search_suggested():
    return jsonify(SUGGESTED_HUNTS)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------
@app.route("/api/audit")
@login_required
def api_audit():
    limit = request.args.get("limit", type=int)
    return jsonify(get_audit_log(limit=limit))


# ---------------------------------------------------------------------------
# Risk summary
# ---------------------------------------------------------------------------
@app.route("/api/risk-summary")
@login_required
def api_risk_summary():
    incidents = get_incidents()
    dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for i in incidents:
        dist[i.risk_level] = dist.get(i.risk_level, 0) + 1

    top = sorted(incidents, key=lambda i: i.risk_score, reverse=True)[:10]
    return jsonify({
        "risk_distribution":  dist,
        "top_risk_incidents": enrich_incidents(top),
        "avg_risk_score":     round(sum(i.risk_score for i in incidents) / len(incidents), 2)
                              if incidents else 0,
    })


# ---------------------------------------------------------------------------
# Dashboard summary
# ---------------------------------------------------------------------------
@app.route("/api/summary")
@login_required
def api_summary():
    events    = get_events()
    incidents = get_incidents()
    threads   = get_user_threads(incidents)
    report    = full_report(incidents)

    severity_counts: dict[str, int] = {}
    attack_counts:   dict[str, int] = {}
    risk_counts:     dict[str, int] = {}
    status_counts:   dict[str, int] = {}

    for inc in incidents:
        severity_counts[inc.severity]  = severity_counts.get(inc.severity, 0) + 1
        attack_counts[inc.attack_type] = attack_counts.get(inc.attack_type, 0) + 1
        risk_counts[inc.risk_level]    = risk_counts.get(inc.risk_level, 0) + 1
        status_counts[inc.status]      = status_counts.get(inc.status, 0) + 1

    multi_event = sum(1 for i in incidents if i.event_count > 1)
    chains      = sum(1 for i in incidents if i.chain_confidence > 0.5)

    critical_incidents = sum(1 for i in incidents if i.risk_level == "Critical")
    assets_affected = len({i.asset_id for i in incidents})
    users_affected  = len({u for i in incidents for u in i.affected_users})
    sla_breaches = sum(
        1 for i in incidents
        if i.detection_sla_breached or i.response_sla_breached or i.containment_sla_breached
    )

    payload = {
        "total_events":          len(events),
        "total_incidents":       len(incidents),
        "total_users":           len(threads),
        "repeat_offenders":      sum(1 for v in threads.values() if len(v) > 1),
        "multi_event_incidents": multi_event,
        "attack_chain_count":    chains,
        "severity_breakdown":    severity_counts,
        "attack_type_breakdown": attack_counts,
        "risk_level_breakdown":  risk_counts,
        "status_breakdown":      status_counts,
        "overall_mttd_mttr":     report["overall"],
        "critical_incidents":    critical_incidents,
        "assets_affected":       assets_affected,
        "users_affected":        users_affected,
        "sla_breaches":          sla_breaches,
    }

    user = current_user()
    if user and can(user.role, "view_trust_scores"):
        board = get_leaderboard(ascending=True)
        payload["riskiest_users"]     = [s.to_dict() for s in board[:5]]
        payload["most_trusted_users"] = [s.to_dict() for s in board[-5:]][::-1]

    return jsonify(payload)


if __name__ == "__main__":
    print("Cyber Control Tower backend starting (v4 — auth + sign-up)...")
    print(f"Frontend served from: {FRONTEND_DIR}")
    print("Demo accounts: analyst/analyst123 | manager/manager123")
    app.run(debug=True, port=5000)
