# Cyber Control Tower (CCT)

**AI-driven cybersecurity simulation & SOC visualization platform**

Cyber Control Tower simulates a real Security Operations Center (SOC). It
turns raw security logs into structured events, correlates those events
into incidents and attack stories, maps them to the MITRE ATT&CK
framework, scores user behavior with a Trust Score engine, tracks
detection/response performance (MTTD/MTTR), and visualizes the
organization as a graph-based Cyber Digital Twin — all through a single
Flask backend and a role-aware dashboard frontend.

---

## What's in this repo

```
cct/
├── backend/
│   ├── app.py                  Flask app — routes, auth, role gating
│   ├── auth/
│   │   ├── users.py            User directory (2 demo accounts) + password hashing
│   │   ├── permissions.py      Role → capability map
│   │   └── audit.py            In-memory audit log
│   ├── ingestion/loader.py     Loads & normalizes the raw CSV into Events
│   ├── correlation/engine.py   Groups events into Incidents, builds attack chains
│   ├── mitre/                  Maps attack types/stages to MITRE ATT&CK techniques
│   ├── trust_score/engine.py   Behavior-based per-user risk scoring
│   ├── metrics/engine.py       MTTD/MTTR aggregation & reporting
│   ├── graph/twin.py           Builds the Cyber Digital Twin graph
│   ├── search/engine.py        Threat-hunting query engine
│   ├── api/live_feed.py        Simulated live event feed
│   ├── data/                   Source dataset (cybersecurity_example.csv)
│   ├── test_api.py             Smoke test suite for every endpoint
│   └── requirements.txt
├── frontend/
│   └── index.html              Single-file dashboard (HTML/CSS/vanilla JS)
├── notebooks/                  Dataset preprocessing notebooks
└── run.sh / run.bat            Convenience launch scripts
```

The backend and frontend are one app: Flask serves `frontend/index.html`
directly, and the page talks to the API on the same origin.

---

## Running it

```bash
cd backend
pip install -r requirements.txt
python3 app.py
```

Then open **http://127.0.0.1:5000**. `run.sh` (macOS/Linux) and
`run.bat` (Windows) do the same thing.

### Demo accounts

| Role | Username | Password |
|---|---|---|
| Security Analyst | `analyst` | `analyst123` |
| SOC Manager | `manager` | `manager123` |

These are also shown on the login screen itself (fetched live from
`GET /api/auth/demo-accounts`, not hard-coded in the page).

---

## Roles & access

Every `/api/*` route requires a logged-in session. Two roles exist,
matching the project's own stakeholder analysis:

- **Security Analyst** — day-to-day triage: view incidents, change an
  incident's workflow status, search/hunt, view the MITRE heatmap and
  the Digital Twin graph, view the audit trail.
- **SOC Manager** — everything an analyst can do, **plus** the Trust
  Score leaderboard and MTTD/MTTR performance metrics.

Role checks are enforced server-side (`@role_required(...)` in
`app.py`, backed by `auth/permissions.py`) — the frontend hides
manager-only nav items behind a lock icon for analysts, but the real
protection is the 403 the API returns if that boundary is ever
bypassed.

---

## API reference

All endpoints return JSON. All routes below except `/api/auth/*`
require a session cookie from a successful login.

**Auth**
```
POST /api/auth/login            { username, password } -> { user, permissions }
POST /api/auth/logout
GET  /api/auth/me               -> current session's user + permissions
GET  /api/auth/demo-accounts    -> non-secret demo credentials for the login screen
```

**Incidents**
```
GET  /api/incidents             ?severity=&risk_min=&attack_type=&status=
GET  /api/incidents/<id>
GET  /api/incidents/chains      multi-stage attack chains only
GET  /api/incidents/statuses    valid workflow states
POST /api/incidents/<id>/status { status } -> moves an incident through
                                  Open -> Investigating -> Contained -> Resolved
```

**Intelligence layers**
```
GET  /api/events                 raw normalized events
GET  /api/mitre/heatmap          technique frequency across all incidents
GET  /api/mitre/catalog          full attack-type -> technique mapping
GET  /api/graph                  Cyber Digital Twin (Cytoscape-style nodes/edges)
GET  /api/risk-summary           risk distribution + top-risk incidents
GET  /api/summary                dashboard overview (counts, breakdowns)
GET  /api/live-feed              ?cursor=&page_size=  simulated streaming feed
```

**Manager-only**
```
GET  /api/trust-scores           ?order=ascending|descending
GET  /api/trust-scores/<user>
GET  /api/metrics                full MTTD/MTTR report
```

**Search & audit**
```
GET  /api/search                 ?q=  real query engine, see below
GET  /api/search/suggested       ready-made hunt queries
GET  /api/audit                  ?limit=  server-recorded actions this session
```

### Search query syntax

`GET /api/search?q=...` supports field filters and free text, AND-ed
together:

```
severity:Critical
status:Open
segment:"Segment A"        quote multi-word values
attack:DDoS
user:Riya
ip:45.34.98.137
technique:T1078
risk:>50                   numeric fields support > and <
mttd:<10
```

Anything that isn't `field:value` is treated as free text matched
against user, IPs, attack type, segment, severity, status, and MITRE
technique names/IDs.

---

## Architecture

```
Data Ingestion  ->  Cyber Digital Twin  ->  Correlation Engine  ->  MITRE Mapping
      ->  Trust Score Engine  ->  Detection / Metrics  ->  Auth & Role Gating  ->  Dashboard
```

Everything is derived from `backend/data/cybersecurity_example.csv` at
process start and cached in memory — there's no database. Incident
workflow status (set via `POST /api/incidents/<id>/status`) and the
audit log are the only pieces of state that change after startup, and
both reset when the server restarts, consistent with the rest of the
system being an in-memory simulation rather than a persisted backend.

---

## Notes on the auth design

- Passwords are hashed with PBKDF2-HMAC-SHA256 (200,000 iterations,
  random per-user salt) — never stored or compared in plaintext.
- Sessions are Flask's built-in signed cookies (`SESSION_COOKIE_HTTPONLY`,
  `SameSite=Lax`). No JWTs, no external identity provider — appropriate
  for a two-role demo SOC app, not intended as a production auth system.
- There's no signup flow and no password reset; the two demo accounts
  are the entire user base by design.

## Running the test suite

```bash
cd backend
python3 test_api.py
```

This exercises authentication, role gating (analyst vs manager), the
incident status workflow, search, and every read endpoint, with
backward-compatibility checks against the original v1/v2 incident
shape.
