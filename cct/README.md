# Cyber Control Tower (CCT)

A working, end-to-end implementation of the Cyber Control Tower project: a
simulated Security Operations Center (SOC) that ingests security event logs,
persists them to a real database, correlates them into incidents with a
genuine state machine (New → Under Analysis → Confirmed → Resolved), maps
them to MITRE ATT&CK, scores user behavioral risk (Trust Score), runs a
rule-based Response Engine, simulates lateral-movement attack propagation
over a Cyber Digital Twin, hunts threats with real predicate queries, tracks
a real asset inventory, and keeps an org-wide audit trail — all behind real
login/authentication, with the Security Analyst and SOC Manager roles seeing
genuinely different sections of a 7-section console, not just a different
button.

This README documents the actual running system. See `pdf.md` / the
original `README.md` for the academic project proposal this implements.

---

## 1. Quick start

**Windows** (Command Prompt or double-click):

```
cd cct
run.bat
```

Or just double-click `run.bat` in File Explorer.

**macOS / Linux:**

```bash
cd cct
./run.sh
```

Then open **http://127.0.0.1:5000** in your browser once the terminal says
`Running on http://127.0.0.1:5000`. On first run, the database is created
and seeded automatically from the CSV, and two demo accounts are printed to
the console:

```
Security Analyst -> username: analyst  password: analyst123
SOC Manager      -> username: manager  password: manager123
```

You can also create your own account from the login page.

> **Windows note:** `run.sh` will NOT work from Command Prompt or
> PowerShell directly — `.sh` files aren't natively executable on Windows,
> and depending on your file associations, double-clicking or typing
> `run.sh` may open it in an editor instead of running it. Use `run.bat`
> on Windows. (`run.sh` still works fine inside Git Bash or WSL if you
> prefer that environment.)

Both scripts create a virtual environment, install dependencies, and start
the Flask server, which serves both the API and the dashboard frontend from
a single process — there's nothing else to run.

If you'd rather do it manually:

```bash
cd cct/backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate.bat
pip install -r requirements.txt
python3 app.py                    # Windows: python app.py
```

The database (`backend/db/cct.db`, SQLite — a single file, no server
process needed) is created and seeded automatically the first time you run
the app. To start over with a clean database, delete `backend/db/cct.db`
and restart the server.

---

## 2. Architecture

```
backend/data/cybersecurity_example.csv
        │
        ▼
ingestion/loader.py        →  normalizes raw CSV rows into a unified Event schema
        │
        ▼
correlation/engine.py      →  turns Events into Incidents (synthesized
                               detected_at; thread_id per user)
        │
        ▼
db/seed.py                 →  persists Events + derived Devices/Servers +
                               Incidents into SQLite (db/cct.db), once
        │
        ├──────────┬──────────┬───────────┬──────────┬──────────┬──────────┐
        ▼          ▼          ▼           ▼          ▼          ▼          ▼
correlation/  response/  propagation/  mitre/    trust_score/ assets/    audit/
state_        engine.py  engine.py     mapping/  engine.py    inventory  trail.py
machine.py    (rule-      (lateral-     enrich-   (behavioral  .py        (org-wide
(New→...→      based      movement      ment      risk          (real     history)
Resolved,      contain-    blast        (ATT&CK   scoring)       device/
real MTTR)     ment)       radius)      lookup)                  server)
        │          │          │           │          │            │          │
        └──────────┴──────────┴───────────┴──────────┴────────────┴──────────┘
                                      │
                          hunting/queries.py (real predicate
                          queries over ingested events)
                                      │
                                      ▼
                          auth/service.py (login/session, 2 roles)
                                      │
                                      ▼
                              api/  +  app.py   (Flask REST API)
                                      │
                                      ▼
                    frontend/ (HTML/CSS/vanilla JS)
                    - index.html    → landing page
                    - login.html    → sign in
                    - console.html  → 7-section sidebar console (role-based nav)
                    - Cytoscape.js  → Cyber Digital Twin graph
                    - Chart.js      → MTTD/MTTR charts
```

Every module is independently testable (`python3 -m <module>.<file>` runs
its own demo/sanity-check block) and the API layer (`app.py`) is the only
place that wires them together — so any one piece can be extended without
touching the others.

### Module-by-module

| Module | File | Responsibility |
|---|---|---|
| Ingestion | `backend/ingestion/loader.py` | Loads `cybersecurity_example.csv`, normalizes every row into an `Event` dataclass (consistent field names/types for everything downstream). |
| Database | `backend/db/schema.py`, `seed.py` | SQLite schema (USER/DEVICE/SERVER/EVENT/INCIDENT + history/responses/propagations) matching the project's ER diagram; seeds once from the CSV pipeline on first run. |
| Correlation | `backend/correlation/engine.py` | Converts Events into Incidents; synthesizes a realistic `detected_at` timestamp (severity drives detection speed); links incidents from the same user into a "thread" for behavioral analysis. |
| Incident State Machine | `backend/correlation/state_machine.py` | Enforces New → Under Analysis → Confirmed → Resolved (with Re-assign and Escalate transitions), persists every transition to an audit trail, and computes a *real* MTTR from the actual elapsed time of the analyst's session. |
| Response Engine | `backend/response/engine.py` | Rule-based playbook engine: evaluates each Confirmed incident's severity, attack type, and the subject's Trust Score, and decides a containment action (isolate host, block IP, disable account, etc.) with a written rationale. Only fires on Confirmed incidents. |
| Attack Propagation Engine | `backend/propagation/engine.py` | Simulates lateral movement / blast radius from an incident's origin node, walking outward through the real Cyber Digital Twin graph with probabilistic decay per hop. Deterministic per incident (same incident → same simulated blast radius on repeat runs). |
| Authentication | `backend/auth/service.py` | Login/session system (Flask signed-cookie sessions + werkzeug password hashing). Two roles — Security Analyst and SOC Manager — matching the Use Case Diagram; "Simulate Attack" is gated to SOC Manager only. |
| MITRE Mapping | `backend/mitre/mapping.py`, `enrichment.py` | Maps each incident's `Attack Type` to real MITRE ATT&CK technique IDs/tactics; produces the heatmap data. |
| Trust Score | `backend/trust_score/engine.py` | **Core module.** Computes a 0–100 per-user behavioral risk score from severity history, response quality, anomaly scores, and incident frequency — with time-decay so old incidents matter less. Fully explainable: every score ships with a plain-language breakdown. |
| MTTD/MTTR | `backend/metrics/engine.py` | **Core module.** Aggregates detection/response timing — overall, by severity, by attack type, by segment, by action, and as a monthly trend. |
| Cyber Digital Twin | `backend/graph/twin.py` | Builds a NetworkX graph of IPs, users, and network segments from the event log, exported in Cytoscape.js format with per-node risk coloring. This is also the graph the Attack Propagation Engine walks. |
| Live Feed | `backend/api/live_feed.py` | Powers "Live Mode" — replays incidents in order via a simple cursor-based polling endpoint, looping forever so a demo never runs dry. |
| Asset Inventory | `backend/assets/inventory.py` | Derives a real device/server inventory from the ingested events (one device per user+source-IP pair actually observed, one server per destination IP actually observed), joined with real incident counts and risk. |
| Audit Trail | `backend/audit/trail.py` | Org-wide, chronological feed of every status transition and Response Engine decision across the whole system — the SOC Manager's "what has actually happened" view. |
| Threat Hunting | `backend/hunting/queries.py` | A library of real predicate-based queries evaluated against the ingested event set (e.g. "Critical events with no IDS/IPS alert"). Running the same query twice always returns the same matches, because it's querying real data, not picking from a script. |
| API | `backend/app.py` | Flask app exposing everything above as JSON, and serving the frontend's static files. |
| Frontend | `frontend/` | Vanilla HTML/CSS/JS: a landing page (`/`), login (`/login`), and a single-page sidebar **console** (`/console`) with 7 role-based sections. No build step — just static files served by Flask. |

### Pages

| Route | File | Purpose |
|---|---|---|
| `/` | `index.html` | Landing page — explains the product, shows live KPI numbers pulled from `/api/summary`, and links into login/console. |
| `/login` | `login.html` | Sign in (or use either demo account, one click each). |
| `/console` and `/console/<section>` | `console.html` | The actual product: a sidebar-navigated console with 7 sections (see below), each rendering real data fetched from the API. Client-side routed — switching sections doesn't reload the page. |

### Console sections (role-based)

The sidebar shows a different set of sections depending on who's logged in
— this isn't cosmetic; the backend enforces it too (see the role column).
Sections shown to both roles use the exact same component and data either
way; there's no separate "manager version" of Command Center, for example.

| Section | Module | Roles | What it actually does |
|---|---|---|---|
| Command Center | `js/console/sections/command.js` | Both | KPIs, the live Cyber Digital Twin, top-risk users, most recent incidents. |
| Incident Triage | `js/console/sections/triage.js` | Security Analyst | The full incident table — filter/sort/search, click through to the workflow drawer (transition status, run the Response Engine). |
| Correlation Engine | `js/console/sections/correlation.js` | Both | Explains the real correlation logic in plain language, lists repeat-offender threads, and shows the digital twin. |
| Threat Hunting | `js/console/sections/hunting.js` | Security Analyst | Runs real predicate queries (`backend/hunting/queries.py`) against the ingested event log and shows actual matches. |
| Response Playbooks | `js/console/sections/playbooks.js` | Security Analyst | Documents the Response Engine's actual decision rules, lists Confirmed incidents ready for response, and shows real response history. |
| Assets | `js/console/sections/assets.js` | Both | Real device/server inventory with incident counts and risk, derived from the ingested logs (`backend/assets/inventory.py`). |
| Audit Trail | `js/console/sections/audit.js` | SOC Manager | Org-wide chronological history of every transition and response decision (`backend/audit/trail.py`). |

If you navigate (by URL or by editing the sidebar config) to a section your
role doesn't have access to, the console shows an explicit "Not available
for \<role\>" notice rather than silently failing — and the backend
independently enforces the same restriction on every mutating endpoint
(role-gated routes return 403, not just a hidden button).

---

## 3. Important design decisions (and why)

These are worth knowing before you present or defend the project, because
they were deliberate choices made after actually inspecting the dataset
(see "Data reality" below), not arbitrary ones.

### The dataset has no real incident IDs or detect/respond timestamps
`cybersecurity_example.csv` has one timestamp per row and no
session/incident grouping field. So:
- **Correlation** groups incidents into per-user "threads" rather than by a
  short time window, because every `Source IP Address` in the dataset is
  unique and repeat events from the same user are spread months apart —
  there's no real temporal clustering to detect. This is documented in
  detail in the docstring at the top of `correlation/engine.py`.
- **MTTD/MTTR timestamps are simulated**, derived deterministically from
  each incident's severity (detection speed) and action taken (response
  speed), not recovered from the raw data (which doesn't contain them).
  This is honest simulation, consistent with the project being a SOC
  *simulator* per the original proposal — not a claim of real telemetry.

### Trust Score is explainable, not a black box
Every score comes with a written breakdown (`explanation` field) of exactly
how much each factor (severity, response quality, anomaly score, frequency)
contributed — visible in the dashboard's detail drawer when you click a
user. This matters for a "Trust Score" meant to justify itself to a SOC
analyst.

### Score decay
Incidents are weighted by recency using exponential decay (365-day
half-life) relative to the most recent event in the dataset — so a single
bad incident three years ago doesn't permanently tank someone's score the
same way a bad incident last month would.

### MTTR is now a real measurement, not a second synthetic number
Earlier versions synthesized both MTTD *and* MTTR from severity/action
columns. That double-synthesis was honest but made MTTR meaningless as a
"performance" metric — nothing was actually being timed. Now: MTTD is
still synthesized (a Correlation Engine concern — see above, detection
happens before any human acts), but **MTTR is computed from the real
elapsed wall-clock time between when an incident is Confirmed and when it
is actually marked Resolved** in the running app. Since the dataset's
events are historical (2020–2022) and the demo runs in 2026, the resolution
timestamp is anchored to the incident's own historical timeline rather than
colliding with it — see the docstring in `correlation/state_machine.py` for
the exact mechanism. The practical effect: every incident starts with
`mttr_minutes = null` ("pending resolution") until an analyst actually
resolves it through the UI, and the number that appears afterward reflects
how long that real action actually took.

### The Response Engine only acts on Confirmed incidents, by design
This mirrors the project's own state diagram (New → Under Analysis →
Confirmed → Resolved): a real SOC doesn't auto-contain something that
hasn't been confirmed as a genuine incident, since that's exactly the kind
of false-positive-driven over-blocking that gives automated response
systems a bad reputation. Calling the Response Engine on a New or Under
Analysis incident returns a 409 error rather than silently no-op'ing.

### Attack Propagation is a genuine simulation over real graph structure
The "blast radius" shown for an incident isn't scripted — it's a
probabilistic breadth-first search over the actual Cyber Digital Twin
graph, where each hop's probability decays based on the real edge type
connecting it (a direct observed network flow is weighted as a stronger
lateral-movement path than merely sharing a network segment). Change the
underlying dataset and the propagation paths change with it. Results are
deterministic per incident (seeded RNG) so the same incident always
produces the same simulated blast radius across runs — useful for
reproducible demos and grading.

### Login is real, but scoped for a local demo
Passwords are hashed (never stored or compared in plaintext) and sessions
use Flask's signed cookies. This is genuine authentication, not a fake
gate — but it's scoped for a single-machine local demo, not
internet-facing production use. Things a real deployment would add on top
(HTTPS, CSRF protection, rate limiting on login attempts, a persistent
session store) are out of scope here deliberately, since the project runs
on `127.0.0.1` only.

### Security Analyst and SOC Manager see genuinely different consoles
Earlier versions only differed by one gated button. Now the two roles see
different *sets of sections* in the sidebar, enforced on both ends:
- The **frontend** router (`js/console/router.js`) only renders nav links
  for sections the current role has access to, and shows an explicit
  "Not available for \<role\>" notice rather than a blank page if you try
  to reach a restricted one directly by URL.
- The **backend** independently enforces the same restriction with
  `@role_required(...)` decorators on every Manager-only endpoint
  (`/api/audit`, `/api/audit/summary`) — so the restriction isn't just a
  hidden button; it's a real 403 even if you call the API directly.
This mirrors a real access-control split: an analyst's job is triage,
hunting, and response; a manager's job includes org-wide oversight
(Audit Trail) and the highest-impact action (Simulate Attack).

---

## 4. Data reality check

The sample dataset (`cybersecurity_example.csv`/`.json`) has **100 rows**
spanning **2020–2022**, generated as a small synthetic example (every
source IP is unique; users repeat 1–3 times each). This is fine for a demo
and for proving every module works end-to-end, but it's intentionally
small. If you want richer results for your final report:

- The three preprocessing notebooks already in this project
  (`notebooks/preprocessed_dataset_1.ipynb` — UNSW-NB15,
  `preprocessed_dataset2.ipynb` — CICIDS-2017,
  `preprocessed_dataset3.ipynb` — NSL-KDD) show how to pull much larger,
  real-world intrusion-detection datasets from Kaggle. Swapping one of
  those in only requires writing one new `*_to_events()` function in
  `ingestion/loader.py`, then deleting `backend/db/cct.db` and restarting
  the server so it re-seeds from the new source — nothing else changes, by
  design.
- Note those datasets use different correlation signals (e.g. CICIDS-2017
  has real flow durations), so the synthesized MTTD simulation in
  `correlation/engine.py` could be replaced with real timing data if you
  use one of them instead. (MTTR no longer needs replacing — it's already
  measured from real state-machine transitions, see the design decisions
  above.)

**Resetting the database**: `backend/db/cct.db` is a single SQLite file,
created and seeded automatically on first run. Delete it and restart the
server any time you want every incident back to a clean "New" state (e.g.
before a live demo, so you're not explaining why some incidents are
already Resolved from your own testing).

---

## 5. API reference

**Read-only (no auth required):**

| Endpoint | Returns |
|---|---|
| `GET /api/events` | All normalized raw events |
| `GET /api/incidents?status=<status>` | All incidents from the database (optionally filtered by status), MITRE-enriched |
| `GET /api/incidents/<id>` | Single incident detail, including current status and assignment |
| `GET /api/incidents/<id>/history` | Full audit trail of status transitions for an incident |
| `GET /api/incidents/<id>/responses` | Response Engine decisions recorded for an incident |
| `GET /api/incidents/<id>/propagation` | Simulated blast radius for an incident (runs + caches on first request) |
| `GET /api/responses` | Every Response Engine decision across all incidents |
| `GET /api/mitre/heatmap` | Technique frequency for the ATT&CK heatmap |
| `GET /api/mitre/catalog` | Full attack-type → technique lookup table |
| `GET /api/trust-scores?order=ascending\|descending` | All users' Trust Scores |
| `GET /api/trust-scores/<user>` | Single user's score breakdown |
| `GET /api/metrics` | Full MTTD/MTTR report (overall + breakdowns + trend) |
| `GET /api/graph` | Cyber Digital Twin graph (Cytoscape.js format) |
| `GET /api/live-feed?cursor=0&page_size=1` | Next page of the live feed simulator |
| `GET /api/summary` | One-call dashboard overview (KPIs + status breakdown + top risks) |
| `GET /api/auth/me` | Currently logged-in user (or `null`) |
| `GET /api/assets` | Real device/server inventory with incident counts and risk |
| `GET /api/assets/summary` | Asset counts by type/severity, high-risk asset count |
| `GET /api/assets/<ip>/incidents` | Every incident touching a given asset IP |

**Require login (any role):**

| Endpoint | Returns |
|---|---|
| `GET /api/hunting/queries` | All saved hunt queries with their current real match counts |
| `POST /api/hunting/queries/<id>/run` | Runs a query, returns up to 50 real matching events |

**Require SOC Manager role:**

| Endpoint | Returns |
|---|---|
| `GET /api/audit?limit=200` | Org-wide chronological history of transitions + response decisions |
| `GET /api/audit/summary` | Action counts by analyst, response counts by playbook |

**Authentication:**

| Endpoint | Returns |
|---|---|
| `POST /api/auth/login` `{username, password}` | Logs in, sets session cookie |
| `POST /api/auth/register` `{username, password, role}` | Creates a new account and logs in |
| `POST /api/auth/logout` | Clears the session |

**Mutating (require login via session cookie):**

| Endpoint | Returns |
|---|---|
| `POST /api/incidents/<id>/transition` `{to_status, note}` | Moves an incident through the state machine; 409 if the transition isn't valid from its current status |
| `POST /api/incidents/<id>/assign` `{username}` | Assigns an incident to an analyst |
| `POST /api/incidents/<id>/respond` | Runs the Response Engine; 409 if the incident isn't Confirmed |
| `POST /api/incidents/<id>/simulate-attack` | Runs attack propagation simulation; **requires SOC Manager role**, returns 403 for Security Analyst accounts |

---

## 6. Using the site

- **`/` (Overview)**: the landing page. Shows live counts (events, incidents,
  tracked accounts, average MTTD) pulled directly from the API, an
  explanation of the six-stage pipeline, and links into login and the console.
- **`/login`**: sign in, or click "Use" next to either demo account to
  auto-fill its credentials.
- **`/console`**: the actual product — a sidebar console with up to 7
  sections depending on your role (see the table above). Try logging in as
  each demo account to see the difference:
  - **`analyst` / `analyst123`** sees Command Center, Incident Triage,
    Correlation Engine, Threat Hunting, Response Playbooks, and Assets.
  - **`manager` / `manager123`** sees Command Center, Correlation Engine,
    Assets, and Audit Trail — plus the only account that can trigger
    Simulate Attack on any incident.
- **Click any node** in the Cyber Digital Twin (Command Center or
  Correlation Engine) to see its risk score and event count.
- **Click any user** in the Trust Score leaderboard to see the full score
  breakdown and highlight them in the graph.
- **Click any incident** anywhere it appears (Command Center, Incident
  Triage, Response Playbooks) to open the shared detail drawer, which shows:
  - Buttons for every valid next state (e.g. a "New" incident only shows
    "→ Under Analysis"; a "Resolved" one only shows "Escalate (→ Confirmed)").
  - A **"Run Response Engine"** button once the incident reaches Confirmed
    — shows the action it decided on and why.
  - A **"Simulate Attack (Propagation)"** button, visible only to SOC
    Manager accounts (Security Analyst accounts see a note explaining why
    it's hidden) — matches the Use Case Diagram's manager-only "Simulate
    Attack" use case exactly.
- **Run a Threat Hunting query** to see real matches (or a real "no
  matches" result — both are honest outcomes) against the ingested events.
- **Check the Audit Trail** (as the manager) after doing some analyst work
  to see every action you just took, in true chronological order.

---

## 7. Extending this project

Each module is intentionally decoupled so you (or future teammates) can
extend one piece without touching the rest:

- **New data source**: add a `*_to_events()` function in `ingestion/loader.py`;
  re-run `python3 -m db.seed` (or delete `db/cct.db` and restart) to re-seed.
- **Smarter correlation**: edit `correlation/engine.py` — the rest of the
  system only depends on the `Incident` shape, not how it's built.
- **Better Trust Score model**: edit the weights/components in
  `trust_score/engine.py` — `WEIGHTS` and `SEVERITY_RISK`/`ACTION_RISK` are
  the easiest knobs.
- **More playbooks**: add new rules to `response/engine.py`'s `decide()`
  function — each rule just needs to return a `ResponseDecision` with an
  action, rationale, and playbook name.
- **Different propagation model**: `propagation/engine.py`'s `EDGE_DECAY`
  dict controls how much each relationship type contributes to lateral
  movement likelihood; tune those weights or swap the BFS for a different
  graph algorithm entirely.
- **Real-time ingestion** (beyond the simulator): replace `api/live_feed.py`
  with a real streaming source; the frontend's polling contract
  (`cursor`/`next_cursor`) would stay the same. Note: the `/api/live-feed`
  endpoint and `API.liveFeed()` wrapper still exist and work, but no
  console section currently calls them — the old dashboard's "Live Feed"
  toggle didn't carry over into the 7-section console rebuild. Wiring it
  into Command Center (e.g. a toggle that streams incidents into the
  "Recent Incidents" list) would be a natural addition if you want it back.
- **Production-grade auth**: swap `auth/service.py`'s Flask session cookies
  for a proper session store + add HTTPS/CSRF protection if this ever needs
  to run beyond `127.0.0.1`.
- **New console section**: add an entry to the `SECTIONS` map in
  `js/console/router.js` (icon, title, roles, and a module with a
  `render(container, ctx)` function), create the section's render module in
  `js/console/sections/`, and add a `<script>` tag for it in `console.html`.
  The router handles nav rendering, role-gating, and URL routing
  automatically once the section is registered.
