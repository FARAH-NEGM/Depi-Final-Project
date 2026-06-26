# Cyber Control Tower (CCT)

A working, end-to-end implementation of the Cyber Control Tower project: a
simulated Security Operations Center (SOC) that ingests security event logs,
correlates them into incidents, maps them to MITRE ATT&CK, scores user
behavioral risk (Trust Score), measures detection/response performance
(MTTD/MTTR), and visualizes the organization as a Cyber Digital Twin — all
in one connected dashboard.

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
`Running on http://127.0.0.1:5000`.

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

No database, no separate frontend server, no Docker — everything runs
locally from one Python process, by design (per project scope).

---

## 2. Architecture

```
backend/data/cybersecurity_example.csv
        │
        ▼
ingestion/loader.py        →  normalizes raw CSV rows into a unified Event schema
        │
        ▼
correlation/engine.py      →  turns Events into Incidents
                               + synthesizes detected_at / resolved_at timestamps
                               + groups incidents into per-user "threads"
        │
        ├──────────────┬───────────────┬──────────────────┐
        ▼              ▼               ▼                  ▼
  mitre/mapping.py  trust_score/    metrics/engine.py   graph/twin.py
  (ATT&CK lookup)   engine.py       (MTTD/MTTR stats)   (Cyber Digital Twin)
                    (risk scoring)
        │              │               │                  │
        └──────────────┴───────────────┴──────────────────┘
                              │
                              ▼
                         api/  +  app.py   (Flask REST API)
                              │
                              ▼
                    frontend/ (HTML/CSS/vanilla JS dashboard)
                    - Cytoscape.js  → Cyber Digital Twin graph
                    - Chart.js      → MTTD/MTTR charts
                    - Live polling  → simulated real-time feed
```

Every module is independently testable (`python3 -m <module>.<file>` runs
its own demo/sanity-check block) and the API layer (`app.py`) is the only
place that wires them together — so any one piece can be extended without
touching the others.

### Module-by-module

| Module | File | Responsibility |
|---|---|---|
| Ingestion | `backend/ingestion/loader.py` | Loads `cybersecurity_example.csv`, normalizes every row into an `Event` dataclass (consistent field names/types for everything downstream). |
| Correlation | `backend/correlation/engine.py` | Converts Events into Incidents; synthesizes realistic `detected_at`/`resolved_at` timestamps (severity drives detection speed, action taken drives response speed); links incidents from the same user into a "thread" for behavioral analysis. |
| MITRE Mapping | `backend/mitre/mapping.py`, `enrichment.py` | Maps each incident's `Attack Type` to real MITRE ATT&CK technique IDs/tactics; produces the heatmap data. |
| Trust Score | `backend/trust_score/engine.py` | **Core module.** Computes a 0–100 per-user behavioral risk score from severity history, response quality, anomaly scores, and incident frequency — with time-decay so old incidents matter less. Fully explainable: every score ships with a plain-language breakdown. |
| MTTD/MTTR | `backend/metrics/engine.py` | **Core module.** Aggregates detection/response timing — overall, by severity, by attack type, by segment, by action, and as a monthly trend. |
| Cyber Digital Twin | `backend/graph/twin.py` | Builds a NetworkX graph of IPs, users, and network segments from the event log, exported in Cytoscape.js format with per-node risk coloring. |
| Live Feed | `backend/api/live_feed.py` | Powers "Live Mode" — replays incidents in order via a simple cursor-based polling endpoint, looping forever so a demo never runs dry. |
| API | `backend/app.py` | Flask app exposing everything above as JSON, and serving the frontend's static files. |
| Frontend | `frontend/` | Vanilla HTML/CSS/JS, three pages: a landing/overview page (`/`), the live dashboard (`/dashboard`), and a dedicated incidents table (`/incidents`). No build step — just static files served by Flask. |

### Pages

| Route | File | Purpose |
|---|---|---|
| `/` | `index.html` | Landing page — explains the product, shows live KPI numbers pulled from `/api/summary`, and links into the dashboard/incidents pages. |
| `/dashboard` | `dashboard.html` | The full live dashboard: Cyber Digital Twin graph, Trust Score leaderboard, MITRE heatmap, MTTD/MTTR charts, and the Full Analysis / Live Feed toggle. |
| `/incidents` | `incidents.html` | A dedicated, sortable, filterable table of every correlated incident — searchable by user/IP/attack type, with pagination and the same click-through detail drawer as the dashboard. |

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
  `ingestion/loader.py` — nothing else changes, by design.
- Note those datasets use different correlation signals (e.g. CICIDS-2017
  has real flow durations), so the synthesized MTTD/MTTR simulation in
  `correlation/engine.py` could be replaced with real timing data if you
  use one of them instead.

---

## 5. API reference

| Endpoint | Returns |
|---|---|
| `GET /api/events` | All normalized raw events |
| `GET /api/incidents` | All correlated incidents, MITRE-enriched |
| `GET /api/incidents/<id>` | Single incident detail |
| `GET /api/mitre/heatmap` | Technique frequency for the ATT&CK heatmap |
| `GET /api/mitre/catalog` | Full attack-type → technique lookup table |
| `GET /api/trust-scores?order=ascending\|descending` | All users' Trust Scores |
| `GET /api/trust-scores/<user>` | Single user's score breakdown |
| `GET /api/metrics` | Full MTTD/MTTR report (overall + breakdowns + trend) |
| `GET /api/graph` | Cyber Digital Twin graph (Cytoscape.js format) |
| `GET /api/live-feed?cursor=0&page_size=1` | Next page of the live feed simulator |
| `GET /api/summary` | One-call dashboard overview (KPIs + top risks) |

---

## 6. Using the site

- **`/` (Overview)**: the landing page. Shows live counts (events, incidents,
  tracked accounts, average MTTD) pulled directly from the API, an
  explanation of the six-stage pipeline, and links into the dashboard and
  incidents pages.
- **`/dashboard` (Full Analysis mode, default)**: shows everything computed
  from the whole dataset at once — full incident list, MITRE heatmap,
  MTTD/MTTR charts.
- **`/dashboard` (Live Feed mode)**: switches the bottom panel to a
  simulated real-time incident stream (replays the dataset in order, one
  incident every ~2.5s, looping forever).
- **`/incidents`**: a dedicated, full-width table of every incident —
  search by user/IP/attack type, filter by severity/attack type/action,
  sort any column, paginate through results.
- **Click any node** in the Cyber Digital Twin to see its risk score and
  event count.
- **Click any user** in the Trust Score leaderboard to see the full score
  breakdown and highlight them in the graph.
- **Click any incident** (on either the dashboard feed or the incidents
  table) to see its full detail, including MTTD/MTTR and mapped MITRE
  techniques.

---

## 7. Extending this project

Each module is intentionally decoupled so you (or future teammates) can
extend one piece without touching the rest:

- **New data source**: add a `*_to_events()` function in `ingestion/loader.py`.
- **Smarter correlation**: edit `correlation/engine.py` — the rest of the
  system only depends on the `Incident` dataclass shape, not how it's built.
- **Better Trust Score model**: edit the weights/components in
  `trust_score/engine.py` — `WEIGHTS` and `SEVERITY_RISK`/`ACTION_RISK` are
  the easiest knobs.
- **Real-time ingestion** (beyond the simulator): replace `api/live_feed.py`
  with a real streaming source; the frontend's polling contract
  (`cursor`/`next_cursor`) would stay the same.
