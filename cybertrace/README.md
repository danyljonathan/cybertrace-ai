# CYBERTRACE AI — From Isolated Events to Explainable Attack Intelligence

**HackNex 2026 Internal Qualifier · Problem HNX26PSI03 (AI-Powered Cyber Threat Intelligence) · Team HNX-INT-035 "SkillIssue"**

CyberTrace connects security events across **users, devices, IPs, applications, resources and USB
peripherals** and reconstructs what an attacker did, step by step. For each attack it shows the
**timeline**, **who/what was involved**, the **stages** (MITRE ATT&CK-mapped), **proof for every stage**,
an **explainable risk score**, and **recommended actions**. It also stays quiet on clean logs.

> All bundled data is **SYNTHETIC DEMONSTRATION DATA**.

---

## Run it (VS Code, Windows / macOS / Linux)

Requirements: **Python 3.10+** (tested on 3.12 and 3.14). Node.js is **not** needed: the frontend is a
no-build SPA served by the backend.

```bash
cd cybertrace
python -m venv .venv
# Windows:            .venv\Scripts\activate
# macOS / Linux:      source .venv/bin/activate
pip install -r requirements-dev.txt
python run.py
```

Open **http://127.0.0.1:8001**, then **Demo Center → RUN MULTI-STAGE ATTACK DEMO**.

From VS Code you can also:
- **Terminal → Run Task → "Setup: create venv + install"**, then **"Run CyberTrace AI"**, or
- press **F5** and pick **"CyberTrace AI (server)"**. The `debugpy` launch configs are in `.vscode/`.

Run the tests with `python -m pytest -q` (14 end-to-end tests).

API docs (Swagger) are at **http://127.0.0.1:8001/docs**.

## What to show the judges

| Judging criterion | Where to see it |
|---|---|
| Links separate events into one chain, in order | Attack Chain, Attack Timeline (09:12 → 09:16 → 09:21 → 09:23) |
| Identifies attacks without false alarms | Threat Detection: escalation ladder + risk weight table |
| Catches the real attacks | Attack demo = 1 chain, 90/100 CRITICAL; imported sample = 1 chain via a **second** pattern |
| Connects users, devices, IPs, apps | Attack Graph: click nodes, scrub stages |
| Stays quiet on clean logs | Clean demo: 0 chains, 1 isolated signal held at SUSPICIOUS |
| Accurate timeline | Built only from stored event timestamps |
| Explains why | Explanation: hard facts vs. interpretation, conclusion, narrative, actions |
| Proof for every stage | Evidence ledger: 48/48 rows verified against stored events; export case JSON |

**Bring your own logs:** Log Explorer → *Import your own logs* accepts JSON arrays, JSON Lines or CSV.
Two samples are provided (download links are on the page):
- `frontend/samples/network_exfiltration_logs.json` triggers **Account Takeover with Network Exfiltration**
  (login from Frankfurt → first-time read of `customer_pii_export` → 1.8 GB upload to a new domain).
- `frontend/samples/custom_logs_template.csv` triggers **USB exfiltration** for a different user.

Rows with `"baseline": true` form the behavioral baseline. Without a baseline, the last 24 h are
evaluated against everything earlier.

## How detection works (13 deterministic stages)

1. Log Ingestion → 2. Normalization → 3. Entity Extraction → 4. Behavioral Baseline (per user) →
5. Anomaly Detection (rule registry) → 6. Event Correlation → 7. Sequence/Order Analysis →
8. Attack Chain Reconstruction (pattern registry) → 9. Evidence Validation → 10. Risk Assessment →
11. Explanation → 12. Recommended Action → 13. Verdict

**False-positive control (escalation ladder):**
`1 anomaly → SUSPICIOUS EVENT` · `2+ related → POSSIBLE INCIDENT` ·
`3+ related AND a registered pattern observed in order → HIGH-CONFIDENCE ATTACK`.
Anomalies are "related" only when they share the **same user AND a non-user entity** (device, IP,
resource, app, USB, destination) **inside the investigation window**, never on time alone. Users
with no baseline are not scored.

**Risk weights:** Unusual Login +15 · Unusual Resource Access +20 · New USB Device +20 ·
File Copy to Removable Media +25 · Large Transfer to New Destination +25 · Strong correlation +10
(capped at 100). Tiers: 0–29 LOW, 30–59 MEDIUM, 60–79 HIGH, 80–100 CRITICAL.

**Extending:** add a pattern to `backend/patterns.py` (and, if it needs a new signal, a rule in
`backend/engine.py → RULES`). The detector itself does not change.

**AI layer (optional):** set `GEMINI_API_KEY` to have Gemini *rephrase* the verified chain into an
analyst narrative. Detection never depends on it; any error or timeout falls back to the
deterministic narrative.

## Project layout

```
cybertrace/
├─ run.py                 # entry point (python run.py)
├─ backend/
│  ├─ main.py             # FastAPI app: /api/* + serves the SPA
│  ├─ engine.py           # 13-stage detection pipeline
│  ├─ patterns.py         # attack-pattern registry, risk weights, playbook
│  ├─ graph.py            # entity-relationship graph from events
│  ├─ data_generator.py   # deterministic synthetic attack / clean datasets
│  ├─ ingest.py           # JSON / JSONL / CSV log import + field aliasing
│  ├─ ai_narrative.py     # optional Gemini rephrasing (stdlib only)
│  ├─ storage.py          # SQLite store (zero setup)
│  └─ config.py
├─ frontend/              # vanilla JS SPA (ES modules, no build step)
│  ├─ index.html · css/app.css · js/app.js · js/pages/*.js
│  └─ samples/            # importable sample logs
└─ tests/test_api.py
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness + event count |
| GET | `/api/stats` | dashboard numbers, verdict, 7-day volume |
| GET | `/api/analysis/latest` | full latest analysis (`null` if none) |
| POST | `/api/analyze` `{window_minutes}` | re-run the pipeline on stored events |
| POST | `/api/demo/{attack\|clean}` `{window_minutes}` | regenerate dataset + analyze |
| GET | `/api/demo/patterns` | attack-pattern registry |
| GET | `/api/events?q=&user=&event_type=&limit=&offset=` | search the event store |
| GET | `/api/events/{event_id}` | one raw event |
| POST | `/api/events/upload` (multipart `file`, `mode`=append\|replace) | import logs + analyze |
| GET | `/api/graph` | entity graph (nodes, edges, stages) |
| GET | `/api/explanation/{chain_id\|latest}` | explanation + recommendations |
| POST | `/api/reset` | clear everything |

## Deploy

- **Docker:** `docker build -t cybertrace . && docker run -p 8001:8001 cybertrace`
- **Render:** push the repo; `render.yaml` is included (free plan works).
- **Railway / Heroku-style:** the `Procfile` runs `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`.
- **Any VM:** `HOST=0.0.0.0 PORT=8001 python run.py`.

Configuration lives in environment variables; see `.env.example`.

Team: Harshan Nandha R · Danyl Jonathan D · S. M. Navaneetha Krishnan · Sugandh
