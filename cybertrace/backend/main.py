"""CyberTrace AI — FastAPI application.

Serves the JSON API under /api and the single-page frontend from ./frontend, so the whole
app runs as one process on one port (no Node/npm build step required).
"""

from __future__ import annotations

import logging
import mimetypes
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import ai_narrative, config, data_generator
from .engine import parse_ts, run_analysis
from .graph import build_graph
from .ingest import IngestError, parse_upload
from .patterns import public_patterns
from .storage import Store

# Windows sometimes maps .js to text/plain in the registry, which breaks ES modules.
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/svg+xml", ".svg")

log = logging.getLogger("cybertrace")


class WindowBody(BaseModel):
    window_minutes: int = Field(config.DEFAULT_WINDOW_MINUTES, ge=config.MIN_WINDOW_MINUTES,
                                le=config.MAX_WINDOW_MINUTES)


def create_app(db_path: str | Path | None = None) -> FastAPI:
    store = Store(db_path or config.DB_PATH)
    app = FastAPI(title="CyberTrace AI", version="1.0.0",
                  description="Explainable multi-stage attack reconstruction — HNX26PSI03")
    app.state.store = store
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["*"],
                       allow_headers=["*"])

    # ------------------------------------------------------------------ helpers
    def analyze_and_store(window_minutes: int, mode: str | None, label: str | None) -> dict:
        events = store.all_events()
        if not events:
            raise HTTPException(409, "No events stored — run a demo or import logs first.")
        analysis = run_analysis(events, window_minutes=window_minutes, mode=mode, scenario_label=label)
        store.save_analysis(analysis)
        store.set_meta("last_run_mode", mode)
        store.set_meta("scenario_label", label)
        return analysis

    # --------------------------------------------------------------------- api
    @app.get("/api/")
    @app.get("/api")
    def root():
        return {"message": "CyberTrace AI API", "docs": "/docs"}

    @app.get("/api/health")
    def health():
        return {"status": "ok", "events": store.count_events(), "ai_narrative": ai_narrative.enabled()}

    @app.get("/api/stats")
    def stats():
        a = store.latest_analysis()
        events = store.all_events()
        ref_day = parse_ts(events[-1]["timestamp"]).date() if events else date.today()
        by_day = Counter(e["timestamp"][:10] for e in events)
        daily = [{"date": (ref_day - timedelta(days=d)).isoformat(),
                  "count": by_day.get((ref_day - timedelta(days=d)).isoformat(), 0)} for d in range(6, -1, -1)]
        by_type = Counter(e["event_type"] for e in events)
        s = a["summary"] if a else {}
        return {
            "has_analysis": a is not None,
            "last_run_mode": a.get("mode") if a else None,
            "last_run_at": a.get("created_at") if a else None,
            "total_events": len(events),
            "events_today": by_day.get(ref_day.isoformat(), 0),
            "users": len({e["user"] for e in events if e.get("user")}),
            "devices": len({e["device"] for e in events if e.get("device")}),
            "anomalies": s.get("anomalies", 0),
            "suspicious_events": s.get("suspicious_events", 0),
            "possible_incidents": s.get("possible_incidents", 0),
            "high_confidence_attacks": s.get("high_confidence_attacks", 0),
            "system_status": s.get("system_status", "NO_DATA"),
            "verdict_message": s.get("verdict_message",
                                     "AWAITING DATA — run a demo or import logs to start the detection engine."),
            "risk_score": s.get("risk_score", 0),
            "risk_tier": s.get("risk_tier", "LOW"),
            "daily_volume": daily if events else [],
            "anomaly_by_type": [{"type": k, "count": v} for k, v in
                                sorted(Counter(x["anomaly_type"] for x in (a or {}).get("anomalies", [])).items())],
            "events_by_type": [{"type": k, "count": v} for k, v in by_type.most_common()],
        }

    @app.get("/api/analysis/latest")
    def analysis_latest():
        # "Nothing analyzed yet" is a normal state, not an error: answer 200 with null.
        return store.latest_analysis()

    @app.post("/api/analyze")
    def analyze(body: WindowBody | None = None):
        body = body or WindowBody()
        return analyze_and_store(body.window_minutes, store.get_meta("last_run_mode"),
                                 store.get_meta("scenario_label"))

    @app.get("/api/events")
    def list_events(q: str | None = None, user: str | None = None, event_type: str | None = None,
                    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        total, items = store.query_events(q, user, event_type, limit, offset)
        return {"total": total, "items": items}

    @app.get("/api/events/{event_id}")
    def get_event(event_id: str):
        ev = store.get_event(event_id)
        if ev is None:
            raise HTTPException(404, f"Event {event_id} not found")
        return ev

    @app.post("/api/events/upload")
    async def upload_events(file: UploadFile = File(...),
                            mode: Literal["append", "replace"] = Form("append"),
                            window_minutes: int = Form(config.DEFAULT_WINDOW_MINUTES,
                                                       ge=config.MIN_WINDOW_MINUTES, le=config.MAX_WINDOW_MINUTES)):
        raw = await file.read(config.MAX_UPLOAD_BYTES + 1)
        if len(raw) > config.MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"File larger than {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
        start = 1 if mode == "replace" else store.max_event_number() + 1
        try:
            events, errors = parse_upload(raw, file.filename or "upload.json", start_number=start)
        except IngestError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not events:
            raise HTTPException(422, {"message": "No valid events found", "errors": errors[:20]})
        if len(events) > config.MAX_UPLOAD_EVENTS:
            raise HTTPException(413, f"More than {config.MAX_UPLOAD_EVENTS} events in one upload")
        if mode == "replace":
            store.replace_events(events)
        else:
            store.add_events(events)
        label = f"Imported logs: {file.filename}"
        analysis = analyze_and_store(window_minutes, "uploaded", label)
        return {"ingested": len(events), "error_count": len(errors), "errors": errors[:20],
                "total_events": store.count_events(), "mode": mode, "summary": analysis["summary"]}

    @app.get("/api/graph")
    def graph():
        return build_graph(store.latest_analysis(), store.all_events())

    @app.get("/api/explanation/{chain_id}")
    def explanation(chain_id: str):
        a = store.latest_analysis()
        chains = (a or {}).get("chains", [])
        if chain_id == "latest":
            if not chains:
                return None  # quiet system: nothing to explain (200 null, not an error)
            chain = chains[0]
        else:
            chain = next((c for c in chains if c["id"] == chain_id), None)
            if chain is None:
                raise HTTPException(404, f"Chain {chain_id} not found in the latest analysis")
        if ai_narrative.enabled() and chain["explanation"]["generated_by"] == "deterministic-rules":
            text = ai_narrative.rephrase(chain)
            if text:
                chain["explanation"]["narrative"] = text
                chain["explanation"]["generated_by"] = config.GEMINI_MODEL
                store.save_analysis(a)  # cache so the model is called once per analysis
        return {"chain_id": chain["id"], "chain_name": chain["name"], "pattern_id": chain["pattern_id"],
                "state": chain["state"], "risk": chain["risk"], "explanation": chain["explanation"],
                "recommendations": chain["recommendations"]}

    @app.get("/api/demo/patterns")
    def patterns():
        return public_patterns()

    @app.post("/api/demo/{scenario}")
    def run_demo(scenario: Literal["attack", "clean"], body: WindowBody | None = None):
        body = body or WindowBody()
        events = data_generator.generate(scenario)
        store.replace_events(events)
        analysis = analyze_and_store(body.window_minutes, scenario, data_generator.SCENARIO_LABELS[scenario])
        return {"scenario": scenario, "events_ingested": len(events),
                "baseline_events": analysis["summary"]["baseline_events"], "analysis": analysis}

    @app.post("/api/reset")
    def reset():
        store.reset()
        return {"status": "cleared"}

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def api_not_found(path: str):
        return JSONResponse({"detail": f"Unknown API route /api/{path}"}, status_code=404)

    # ---------------------------------------------------------------- frontend
    frontend = config.FRONTEND_DIR.resolve()
    index = frontend / "index.html"

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        return FileResponse(frontend / "favicon.svg", media_type="image/svg+xml")

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def spa(path: str, request: Request):
        if path:
            candidate = (frontend / path).resolve()
            if candidate.is_relative_to(frontend) and candidate.is_file():
                # Revalidate with ETag on every load so a redeploy never serves stale JS/CSS.
                return FileResponse(candidate, headers={"Cache-Control": "no-cache"})
            if "." in Path(path).name:  # a missing asset, not a client-side route
                return JSONResponse({"detail": "Not found"}, status_code=404)
        if not index.is_file():
            return JSONResponse({"detail": "frontend/index.html missing"}, status_code=500)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return app


app = create_app()
