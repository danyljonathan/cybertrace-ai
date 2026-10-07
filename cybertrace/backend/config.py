"""Runtime configuration — everything is optional and has a safe default."""

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"
DATA_DIR = Path(os.getenv("CYBERTRACE_DATA_DIR", ROOT_DIR / "data"))
DB_PATH = Path(os.getenv("CYBERTRACE_DB", DATA_DIR / "cybertrace.db"))

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8001"))

# Optional AI narrative layer. Without a key the deterministic narrative is served.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_TIMEOUT_S = float(os.getenv("GEMINI_TIMEOUT_S", "8"))

# CORS is only needed when the frontend is hosted on a different origin.
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]

DEFAULT_WINDOW_MINUTES = 30
MIN_WINDOW_MINUTES = 5
MAX_WINDOW_MINUTES = 240

# When an uploaded dataset has no "ambient"/baseline-tagged events, the most recent
# EVAL_HOURS of activity are evaluated and everything earlier becomes the baseline.
EVAL_HOURS = int(os.getenv("CYBERTRACE_EVAL_HOURS", "24"))

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_UPLOAD_EVENTS = 50_000
