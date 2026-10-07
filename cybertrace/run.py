"""Start CyberTrace AI: `python run.py` then open http://127.0.0.1:8001

Options (environment variables): HOST, PORT, GEMINI_API_KEY, CYBERTRACE_DB.
Pass --reload for auto-reload while developing.
"""

import os
import sys
from pathlib import Path

# Work no matter which directory the script is launched from (VS Code, a terminal, a service).
ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402

from backend import config  # noqa: E402

if __name__ == "__main__":
    reload = "--reload" in sys.argv
    print(f"\n  CyberTrace AI  ->  http://{'localhost' if config.HOST in ('0.0.0.0', '127.0.0.1') else config.HOST}:{config.PORT}\n")
    uvicorn.run("backend.main:app", host=config.HOST, port=config.PORT, reload=reload,
                reload_dirs=["backend"] if reload else None, log_level="info")
