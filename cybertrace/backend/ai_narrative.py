"""Optional AI rephrasing of the deterministic narrative (Google Gemini REST API).

Detection is never delegated: the model only receives the verified chain as JSON and is asked
to rephrase it. No key, an API error, or a timeout -> the deterministic narrative is kept.
Uses only the standard library, so there is no extra dependency to install.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from .config import GEMINI_API_KEY, GEMINI_MODEL, GEMINI_TIMEOUT_S

log = logging.getLogger("cybertrace.ai")

PROMPT = (
    "You are a SOC analyst writing for an incident report. Rephrase the verified attack chain below into "
    "one clear paragraph (max 120 words). Use ONLY the facts provided — do not invent events, entities, "
    "timestamps or numbers. Mention the event ids. Plain text, no markdown.\n\nVERIFIED CHAIN JSON:\n"
)


def enabled() -> bool:
    return bool(GEMINI_API_KEY)


def rephrase(chain: dict) -> str | None:
    if not GEMINI_API_KEY:
        return None
    facts = {
        "pattern": chain["pattern_name"],
        "risk": {"score": chain["risk"]["score"], "tier": chain["risk"]["tier"]},
        "stages": [{"time": s["timestamp"], "name": s["name"], "event_ids": s["event_ids"],
                    "reason": s["reason"]} for s in chain["stages"]],
        "conclusion": chain["explanation"]["conclusion"],
    }
    body = json.dumps({"contents": [{"parts": [{"text": PROMPT + json.dumps(facts, indent=1)}]}]}).encode()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "x-goog-api-key": GEMINI_API_KEY,
    })
    try:
        with urllib.request.urlopen(req, timeout=GEMINI_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode())
        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        return text or None
    except (urllib.error.URLError, TimeoutError, KeyError, IndexError, ValueError) as exc:
        log.warning("Gemini narrative unavailable, using deterministic narrative: %s", exc)
        return None
