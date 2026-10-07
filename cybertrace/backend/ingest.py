"""Parse and normalize user-supplied security logs (JSON or CSV).

Accepted shapes:
  * JSON array of event objects, or {"events": [...]}, or JSON Lines (one object per line)
  * CSV with a header row

Field names are matched case-insensitively against common aliases (e.g. "src_ip", "host",
"username"). Unknown fields are preserved in `metadata`. Rows with `"baseline": true` (or
source_tag "ambient") become part of the behavioral baseline.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .engine import iso, parse_ts

ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "@timestamp", "datetime", "ts", "date", "event_time"),
    "user": ("user", "username", "user_name", "account", "principal", "userid", "user_id"),
    "device": ("device", "host", "hostname", "computer", "workstation", "device_id"),
    "ip": ("ip", "src_ip", "source_ip", "ip_address", "client_ip", "sourceip"),
    "application": ("application", "app", "process", "program", "service"),
    "resource": ("resource", "file", "file_path", "object", "share", "path", "target_resource"),
    "event_type": ("event_type", "type", "event", "category", "eventtype"),
    "action": ("action", "activity", "operation", "verb"),
    "location": ("location", "geo", "country", "city", "geo_location"),
    "severity": ("severity", "level", "priority"),
    "source_tag": ("source_tag", "source", "tag"),
}
META_ALIASES: dict[str, tuple[str, ...]] = {
    "usb_device": ("usb_device", "usb", "removable_device", "usb_id"),
    "destination": ("destination", "dest", "dst", "domain", "url", "remote_host", "dest_host"),
    "bytes": ("bytes", "size", "bytes_out", "bytes_sent", "volume"),
    "auth_result": ("auth_result", "result", "outcome", "status"),
}
TYPE_MAP = {
    "LOGIN": "AUTH_LOGIN", "LOGON": "AUTH_LOGIN", "AUTH": "AUTH_LOGIN", "AUTHENTICATION": "AUTH_LOGIN",
    "SIGNIN": "AUTH_LOGIN", "SIGN_IN": "AUTH_LOGIN",
    "FILE_READ": "FILE_ACCESS", "FILE_OPEN": "FILE_ACCESS", "READ": "FILE_ACCESS", "FILE": "FILE_ACCESS",
    "USB": "USB_CONNECT", "USB_INSERT": "USB_CONNECT", "USB_MOUNT": "USB_CONNECT", "DEVICE_CONNECT": "USB_CONNECT",
    "COPY": "FILE_COPY", "FILE_WRITE_REMOVABLE": "FILE_COPY",
    "NETWORK": "NETWORK_CONNECTION", "CONNECTION": "NETWORK_CONNECTION", "UPLOAD": "NETWORK_CONNECTION",
    "NETFLOW": "NETWORK_CONNECTION",
    "APP": "APP_USAGE", "PROCESS": "APP_USAGE", "PROCESS_START": "APP_USAGE",
}
DEFAULT_ACTION = {"AUTH_LOGIN": "LOGIN", "FILE_ACCESS": "READ", "USB_CONNECT": "CONNECT", "FILE_COPY": "COPY",
                  "NETWORK_CONNECTION": "TRANSFER", "APP_USAGE": "USE"}


class IngestError(ValueError):
    pass


def _records(raw: bytes, filename: str) -> list[dict[str, Any]]:
    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise IngestError("the file is empty")
    if filename.lower().endswith(".csv") or (not text.startswith(("[", "{"))):
        if text.startswith(("[", "{")):
            raise IngestError("expected CSV content")
        rows = list(csv.DictReader(io.StringIO(text)))
        if not rows:
            raise IngestError("CSV has a header but no rows")
        return rows
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:  # JSON Lines
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise IngestError(f"invalid JSON: {exc.msg} (line {exc.lineno})") from exc
    if isinstance(data, dict):
        data = data.get("events", data.get("logs", data.get("records", [data])))
    if not isinstance(data, list):
        raise IngestError("JSON must be an array of events or an object with an 'events' array")
    return [r for r in data if isinstance(r, dict)]


def normalize(records: list[dict[str, Any]], *, start_number: int, default_tag: str) -> tuple[list[dict], list[str]]:
    events, errors = [], []
    for idx, raw in enumerate(records, start=1):
        rec = {str(k).strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in raw.items()}
        used: set[str] = set()

        def take(names: tuple[str, ...]) -> Any:
            for n in names:
                if n in rec and rec[n] not in (None, ""):
                    used.add(n)
                    return rec[n]
            return None

        ts_raw = take(ALIASES["timestamp"])
        et_raw = take(ALIASES["event_type"])
        if ts_raw is None or et_raw is None:
            errors.append(f"row {idx}: missing timestamp or event_type")
            continue
        try:
            ts = iso(parse_ts(str(ts_raw)))
        except ValueError:
            errors.append(f"row {idx}: unparseable timestamp {ts_raw!r}")
            continue
        et = str(et_raw).upper().replace("-", "_").replace(" ", "_")
        et = TYPE_MAP.get(et, et)
        ev: dict[str, Any] = {
            "event_type": et,
            "timestamp": ts,
            "user": take(ALIASES["user"]),
            "device": take(ALIASES["device"]),
            "ip": take(ALIASES["ip"]),
            "application": take(ALIASES["application"]),
            "resource": take(ALIASES["resource"]),
            "action": (str(take(ALIASES["action"]) or DEFAULT_ACTION.get(et, "EVENT"))).upper(),
            "location": take(ALIASES["location"]),
            "severity": str(take(ALIASES["severity"]) or "informational").lower(),
        }
        for k in ("user", "device", "ip", "application", "resource", "location"):
            if ev[k] is not None:
                ev[k] = str(ev[k])
        meta: dict[str, Any] = {}
        nested = rec.get("metadata")
        if isinstance(nested, dict):
            meta.update(nested)
            used.add("metadata")
        elif isinstance(nested, str) and nested.startswith("{"):
            try:
                meta.update(json.loads(nested))
                used.add("metadata")
            except json.JSONDecodeError:
                pass
        for key, names in META_ALIASES.items():
            v = take(names)
            if v is not None and key not in meta:
                meta[key] = v
        if "bytes" in meta:
            try:
                meta["bytes"] = int(float(meta["bytes"]))
            except (TypeError, ValueError):
                meta.pop("bytes")
        baseline_flag = rec.get("baseline")
        used.add("baseline")
        tag = take(ALIASES["source_tag"])
        is_baseline = str(baseline_flag).lower() in ("true", "1", "yes") or str(tag).lower() == "ambient"
        ev["source_tag"] = "ambient" if is_baseline else (default_tag if tag in (None, "ambient") else str(tag))
        for k, v in rec.items():
            if k not in used and k != "event_id" and v not in (None, ""):
                meta.setdefault(k, v)
        ev["metadata"] = meta
        events.append(ev)
    events.sort(key=lambda e: e["timestamp"])
    for i, ev in enumerate(events, start=start_number):
        ev["event_id"] = f"EVT-{i:05d}"
    return events, errors


def parse_upload(raw: bytes, filename: str, *, start_number: int, default_tag: str = "uploaded"):
    records = _records(raw, filename)
    return normalize(records, start_number=start_number, default_tag=default_tag)
