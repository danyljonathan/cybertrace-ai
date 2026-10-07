"""SQLite persistence for normalized events and analysis results.

Zero-setup replacement for MongoDB: the database is a single file under ./data and is
created on first use. All access goes through one connection guarded by a lock, which is
plenty for a single-process demo server.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

EVENT_FIELDS = (
    "event_id", "timestamp", "user", "device", "ip", "application", "resource",
    "event_type", "action", "location", "severity", "metadata", "source_tag",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    user        TEXT,
    device      TEXT,
    ip          TEXT,
    application TEXT,
    resource    TEXT,
    event_type  TEXT NOT NULL,
    action      TEXT,
    location    TEXT,
    severity    TEXT,
    metadata    TEXT NOT NULL DEFAULT '{}',
    source_tag  TEXT NOT NULL DEFAULT 'uploaded'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS analyses (
    id         TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    body       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class Store:
    def __init__(self, db_path: Path | str):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ events
    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        ev = {k: row[k] for k in EVENT_FIELDS}
        ev["metadata"] = json.loads(ev["metadata"] or "{}")
        return ev

    def replace_events(self, events: Iterable[dict[str, Any]]) -> int:
        with self._lock:
            self._conn.execute("DELETE FROM events")
            n = self._insert(events)
            self._conn.commit()
            return n

    def add_events(self, events: Iterable[dict[str, Any]]) -> int:
        with self._lock:
            n = self._insert(events)
            self._conn.commit()
            return n

    def _insert(self, events: Iterable[dict[str, Any]]) -> int:
        rows = [
            tuple(json.dumps(e.get("metadata") or {}) if k == "metadata" else e.get(k) for k in EVENT_FIELDS)
            for e in events
        ]
        self._conn.executemany(
            f"INSERT OR REPLACE INTO events ({','.join(EVENT_FIELDS)}) VALUES ({','.join('?' * len(EVENT_FIELDS))})",
            rows,
        )
        return len(rows)

    def all_events(self) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM events ORDER BY timestamp ASC, event_id ASC")
            return [self._row_to_event(r) for r in cur.fetchall()]

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
            return self._row_to_event(row) if row else None

    def count_events(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def max_event_number(self) -> int:
        """Highest numeric suffix of EVT-xxxxx ids, so appended events keep unique ids."""
        with self._lock:
            ids = [r[0] for r in self._conn.execute("SELECT event_id FROM events WHERE event_id LIKE 'EVT-%'")]
        best = 0
        for eid in ids:
            try:
                best = max(best, int(eid.split("-", 1)[1]))
            except (IndexError, ValueError):
                continue
        return best

    def query_events(
        self, q: str | None, user: str | None, event_type: str | None, limit: int, offset: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        where, params = [], []
        if q:
            like = f"%{q.strip()}%"
            where.append(
                "(event_id LIKE ? OR user LIKE ? OR device LIKE ? OR ip LIKE ? OR application LIKE ? "
                "OR resource LIKE ? OR location LIKE ? OR event_type LIKE ? OR metadata LIKE ?)"
            )
            params += [like] * 9
        if user:
            where.append("user LIKE ?")
            params.append(f"%{user.strip()}%")
        if event_type:
            where.append("event_type = ?")
            params.append(event_type.strip())
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) FROM events {clause}", params).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM events {clause} ORDER BY timestamp DESC, event_id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return total, [self._row_to_event(r) for r in rows]

    # ---------------------------------------------------------------- analyses
    def save_analysis(self, analysis: dict[str, Any]) -> None:
        with self._lock:
            # Only the latest analysis is ever served; keep the table small.
            self._conn.execute("DELETE FROM analyses")
            self._conn.execute(
                "INSERT INTO analyses (id, created_at, body) VALUES (?, ?, ?)",
                (analysis["id"], analysis["created_at"], json.dumps(analysis)),
            )
            self._conn.commit()

    def latest_analysis(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM analyses ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        return json.loads(row[0]) if row else None

    def clear_analysis(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM analyses")
            self._conn.commit()

    # -------------------------------------------------------------------- meta
    def set_meta(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, json.dumps(value))
            )
            self._conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def reset(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.execute("DELETE FROM analyses")
            self._conn.execute("DELETE FROM meta")
            self._conn.commit()
