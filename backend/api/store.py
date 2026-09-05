"""SQLite persistence for scan jobs.

Keeps the in-memory manager as the live cache, but writes every status
change so a restart (or a later GET) can still serve the report, dumps,
and event log. One row per scan; JSON columns hold the structured bits.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manager import ScanState

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    status      TEXT NOT NULL,
    url         TEXT NOT NULL,
    urls        TEXT NOT NULL DEFAULT '[]',
    method      TEXT NOT NULL DEFAULT 'GET',
    params      TEXT NOT NULL DEFAULT '{}',
    findings    TEXT NOT NULL DEFAULT '[]',
    extracted   TEXT NOT NULL DEFAULT '[]',
    dumps       TEXT NOT NULL DEFAULT '[]',
    events      TEXT NOT NULL DEFAULT '[]',
    waf         TEXT NOT NULL DEFAULT '[]'
);
"""


class ScanStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.executescript(_SCHEMA)
            self._migrate(db)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, check_same_thread=False)
        db.row_factory = sqlite3.Row
        return db

    def _migrate(self, db: sqlite3.Connection) -> None:
        cols = {row[1] for row in db.execute("PRAGMA table_info(scans)")}
        if "urls" not in cols:
            db.execute("ALTER TABLE scans ADD COLUMN urls TEXT NOT NULL DEFAULT '[]'")
        if "waf" not in cols:
            db.execute("ALTER TABLE scans ADD COLUMN waf TEXT NOT NULL DEFAULT '[]'")

    def save(self, state: "ScanState") -> None:
        from datetime import datetime, timezone

        payload = (
            state.id,
            state.created_at,
            datetime.now(timezone.utc).isoformat(),
            state.status,
            state.url,
            json.dumps(state.urls, default=str),
            state.method,
            json.dumps(state.params, default=str),
            json.dumps(state.findings, default=str),
            json.dumps(state.extracted, default=str),
            json.dumps(state.dumps, default=str),
            json.dumps(state.events, default=str),
            json.dumps(state.waf, default=str),
        )
        with self._lock, self._connect() as db:
            db.execute(
                """
                INSERT INTO scans (
                    id, created_at, updated_at, status, url, urls, method,
                    params, findings, extracted, dumps, events, waf
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    status=excluded.status,
                    url=excluded.url,
                    urls=excluded.urls,
                    method=excluded.method,
                    params=excluded.params,
                    findings=excluded.findings,
                    extracted=excluded.extracted,
                    dumps=excluded.dumps,
                    events=excluded.events,
                    waf=excluded.waf
                """,
                payload,
            )

    def load(self, scan_id: str) -> dict | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def delete(self, scan_id: str) -> bool:
        with self._lock, self._connect() as db:
            cur = db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            return cur.rowcount > 0

    def delete_all(self) -> int:
        with self._lock:
            with self._connect() as db:
                cur = db.execute("DELETE FROM scans")
                n = cur.rowcount
            try:
                with self._connect() as db:
                    db.execute("VACUUM")
            except sqlite3.Error:
                pass
            return n

    def list_ids(self) -> list[str]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT id FROM scans").fetchall()
        return [row["id"] for row in rows]

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                """
                SELECT id, created_at, updated_at, status, url, urls, method,
                       params, findings, extracted, dumps, waf
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out = []
        for row in rows:
            item = self._row_to_dict(row, include_events=False)
            item["findings_count"] = len(item.get("findings") or [])
            # Keep the list payload small: drop the bulky blobs.
            item.pop("extracted", None)
            item.pop("dumps", None)
            item.pop("findings", None)
            out.append(item)
        return out

    def _row_to_dict(self, row: sqlite3.Row, *, include_events: bool = True) -> dict:
        def _j(key: str, default):
            raw = row[key] if key in row.keys() else None
            if not raw:
                return default
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return default

        data = {
            "id": row["id"],
            "created_at": row["created_at"],
            "status": row["status"],
            "url": row["url"],
            "urls": _j("urls", []),
            "method": row["method"],
            "params": _j("params", {}),
            "findings": _j("findings", []),
            "extracted": _j("extracted", []),
            "dumps": _j("dumps", []),
            "waf": _j("waf", []),
        }
        if include_events and "events" in row.keys():
            data["events"] = _j("events", [])
        return data
