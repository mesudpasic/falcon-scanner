"""Scan manager: runs scans as asyncio tasks, fans out events, persists to SQLite.

Each scan keeps its full event history (so a client that connects late can
replay) plus a set of live subscriber queues (for WebSocket streaming).
Finished scans are written to SQLite so they survive a process restart.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from engine import AuditLog, ScanConfig, Scanner, Scope
from engine.crawler import target_from_url
from engine.target import Target

from .models import ScanRequest
from .store import ScanStore


@dataclass
class ScanState:
    id: str
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    created_at: str = ""
    status: str = "pending"  # pending -> running -> finished | error
    events: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    extracted: list[dict] = field(default_factory=list)
    dumps: list[dict] = field(default_factory=list)
    waf: list[dict] = field(default_factory=list)
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    task: asyncio.Task | None = None


def _state_from_row(row: dict) -> ScanState:
    return ScanState(
        id=row["id"],
        url=row.get("url") or "",
        method=row.get("method") or "GET",
        params=dict(row.get("params") or {}),
        urls=list(row.get("urls") or []),
        created_at=row.get("created_at") or "",
        status=row.get("status") or "finished",
        events=list(row.get("events") or []),
        findings=list(row.get("findings") or []),
        extracted=list(row.get("extracted") or []),
        dumps=list(row.get("dumps") or []),
        waf=list(row.get("waf") or []),
    )


class ScanManager:
    def __init__(self, audit: AuditLog | None = None, store: ScanStore | None = None):
        self.audit = audit
        self.store = store
        self._scans: dict[str, ScanState] = {}
        if store:
            for row in store.list_scans(limit=100):
                full = store.load(row["id"])
                if full:
                    self._scans[full["id"]] = _state_from_row(full)

    def get(self, scan_id: str) -> ScanState | None:
        state = self._scans.get(scan_id)
        if state:
            return state
        if self.store:
            row = self.store.load(scan_id)
            if row:
                state = _state_from_row(row)
                self._scans[scan_id] = state
                return state
        return None

    def list_scans(self, limit: int = 50) -> list[ScanState]:
        # Live cache first (has running tasks), then anything only on disk.
        items = list(self._scans.values())
        items.sort(key=lambda s: s.created_at, reverse=True)
        return items[:limit]

    def create_scan(self, req: ScanRequest) -> str:
        scan_id = uuid.uuid4().hex[:12]
        urls = req.all_urls()
        state = ScanState(
            id=scan_id,
            url=urls[0] if urls else req.url,
            urls=urls,
            method=req.method,
            params=dict(req.params),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._scans[scan_id] = state
        if self.store:
            self.store.save(state)
        state.task = asyncio.create_task(self._run(state, req))
        return scan_id

    def _persist(self, state: ScanState) -> None:
        if self.store and state.id in self._scans:
            self.store.save(state)

    async def delete(self, scan_id: str) -> bool:
        """Drop a scan from memory and SQLite. Cancels a still-running job."""
        state = self.get(scan_id)
        if not state:
            return False
        task = state.task
        self._scans.pop(scan_id, None)
        if self.store:
            self.store.delete(scan_id)
        for queue in list(state.subscribers):
            try:
                queue.put_nowait({"type": "done", "status": "deleted"})
            except Exception:
                pass
            state.subscribers.discard(queue)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        return True

    async def delete_all(self) -> int:
        ids = list(self._scans)
        if self.store:
            for sid in self.store.list_ids():
                if sid not in ids:
                    ids.append(sid)
        tasks: list[asyncio.Task] = []
        for state in list(self._scans.values()):
            for queue in list(state.subscribers):
                try:
                    queue.put_nowait({"type": "done", "status": "deleted"})
                except Exception:
                    pass
                state.subscribers.discard(queue)
            if state.task and not state.task.done():
                state.task.cancel()
                tasks.append(state.task)
        self._scans.clear()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        if self.store:
            self.store.delete_all()
        return len(ids)

    async def _emit(self, state: ScanState, event: dict) -> None:
        state.events.append(event)
        if event.get("type") == "finding":
            state.findings.append(event)
        elif event.get("type") == "extracted-data":
            state.extracted.append(event)
        elif event.get("type") == "table-dump":
            state.dumps.append(event)
        elif event.get("type") == "waf" and event.get("detected"):
            state.waf.append(event)
        for queue in list(state.subscribers):
            await queue.put(event)
        # Persist on meaningful boundaries so a crash still leaves a trail,
        # without rewriting the row on every progress tick.
        if event.get("type") in {
            "finding",
            "extracted-data",
            "table-dump",
            "waf",
            "crawled",
            "scan_finished",
            "done",
            "error",
        }:
            self._persist(state)

    async def _run(self, state: ScanState, req: ScanRequest) -> None:
        state.status = "running"
        self._persist(state)
        scope = Scope(
            allowed_hosts=req.allowed_hosts,
            allow_private=req.allow_private,
            consent=req.consent,
        )
        config = ScanConfig(
            scope=scope,
            rate_limit_per_sec=req.rate_limit_per_sec,
            timeout=req.timeout,
            proxy=req.proxy,
            verify_tls=req.verify_tls,
            extract_data=req.extract_data,
            dump_data=req.dump_data,
            max_dump_tables=req.max_dump_tables,
            max_dump_rows=req.max_dump_rows,
            crawl=req.crawl,
            crawl_depth=req.crawl_depth,
            crawl_max_pages=req.crawl_max_pages,
            detect_waf=req.detect_waf,
            tampers=list(req.tampers),
            auto_tamper=req.auto_tamper,
            concurrency=req.concurrency,
            oob_callback=req.oob_callback,
            oob_domain=req.oob_domain,
            oob_poll_url=req.oob_poll_url,
            oob_poll_auth=req.oob_poll_auth,
            oob_interactsh=req.oob_interactsh,
            oob_interactsh_token=req.oob_interactsh_token,
            blind_enumerate=req.blind_enumerate,
            max_blind_catalog_len=req.max_blind_catalog_len,
        )
        targets: list[Target] = [
            target_from_url(
                url,
                method=req.method,
                extra_params=req.params,
                cookies=req.cookies,
            )
            for url in (state.urls or [state.url])
        ]
        for t in targets:
            t.tampers = list(req.tampers)
            t.oob_callback = req.oob_callback
            t.oob_domain = req.oob_domain
            t.oob_poll_url = req.oob_poll_url
            t.oob_poll_auth = req.oob_poll_auth
            t.oob_interactsh = req.oob_interactsh
            t.oob_interactsh_token = req.oob_interactsh_token

        scanner = Scanner(config, audit=self.audit)
        errored = False

        async def on_event(event: dict) -> None:
            nonlocal errored
            if event.get("type") == "error":
                errored = True
            await self._emit(state, event)

        try:
            await scanner.run(targets, on_event)
        except asyncio.CancelledError:
            return
        except Exception as exc:  # unexpected engine failure
            errored = True
            await self._emit(state, {"type": "error", "message": str(exc)})
        finally:
            if state.id not in self._scans:
                return
            state.status = "error" if errored else "finished"
            await self._emit(state, {"type": "done", "status": state.status})
            self._persist(state)

    def subscribe(self, scan_id: str) -> asyncio.Queue | None:
        state = self.get(scan_id)
        if not state:
            return None
        queue: asyncio.Queue = asyncio.Queue()
        # Replay history so a late subscriber sees the whole scan.
        for event in state.events:
            queue.put_nowait(event)
        state.subscribers.add(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        state = self._scans.get(scan_id)
        if state:
            state.subscribers.discard(queue)
