"""In-memory scan manager: runs scans as asyncio tasks and fans out events.

Each scan keeps its full event history (so a client that connects late can
replay) plus a set of live subscriber queues (for WebSocket streaming).
Suitable for a single-process local tool; swap for a task queue + store if you
ever run this as a shared service.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from engine import AuditLog, ScanConfig, Scanner, Scope
from engine.target import Target

from .models import ScanRequest


@dataclass
class ScanState:
    id: str
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    created_at: str = ""
    status: str = "pending"  # pending -> running -> finished | error
    events: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    extracted: list[dict] = field(default_factory=list)
    dumps: list[dict] = field(default_factory=list)
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    task: asyncio.Task | None = None


class ScanManager:
    def __init__(self, audit: AuditLog | None = None):
        self.audit = audit
        self._scans: dict[str, ScanState] = {}

    def get(self, scan_id: str) -> ScanState | None:
        return self._scans.get(scan_id)

    def create_scan(self, req: ScanRequest) -> str:
        scan_id = uuid.uuid4().hex[:12]
        state = ScanState(
            id=scan_id,
            url=req.url,
            method=req.method,
            params=dict(req.params),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._scans[scan_id] = state
        state.task = asyncio.create_task(self._run(state, req))
        return scan_id

    async def _emit(self, state: ScanState, event: dict) -> None:
        state.events.append(event)
        if event.get("type") == "finding":
            state.findings.append(event)
        elif event.get("type") == "extracted-data":
            state.extracted.append(event)
        elif event.get("type") == "table-dump":
            state.dumps.append(event)
        for queue in list(state.subscribers):
            await queue.put(event)

    async def _run(self, state: ScanState, req: ScanRequest) -> None:
        state.status = "running"
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
        )
        target = Target(
            url=req.url, method=req.method, params=req.params, cookies=req.cookies
        )
        scanner = Scanner(config, audit=self.audit)

        errored = False

        async def on_event(event: dict) -> None:
            nonlocal errored
            if event.get("type") == "error":
                errored = True
            await self._emit(state, event)

        try:
            await scanner.run(target, on_event)
        except Exception as exc:  # unexpected engine failure
            errored = True
            await self._emit(state, {"type": "error", "message": str(exc)})
        finally:
            state.status = "error" if errored else "finished"
            await self._emit(state, {"type": "done", "status": state.status})

    def subscribe(self, scan_id: str) -> asyncio.Queue | None:
        state = self._scans.get(scan_id)
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
