"""FastAPI application exposing the scan engine to the Vue frontend.

Endpoints:
  POST /api/scans                 create + start a scan, returns scan_id
  GET  /api/scans/{id}            current status, findings, and event log
  GET  /api/scans/{id}/report     downloadable self-contained HTML report
  GET  /api/scans/{id}/dump/{t}   download a dumped table as csv|json|html
  WS   /api/scans/{id}/stream     live event stream (progress + findings)
  GET  /api/audit                 tail of the audit log
  GET  /api/health                liveness probe
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response

from engine import AuditLog

from .exporters import FORMATS, render
from .manager import ScanManager
from .report import render_report
from .models import ScanCreated, ScanRequest, ScanStatus

AUDIT_PATH = Path(__file__).resolve().parent.parent / "data" / "audit.log.jsonl"

app = FastAPI(title="Falcon Scanner API", version="1.0.0")

# Vue dev server runs on a different origin during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

audit = AuditLog(AUDIT_PATH)
manager = ScanManager(audit=audit)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/scans", response_model=ScanCreated)
async def create_scan(req: ScanRequest) -> ScanCreated:
    if not req.consent:
        raise HTTPException(
            status_code=400,
            detail="consent=true is required: confirm you are authorized to test this target.",
        )
    if not req.allowed_hosts:
        raise HTTPException(
            status_code=400,
            detail="allowed_hosts must list at least one host you are authorized to scan.",
        )
    scan_id = manager.create_scan(req)
    return ScanCreated(scan_id=scan_id)


@app.get("/api/scans/{scan_id}", response_model=ScanStatus)
async def get_scan(scan_id: str) -> ScanStatus:
    state = manager.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="scan not found")
    return ScanStatus(
        scan_id=state.id,
        status=state.status,
        url=state.url,
        findings=state.findings,
        extracted=state.extracted,
        dumps=state.dumps,
        events=state.events,
    )


@app.get("/api/scans/{scan_id}/report", response_class=HTMLResponse)
async def download_report(scan_id: str) -> HTMLResponse:
    state = manager.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="scan not found")
    html = render_report(state)
    filename = f"sqli-report-{state.id}.html"
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scans/{scan_id}/dump/{table}")
async def download_dump(scan_id: str, table: str, format: str = "csv") -> Response:
    state = manager.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="scan not found")

    fmt = format.lower()
    if fmt not in FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported format '{format}'; use one of: {', '.join(FORMATS)}",
        )

    dump = next((d for d in state.dumps if d.get("table") == table), None)
    if dump is None:
        raise HTTPException(status_code=404, detail=f"no dumped table named '{table}'")

    ext, content_type = FORMATS[fmt]
    body = render(dump, fmt)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in table) or "table"
    filename = f"{safe}.{ext}"
    return Response(
        content=body,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.websocket("/api/scans/{scan_id}/stream")
async def stream_scan(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    queue = manager.subscribe(scan_id)
    if queue is None:
        await websocket.send_json({"type": "error", "message": "scan not found"})
        await websocket.close()
        return
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event.get("type") == "done":
                break
    except WebSocketDisconnect:
        pass
    finally:
        manager.unsubscribe(scan_id, queue)


@app.get("/api/audit")
async def get_audit(limit: int = 100) -> dict:
    return {"entries": audit.tail(limit)}
