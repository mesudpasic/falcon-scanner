"""Scan orchestration: ties safety, HTTP, and detectors together.

The scanner is UI-independent. It reports progress by calling an async
``on_event`` callback with plain dicts, so the same engine drives the CLI, the
web API's WebSocket stream, or tests.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from .detectors import DEFAULT_DETECTORS
from .detectors.base import Detector, Finding
from .extraction import Extractor
from .http_client import HttpClient
from .safety import AuditLog, Scope, ScopeError
from .target import Target

EventCallback = Callable[[dict], Awaitable[None]]


@dataclass
class ScanConfig:
    scope: Scope
    rate_limit_per_sec: float = 10.0
    timeout: float = 30.0
    proxy: str | None = None
    verify_tls: bool = True
    headers: dict | None = None
    extract_data: bool = True
    dump_data: bool = True
    max_dump_tables: int | None = None
    max_dump_rows: int | None = None
    detectors: list[type[Detector]] = field(default_factory=lambda: list(DEFAULT_DETECTORS))


class Scanner:
    def __init__(self, config: ScanConfig, audit: AuditLog | None = None):
        self.config = config
        self.audit = audit

    async def _maybe_extract(self, client, target, param, param_findings, emit) -> None:
        """After a param's detectors run, use the best channel to extract data."""
        dicts = [f.to_dict() for f in param_findings]
        # Prefer the UNION channel (fast, richer); fall back to boolean-blind.
        channel = next((f for f in dicts if f["technique"] == "union-based"), None) or next(
            (f for f in dicts if f["technique"] == "boolean-blind"), None
        )
        if not channel:
            return

        extractor = Extractor()
        dbms = next(
            (f["detail"]["dbms"] for f in dicts if f.get("detail", {}).get("dbms")), None
        )

        # Silent target: no error leaked a DBMS name. If we have a boolean channel,
        # infer the DBMS via boolean fingerprinting probes.
        if dbms is None:
            bool_finding = next(
                (f for f in dicts if f["technique"] == "boolean-blind"), None
            )
            if bool_finding:
                try:
                    inferred = await extractor.blind_fingerprint(
                        client, target, param, bool_finding["detail"]
                    )
                except Exception:
                    inferred = None
                if inferred:
                    dbms = inferred
                    fp = {
                        "technique": "dbms-fingerprint",
                        "parameter": param,
                        "severity": "info",
                        "payload": f"boolean inference -> {inferred}",
                        "evidence": (
                            f"Backend database identified as {inferred} via boolean "
                            "inference (target did not leak an error)."
                        ),
                        "confidence": 0.8,
                        "detail": {"dbms": inferred, "method": "boolean"},
                    }
                    if self.audit:
                        self.audit.record("finding", url=target.url, **fp)
                    await emit("finding", **fp)

        await emit(
            "extracting", parameter=param, channel=channel["technique"], dbms=dbms
        )
        try:
            result = await extractor.extract(client, target, param, channel, dbms)
        except Exception as exc:
            await emit("extraction_error", parameter=param, message=str(exc))
            return

        if result and not result.is_empty():
            data = {"parameter": param, **result.to_dict()}
            if self.audit:
                self.audit.record("extracted_data", url=target.url, **data)
            await emit("extracted-data", **data)

        # Whole-database dump: only over the UNION channel (blind row dumping is
        # impractically slow). Capped by config to bound request volume.
        if (
            self.config.dump_data
            and channel["technique"] == "union-based"
            and result
            and result.tables
        ):
            await emit(
                "dumping",
                parameter=param,
                tables=(
                    len(result.tables)
                    if self.config.max_dump_tables is None
                    else min(len(result.tables), self.config.max_dump_tables)
                ),
            )
            try:
                dumps = await extractor.dump_tables(
                    client,
                    target,
                    param,
                    channel["detail"],
                    dbms,
                    result.tables,
                    self.config.max_dump_tables,
                    self.config.max_dump_rows,
                )
            except Exception as exc:
                await emit("extraction_error", parameter=param, message=str(exc))
                dumps = []
            for dump in dumps:
                payload = {"parameter": param, **dump.to_dict()}
                if self.audit:
                    self.audit.record(
                        "table_dump",
                        url=target.url,
                        parameter=param,
                        table=dump.table,
                        rows=len(dump.rows),
                    )
                await emit("table-dump", **payload)

    async def run(self, target: Target, on_event: EventCallback) -> list[Finding]:
        async def emit(event_type: str, **data) -> None:
            await on_event({"type": event_type, **data})

        # --- Safety gate: nothing leaves the process until scope is satisfied ---
        try:
            self.config.scope.check(target.url)
        except ScopeError as exc:
            if self.audit:
                self.audit.record("scan_blocked", url=target.url, reason=str(exc))
            await emit("error", message=str(exc))
            return []

        if self.audit:
            self.audit.record(
                "scan_started",
                url=target.url,
                method=target.method,
                params=list(target.params.keys()),
            )

        params = target.testable_params()
        detectors = self.config.detectors
        total_steps = max(1, len(params) * len(detectors))
        step = 0
        findings: list[Finding] = []

        await emit(
            "scan_started",
            url=target.url,
            method=target.method,
            params=params,
            detectors=[d.name for d in detectors],
            total_steps=total_steps,
        )

        client = HttpClient(
            timeout=self.config.timeout,
            rate_limit_per_sec=self.config.rate_limit_per_sec,
            headers=self.config.headers,
            proxy=self.config.proxy,
            verify_tls=self.config.verify_tls,
        )
        try:
            for param in params:
                param_findings: list[Finding] = []
                for detector_cls in detectors:
                    detector = detector_cls()
                    step += 1
                    await emit(
                        "progress",
                        step=step,
                        total_steps=total_steps,
                        parameter=param,
                        detector=detector.name,
                    )
                    try:
                        results = await detector.test_parameter(client, target, param)
                    except Exception as exc:  # a broken detector shouldn't kill the scan
                        await emit(
                            "detector_error",
                            parameter=param,
                            detector=detector.name,
                            message=str(exc),
                        )
                        continue

                    for finding in results:
                        findings.append(finding)
                        param_findings.append(finding)
                        if self.audit:
                            self.audit.record("finding", url=target.url, **finding.to_dict())
                        await emit("finding", **finding.to_dict())

                if self.config.extract_data:
                    await self._maybe_extract(client, target, param, param_findings, emit)
        finally:
            await client.aclose()

        if self.audit:
            self.audit.record("scan_finished", url=target.url, findings=len(findings))
        await emit("scan_finished", findings=len(findings))
        return findings
