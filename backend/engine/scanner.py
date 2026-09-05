"""Scan orchestration: ties safety, HTTP, and detectors together.

The scanner is UI-independent. It reports progress by calling an async
``on_event`` callback with plain dicts, so the same engine drives the CLI, the
web API's WebSocket stream, or tests.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import urlparse

from .collaborator import DnsCollaborator, open_dns_collaborator
from .crawler import crawl, target_from_url
from .detectors import DEFAULT_DETECTORS
from .detectors.base import Detector, Finding
from .extraction import Extractor
from .http_client import HttpClient
from .safety import AuditLog, Scope, ScopeError
from .tamper import DEFAULT_WAF_TAMPERS
from .target import Target
from .waf import detect_waf

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
    crawl: bool = False
    crawl_depth: int = 2
    crawl_max_pages: int = 50
    detect_waf: bool = True
    tampers: list[str] = field(default_factory=list)
    auto_tamper: bool = True
    concurrency: int = 3
    oob_callback: str = ""
    oob_domain: str = ""
    oob_poll_url: str = ""
    oob_poll_auth: str = ""
    oob_interactsh: str = ""
    oob_interactsh_token: str = ""
    blind_enumerate: bool = True
    max_blind_catalog_len: int = 256


class Scanner:
    def __init__(self, config: ScanConfig, audit: AuditLog | None = None):
        self.config = config
        self.audit = audit

    def _decorate(self, target: Target) -> Target:
        """Copy scan-wide evasion / OOB settings onto a target."""
        tampers = list(target.tampers or self.config.tampers)
        return Target(
            url=target.url,
            method=target.method,
            params=dict(target.params),
            cookies=dict(target.cookies),
            tampers=tampers,
            oob_callback=target.oob_callback or self.config.oob_callback,
            oob_domain=target.oob_domain or self.config.oob_domain,
            oob_poll_url=target.oob_poll_url or self.config.oob_poll_url,
            oob_poll_auth=target.oob_poll_auth or self.config.oob_poll_auth,
            oob_interactsh=target.oob_interactsh or self.config.oob_interactsh,
            oob_interactsh_token=target.oob_interactsh_token or self.config.oob_interactsh_token,
            oob_collaborator=target.oob_collaborator,
        )

    async def _maybe_extract(self, client, target, param, param_findings, emit) -> None:
        """After a param's detectors run, use the best channel to extract data."""
        dicts = [f.to_dict() for f in param_findings]
        # Prefer UNION (fast), then boolean-blind, then time-blind (slowest).
        channel = (
            next((f for f in dicts if f["technique"] == "union-based"), None)
            or next((f for f in dicts if f["technique"] == "boolean-blind"), None)
            or next((f for f in dicts if f["technique"] == "time-blind"), None)
        )
        if not channel:
            return

        extractor = Extractor(
            enumerate_catalog=self.config.blind_enumerate,
            max_catalog_len=self.config.max_blind_catalog_len,
        )
        dbms = next(
            (f["detail"]["dbms"] for f in dicts if f.get("detail", {}).get("dbms")), None
        )

        # Silent target: no error leaked a DBMS name. Infer via boolean, then time.
        if dbms is None:
            bool_finding = next(
                (f for f in dicts if f["technique"] == "boolean-blind"), None
            )
            time_finding = next(
                (f for f in dicts if f["technique"] == "time-blind"), None
            )
            inferred = None
            method = ""
            if bool_finding:
                try:
                    inferred = await extractor.blind_fingerprint(
                        client, target, param, bool_finding["detail"]
                    )
                    method = "boolean"
                except Exception:
                    inferred = None
            if inferred is None and time_finding:
                try:
                    inferred = await extractor.time_fingerprint(
                        client, target, param, time_finding["detail"]
                    )
                    method = "time"
                except Exception:
                    inferred = None
            if inferred:
                dbms = inferred
                fp = {
                    "technique": "dbms-fingerprint",
                    "parameter": param,
                    "severity": "info",
                    "payload": f"{method} inference -> {inferred}",
                    "evidence": (
                        f"Backend database identified as {inferred} via {method} "
                        "inference (target did not leak an error)."
                    ),
                    "confidence": 0.8,
                    "detail": {"dbms": inferred, "method": method},
                    "url": target.url,
                }
                if self.audit:
                    self.audit.record("finding", url=target.url, **fp)
                await emit("finding", **fp)

        await emit(
            "extracting",
            parameter=param,
            channel=channel["technique"],
            dbms=dbms,
            url=target.url,
        )
        try:
            result = await extractor.extract(client, target, param, channel, dbms)
        except Exception as exc:
            await emit("extraction_error", parameter=param, message=str(exc), url=target.url)
            return

        if result and not result.is_empty():
            data = {"parameter": param, "url": target.url, **result.to_dict()}
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
                url=target.url,
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
                await emit("extraction_error", parameter=param, message=str(exc), url=target.url)
                dumps = []
            for dump in dumps:
                payload = {"parameter": param, "url": target.url, **dump.to_dict()}
                if self.audit:
                    self.audit.record(
                        "table_dump",
                        url=target.url,
                        parameter=param,
                        table=dump.table,
                        rows=len(dump.rows),
                    )
                await emit("table-dump", **payload)

    async def _scan_one(
        self,
        client: HttpClient,
        target: Target,
        emit: EventCallback,
        progress: dict,
        progress_lock: asyncio.Lock,
    ) -> list[Finding]:
        findings: list[Finding] = []
        params = target.testable_params()
        if not params:
            await emit(
                "detector_error",
                url=target.url,
                parameter="",
                detector="scanner",
                message="No parameters to test on this endpoint (add some or enable the crawler).",
            )
            return findings

        for param in params:
            param_findings: list[Finding] = []
            for detector_cls in self.config.detectors:
                detector = detector_cls()
                async with progress_lock:
                    progress["step"] += 1
                    step = progress["step"]
                    total = progress["total"]
                await emit(
                    "progress",
                    step=step,
                    total_steps=total,
                    parameter=param,
                    detector=detector.name,
                    url=target.url,
                )
                try:
                    results = await detector.test_parameter(client, target, param)
                except Exception as exc:
                    await emit(
                        "detector_error",
                        parameter=param,
                        detector=detector.name,
                        message=str(exc),
                        url=target.url,
                    )
                    continue

                for finding in results:
                    findings.append(finding)
                    param_findings.append(finding)
                    payload = {**finding.to_dict(), "url": target.url}
                    if self.audit:
                        self.audit.record("finding", url=target.url, **finding.to_dict())
                    await emit("finding", **payload)

            if self.config.extract_data:
                await self._maybe_extract(client, target, param, param_findings, emit)
        return findings

    async def run(
        self,
        target: Target | list[Target],
        on_event: EventCallback,
    ) -> list[Finding]:
        async def emit(event_type: str, **data) -> None:
            await on_event({"type": event_type, **data})

        seeds = [target] if isinstance(target, Target) else list(target)
        if not seeds:
            await emit("error", message="No target URLs were provided.")
            return []

        # --- Safety gate: nothing leaves the process until every seed is in scope ---
        for seed in seeds:
            try:
                self.config.scope.check(seed.url)
            except ScopeError as exc:
                if self.audit:
                    self.audit.record("scan_blocked", url=seed.url, reason=str(exc))
                await emit("error", message=str(exc), url=seed.url)
                return []

        if self.audit:
            self.audit.record(
                "scan_started",
                urls=[s.url for s in seeds],
                method=seeds[0].method,
                params=list(seeds[0].params.keys()),
            )

        client = HttpClient(
            timeout=self.config.timeout,
            rate_limit_per_sec=self.config.rate_limit_per_sec,
            headers=self.config.headers,
            proxy=self.config.proxy,
            verify_tls=self.config.verify_tls,
        )
        findings: list[Finding] = []
        collab: DnsCollaborator | None = None
        try:
            try:
                collab = await open_dns_collaborator(
                    interactsh=self.config.oob_interactsh,
                    interactsh_token=self.config.oob_interactsh_token,
                    poll_url=self.config.oob_poll_url,
                    poll_auth=self.config.oob_poll_auth,
                    domain=self.config.oob_domain,
                )
            except Exception as exc:
                await emit("oob_error", message=f"DNS collaborator setup failed: {exc}")
            if collab:
                if not self.config.oob_domain and collab.domain:
                    self.config.oob_domain = collab.domain
                await emit(
                    "oob_collaborator",
                    domain=collab.domain,
                    source=type(collab).__name__,
                )

            work = [self._decorate(s) for s in seeds]

            if self.config.crawl:
                await emit(
                    "crawling",
                    seeds=[s.url for s in work],
                    depth=self.config.crawl_depth,
                    max_pages=self.config.crawl_max_pages,
                )
                discovered = await crawl(
                    client,
                    [s.url for s in work],
                    self.config.scope,
                    cookies=work[0].cookies,
                    extra_params=None,
                    max_depth=self.config.crawl_depth,
                    max_pages=self.config.crawl_max_pages,
                )
                # Keep operator-supplied endpoints even if the crawl found nothing
                # extra; merge by (method, url, param-names).
                seen = {
                    (t.method.upper(), t.url, tuple(sorted(t.params))) for t in work
                }
                added = 0
                for hit in discovered:
                    key = (hit.method.upper(), hit.url, tuple(sorted(hit.params)))
                    if key in seen:
                        continue
                    seen.add(key)
                    work.append(self._decorate(hit))
                    added += 1
                await emit(
                    "crawled",
                    endpoints=len(work),
                    added=added,
                    targets=[
                        {"url": t.url, "method": t.method, "params": list(t.params)}
                        for t in work
                    ],
                )

            for item in work:
                item.oob_collaborator = collab
                if collab and collab.domain:
                    item.oob_domain = item.oob_domain or collab.domain

            if self.config.detect_waf:
                seen_hosts: set[str] = set()
                for item in work:
                    host = (urlparse(item.url).hostname or "").lower()
                    if not host or host in seen_hosts:
                        continue
                    seen_hosts.add(host)
                    await emit("waf_check", url=item.url, host=host)
                    try:
                        waf = await detect_waf(client, item)
                    except Exception as exc:
                        await emit("waf_error", url=item.url, message=str(exc))
                        continue
                    await emit("waf", url=item.url, host=host, **waf.to_dict())
                    if waf.detected:
                        fp = {
                            "technique": "waf-detected",
                            "parameter": host,
                            "severity": "info",
                            "payload": "",
                            "evidence": (
                                f"{waf.product or 'WAF'} in front of {host}: "
                                f"{waf.evidence}"
                            ),
                            "confidence": 0.85,
                            "detail": waf.to_dict(),
                            "url": item.url,
                        }
                        if self.audit:
                            self.audit.record("waf_detected", url=item.url, **waf.to_dict())
                        await emit("finding", **fp)
                        if self.config.auto_tamper and not self.config.tampers:
                            for t in work:
                                if (urlparse(t.url).hostname or "").lower() == host:
                                    t.tampers = list(DEFAULT_WAF_TAMPERS)
                            await emit(
                                "tampers",
                                url=item.url,
                                tampers=DEFAULT_WAF_TAMPERS,
                                reason="auto-enabled after WAF detection",
                            )

            detectors = self.config.detectors
            total_steps = max(
                1,
                sum(len(t.testable_params()) * len(detectors) for t in work),
            )
            progress = {"step": 0, "total": total_steps}
            progress_lock = asyncio.Lock()

            await emit(
                "scan_started",
                urls=[t.url for t in work],
                url=work[0].url,
                method=work[0].method,
                params=work[0].testable_params(),
                detectors=[d.name for d in detectors],
                total_steps=total_steps,
                concurrency=max(1, self.config.concurrency),
            )

            sem = asyncio.Semaphore(max(1, self.config.concurrency))

            async def _guarded(item: Target) -> list[Finding]:
                async with sem:
                    await emit("target_started", url=item.url, method=item.method,
                               params=item.testable_params())
                    try:
                        return await self._scan_one(
                            client, item, emit, progress, progress_lock
                        )
                    except Exception as exc:
                        await emit("error", message=str(exc), url=item.url)
                        return []
                    finally:
                        await emit("target_finished", url=item.url)

            batches = await asyncio.gather(*[_guarded(t) for t in work])
            for batch in batches:
                findings.extend(batch)
        finally:
            await client.aclose()
            if collab is not None:
                await collab.aclose()

        if self.audit:
            self.audit.record(
                "scan_finished",
                urls=[s.url for s in seeds],
                findings=len(findings),
            )
        await emit("scan_finished", findings=len(findings))
        return findings
