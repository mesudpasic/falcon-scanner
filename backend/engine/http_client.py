"""Async HTTP client wrapper with rate limiting and consistent timing.

Wraps httpx.AsyncClient so detectors get a small, stable surface: send a
request built from a Target + a mutated parameter value, and get back a
Response carrying the elapsed time we measured ourselves (needed for
time-based detection).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx


@dataclass
class Response:
    status_code: int
    text: str
    elapsed: float  # seconds, measured locally
    headers: dict


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 30.0,
        rate_limit_per_sec: float = 10.0,
        headers: dict | None = None,
        proxy: str | None = None,
        verify_tls: bool = True,
    ):
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers=headers or {"User-Agent": "sqli-scanner/0.1 (+authorized-testing-only)"},
            proxy=proxy,
            verify=verify_tls,
            follow_redirects=True,
        )
        self._min_interval = 1.0 / rate_limit_per_sec if rate_limit_per_sec > 0 else 0.0
        self._last_request = 0.0
        self._throttle_lock = asyncio.Lock()

    async def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._throttle_lock:
            wait = self._min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        cookies: dict | None = None,
    ) -> Response:
        await self._throttle()
        start = time.perf_counter()
        resp = await self._client.request(
            method.upper(), url, params=params, data=data, cookies=cookies
        )
        elapsed = time.perf_counter() - start
        return Response(
            status_code=resp.status_code,
            text=resp.text,
            elapsed=elapsed,
            headers=dict(resp.headers),
        )

    async def aclose(self) -> None:
        await self._client.aclose()
