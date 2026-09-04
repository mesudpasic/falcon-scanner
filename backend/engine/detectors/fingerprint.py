"""DBMS fingerprint detector.

Once a parameter looks injectable, knowing *which* database is behind it drives
every later step (payload dialects, functions, privilege escalation paths). This
detector provokes a database error and identifies the backend from the error
signature, reporting it as an informational finding.

This is intentionally the lightweight, error-signature approach. Boolean-based
version-string fingerprinting (e.g. probing @@version vs version()) is a natural
future enhancement for targets that don't leak errors.
"""

from __future__ import annotations

from ..dbms import identify_dbms
from ..http_client import HttpClient
from ..target import Target
from .base import Detector, Finding, Severity

_PROBES = ["'", '"', "')", "\\", "'-- -"]


class FingerprintDetector(Detector):
    name = "dbms-fingerprint"

    async def test_parameter(
        self, client: HttpClient, target: Target, param: str
    ) -> list[Finding]:
        base_value = target.params.get(param, "")

        baseline = await self._request(client, target, param, base_value)
        if identify_dbms(baseline.text):
            return []  # page already shows a DB error; not attributable to us

        for probe in _PROBES:
            resp = await self._request(client, target, param, base_value + probe)
            match = identify_dbms(resp.text)
            if match:
                dbms, signature = match
                return [
                    Finding(
                        technique=self.name,
                        parameter=param,
                        severity=Severity.INFO,
                        payload=base_value + probe,
                        evidence=(
                            f"Backend database identified as {dbms} "
                            f"(matched signature: {signature})."
                        ),
                        confidence=0.85,
                        detail={"dbms": dbms},
                    )
                ]

        return []
