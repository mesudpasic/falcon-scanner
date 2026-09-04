"""Error-based SQL injection detector.

Idea: inject characters/sequences that break SQL syntax (a stray quote, an
unbalanced parenthesis, etc.). If the application leaks a database error message
that wasn't present in the normal response, the input is reaching the SQL parser
unsanitised — a strong sign of injectability — and the error text usually tells
us which DBMS is in use.
"""

from __future__ import annotations

from ..dbms import identify_dbms
from ..http_client import HttpClient
from ..target import Target
from .base import Detector, Finding, Severity

# Syntax-breaking suffixes appended to the parameter's baseline value.
_PROBES = ["'", '"', "')", "\")", "'))", "`", "\\"]


class ErrorBasedDetector(Detector):
    name = "error-based"

    async def test_parameter(
        self, client: HttpClient, target: Target, param: str
    ) -> list[Finding]:
        base_value = target.params.get(param, "")

        # Only count errors that appear *because* of our injection.
        baseline = await self._request(client, target, param, base_value)
        if identify_dbms(baseline.text):
            # The page already shows a DB error unprompted; can't attribute it.
            return []

        for probe in _PROBES:
            resp = await self._request(client, target, param, base_value + probe)
            match = identify_dbms(resp.text)
            if match:
                dbms, signature = match
                return [
                    Finding(
                        technique=self.name,
                        parameter=param,
                        severity=Severity.HIGH,
                        payload=base_value + probe,
                        evidence=(
                            f"Injecting {probe!r} triggered a {dbms} error "
                            f"(matched signature: {signature})."
                        ),
                        confidence=0.9,
                        detail={"dbms": dbms},
                    )
                ]

        return []
