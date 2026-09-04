"""UNION-based SQL injection detector.

Idea: a UNION-based injection lets an attacker append their own SELECT to the
original query and have its output rendered in the page. To confirm it, we:

  1. Try a range of column counts (a UNION requires the same number of columns
     as the original query).
  2. Put a unique random marker in each column position.
  3. If any marker shows up in the response, the injected SELECT executed and its
     data was reflected — proof of a UNION-based injection, plus we learn the
     column count and which column(s) are reflected.

We probe both quoted-string and numeric injection contexts.
"""

from __future__ import annotations

import random
import string

from ..http_client import HttpClient
from ..target import Target
from .base import Detector, Finding, Severity

_MAX_COLUMNS = 10


def _marker() -> str:
    body = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"uxu{body}xux"


class UnionBasedDetector(Detector):
    name = "union-based"

    async def test_parameter(
        self, client: HttpClient, target: Target, param: str
    ) -> list[Finding]:
        base_value = target.params.get(param, "")

        # (label, prefix that closes the original value/quote)
        contexts = [
            ("quote", f"{base_value}'"),
            ("numeric", f"{base_value}"),
        ]

        for label, prefix in contexts:
            for cols in range(1, _MAX_COLUMNS + 1):
                markers = [_marker() for _ in range(cols)]
                select_list = ",".join(f"'{m}'" for m in markers)
                payload = f"{prefix} UNION ALL SELECT {select_list}-- -"

                resp = await self._request(client, target, param, payload)
                reflected = [i + 1 for i, m in enumerate(markers) if m in resp.text]
                if reflected:
                    return [
                        Finding(
                            technique=self.name,
                            parameter=param,
                            severity=Severity.CRITICAL,
                            payload=payload,
                            evidence=(
                                f"{label} context: a UNION SELECT with {cols} column(s) "
                                f"reflected our marker in column position(s) {reflected}, "
                                "confirming attacker-controlled data can be returned."
                            ),
                            confidence=0.95,
                            detail={
                                "context": label,
                                "columns": cols,
                                "reflected_position": reflected[0],
                                "base_value": base_value,
                            },
                        )
                    ]

        return []
