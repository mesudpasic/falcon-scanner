"""Boolean-based blind SQL injection detector.

Idea: if a parameter is injected into a SQL query, then appending a condition
that is always TRUE should yield a page (nearly) identical to the original,
while an always-FALSE condition should yield a materially different page. If we
observe that TRUE looks like the baseline and FALSE clearly differs, the
parameter is very likely injectable.

We test several injection contexts (numeric, single-quoted, double-quoted)
because we don't know how the value is embedded in the query.
"""

from __future__ import annotations

from difflib import SequenceMatcher

from ..http_client import HttpClient
from ..target import Target
from .base import Detector, Finding, Severity

# (label, true_suffix, false_suffix) for each context we probe.
_CONTEXTS = [
    ("numeric", " AND 1=1", " AND 1=2"),
    ("single-quote", "' AND '1'='1", "' AND '1'='2"),
    ("double-quote", '" AND "1"="1', '" AND "1"="2'),
]

# How similar two pages must be to count as "the same", and how different to
# count as "clearly different". Tuned conservatively to limit false positives.
_SAME_THRESHOLD = 0.98
_DIFF_MARGIN = 0.05


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


class BooleanBlindDetector(Detector):
    name = "boolean-blind"

    async def test_parameter(
        self, client: HttpClient, target: Target, param: str
    ) -> list[Finding]:
        base_value = target.params.get(param, "")

        async def fetch(value: str) -> str:
            return (await self._request(client, target, param, value)).text

        baseline = await fetch(base_value)

        for label, true_suffix, false_suffix in _CONTEXTS:
            true_page = await fetch(base_value + true_suffix)
            false_page = await fetch(base_value + false_suffix)

            true_sim = _similarity(baseline, true_page)
            false_sim = _similarity(baseline, false_page)

            # TRUE resembles baseline, FALSE clearly diverges from both.
            if (
                true_sim >= _SAME_THRESHOLD
                and false_sim < true_sim - _DIFF_MARGIN
            ):
                confidence = min(1.0, (true_sim - false_sim) + 0.5)
                return [
                    Finding(
                        technique=self.name,
                        parameter=param,
                        severity=Severity.HIGH,
                        payload=f"{base_value}{true_suffix}  /  {base_value}{false_suffix}",
                        evidence=(
                            f"{label} context: TRUE page matched baseline "
                            f"(similarity {true_sim:.3f}) while FALSE page diverged "
                            f"(similarity {false_sim:.3f})."
                        ),
                        confidence=confidence,
                        detail={"context": label, "base_value": base_value},
                    )
                ]

        return []
