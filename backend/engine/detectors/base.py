"""Detector base classes and shared data types."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..tamper import apply_tampers

if TYPE_CHECKING:
    from ..http_client import HttpClient
    from ..target import Target


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    technique: str          # e.g. "boolean-blind", "time-blind"
    parameter: str          # the vulnerable parameter name
    severity: Severity
    payload: str            # the payload that demonstrated the issue
    evidence: str           # human-readable explanation of why we flagged it
    confidence: float       # 0..1
    detail: dict = field(default_factory=dict)  # technique metadata for exploitation

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "parameter": self.parameter,
            "severity": self.severity.value,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 3),
            "detail": self.detail,
        }


class Detector:
    """A detection technique. Subclasses probe one parameter and may yield findings."""

    name: str = "base"

    async def _request(
        self, client: "HttpClient", target: "Target", param: str, value: str
    ):
        """Send one request with ``param`` set to ``value`` (GET query or POST body)."""
        value = apply_tampers(value, target.tampers)
        params = target.mutate(param, value)
        if target.is_get():
            return await client.request(
                target.method, target.url, params=params, cookies=target.cookies
            )
        return await client.request(
            target.method, target.url, data=params, cookies=target.cookies
        )

    async def test_parameter(
        self, client: "HttpClient", target: "Target", param: str
    ) -> list[Finding]:
        raise NotImplementedError
