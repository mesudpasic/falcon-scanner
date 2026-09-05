"""Out-of-band collaborator: unique tokens + an in-process hit inbox.

OOB detection only works when the *database server* (not the scanner) can
reach a callback the operator controls. Two modes:

  * **HTTP callback** — payloads hit ``{callback_base}/api/oob/{token}``.
    The FastAPI route records the token here; the detector then confirms.
  * **DNS domain** — payloads trigger a lookup of ``{token}.{domain}``.
    We cannot see that lookup from inside this process, so the detector
    reports the token for the operator to check in their collaborator.

The inbox is process-local (one scanner instance). Tokens are short-lived
and unguessable enough for a local authorized-testing tool.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field


@dataclass
class OobHit:
    token: str
    received_at: float
    source: str = ""
    method: str = ""


@dataclass
class OobInbox:
    _hits: dict[str, OobHit] = field(default_factory=dict)

    def mint(self) -> str:
        return secrets.token_hex(8)

    def record(self, token: str, *, source: str = "", method: str = "") -> None:
        token = (token or "").strip().lower()
        if not token:
            return
        self._hits[token] = OobHit(
            token=token,
            received_at=time.time(),
            source=source,
            method=method,
        )

    def seen(self, token: str) -> bool:
        return token.lower() in self._hits

    def pop(self, token: str) -> OobHit | None:
        return self._hits.pop(token.lower(), None)


# Process-wide inbox the API route and the OOB detector share.
INBOX = OobInbox()


def callback_url(base: str, token: str) -> str:
    """Join ``base`` (scanner origin or a tunnel) with the OOB sink path."""
    root = (base or "").rstrip("/")
    return f"{root}/api/oob/{token}"
