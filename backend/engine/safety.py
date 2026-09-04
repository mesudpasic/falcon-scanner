"""Safety layer: scope enforcement, authorization consent, and audit logging.

This is deliberately the first thing a scan touches. A tool that can find SQL
injection can cause real damage and real legal liability, so every scan must:

  1. Carry explicit operator consent ("I am authorized to test this target").
  2. Target only hosts on an allowlist.
  3. Refuse private/loopback/reserved addresses unless explicitly overridden
     (prevents SSRF-style pivoting into internal infra by accident).
  4. Be recorded to an append-only audit log.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target is not authorized by the current scope."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve a hostname to all of its IP addresses."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:  # unresolvable host
        raise ScopeError(f"Could not resolve host {host!r}: {exc}") from exc
    addrs: list[ipaddress._BaseAddress] = []
    for info in infos:
        sockaddr = info[4]
        try:
            addrs.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return addrs


@dataclass
class Scope:
    """Defines what a scan is authorized to touch.

    allowed_hosts uses shell-style globs, e.g. ["testphp.vulnweb.com",
    "*.internal.example.com"].
    """

    allowed_hosts: list[str]
    allow_private: bool = False
    consent: bool = False

    def check(self, url: str) -> None:
        """Raise ScopeError unless ``url`` is authorized. Call before any request."""
        if not self.consent:
            raise ScopeError(
                "Authorization not confirmed. The operator must confirm they are "
                "authorized to test this target before a scan can start."
            )

        host = urlparse(url).hostname
        if not host:
            raise ScopeError(f"Cannot determine host from URL: {url!r}")

        if not any(fnmatch.fnmatch(host, pat) for pat in self.allowed_hosts):
            raise ScopeError(
                f"Host {host!r} is not in the scope allowlist {self.allowed_hosts!r}."
            )

        if not self.allow_private:
            for addr in _resolve(host):
                if (
                    addr.is_private
                    or addr.is_loopback
                    or addr.is_link_local
                    or addr.is_reserved
                    or addr.is_multicast
                ):
                    raise ScopeError(
                        f"Host {host!r} resolves to non-public address {addr}. "
                        "Refusing to scan internal infrastructure. Set "
                        "allow_private=True only if you own this network."
                    )


class AuditLog:
    """Append-only JSON-lines audit log. Thread-safe."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, event: str, **fields) -> None:
        entry = {"ts": _utcnow(), "event": event, **fields}
        line = json.dumps(entry, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def tail(self, n: int = 100) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()[-n:]
        out: list[dict] = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
