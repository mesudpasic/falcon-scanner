"""DNS OOB confirmation via Interactsh or a generic collaborator poll URL.

Interactsh (ProjectDiscovery) — register an RSA key, fire ``{token}.{id}.{server}``
lookups, then poll and decrypt. Burp Collaborator / custom sinks — GET a
polling URL the operator already has and search the body for the token.

This talks to the *operator's* collaborator, not the scan target, so it uses
its own HTTP client (no target rate-limit, no cookies).
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import string
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

_ALPHANUM = string.ascii_lowercase + string.digits


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALPHANUM) for _ in range(n))


def _server_origin(server: str) -> str:
    raw = (server or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = parsed.netloc or parsed.path.split("/")[0]
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host}"


def _server_host(server: str) -> str:
    raw = (server or "").strip()
    if "://" in raw:
        return urlparse(raw).hostname or ""
    return raw.split("/")[0].split(":")[0]


@dataclass
class DnsHit:
    token: str
    evidence: str
    source: str


class DnsCollaborator:
    """Common surface the OOB detector uses for DNS confirmation."""

    domain: str = ""

    def hostname(self, token: str) -> str:
        raise NotImplementedError

    async def seen(self, token: str, *, timeout: float = 8.0) -> DnsHit | None:
        raise NotImplementedError

    async def aclose(self) -> None:
        return None


class InteractshCollaborator(DnsCollaborator):
    """Register + poll a ProjectDiscovery Interactsh server."""

    def __init__(self, server: str, auth_token: str = ""):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        self.origin = _server_origin(server)
        self.server_host = _server_host(server)
        self.auth_token = (auth_token or "").strip()
        self.correlation_id = _rand(20)
        self.secret_key = _rand(8)
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_b64 = base64.b64encode(pub).decode("ascii")
        self.domain = f"{self.correlation_id}.{self.server_host}"
        self._http: httpx.AsyncClient | None = None
        self._registered = False

    def hostname(self, token: str) -> str:
        return f"{token}.{self.domain}"

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = self.auth_token
        return headers

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        return self._http

    async def register(self) -> None:
        if self._registered:
            return
        client = await self._client()
        body = {
            "public-key": self.public_key_b64,
            "secret-key": self.secret_key,
            "correlation-id": self.correlation_id,
        }
        resp = await client.post(
            f"{self.origin}/register",
            json=body,
            headers=self._headers(),
        )
        resp.raise_for_status()
        self._registered = True

    def _decrypt_interactions(self, payload: dict) -> list[str]:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        aes_b64 = payload.get("aes_key") or ""
        blobs = list(payload.get("data") or [])
        if not aes_b64 or not blobs:
            return []
        try:
            aes_key = self._private_key.decrypt(
                base64.b64decode(aes_b64),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception:
            return []
        texts: list[str] = []
        for item in blobs:
            try:
                raw = base64.b64decode(item)
                iv, ct = raw[:16], raw[16:]
                decryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
                plain = decryptor.update(ct) + decryptor.finalize()
                texts.append(plain.decode("utf-8", errors="replace"))
            except Exception:
                continue
        return texts

    async def _poll_once(self) -> list[str]:
        client = await self._client()
        resp = await client.get(
            f"{self.origin}/poll",
            params={"id": self.correlation_id, "secret": self.secret_key},
            headers=self._headers(),
        )
        if resp.status_code >= 400:
            return []
        try:
            payload = resp.json()
        except Exception:
            return [resp.text or ""]
        if not isinstance(payload, dict):
            return [resp.text or ""]
        decrypted = self._decrypt_interactions(payload)
        if decrypted:
            return decrypted
        # If decryption failed, still search the raw JSON (some servers
        # echo hostnames in extras / error text).
        return [json.dumps(payload)]

    async def seen(self, token: str, *, timeout: float = 8.0) -> DnsHit | None:
        needle = (token or "").lower()
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            for blob in await self._poll_once():
                if needle and needle in blob.lower():
                    return DnsHit(
                        token=token,
                        evidence=blob[:400],
                        source="interactsh",
                    )
            if asyncio.get_event_loop().time() >= deadline:
                return None
            await asyncio.sleep(1.5)

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None


class PollUrlCollaborator(DnsCollaborator):
    """GET a Burp / custom poll URL and look for the probe token in the body."""

    def __init__(self, poll_url: str, domain: str = "", auth: str = ""):
        self.poll_url = poll_url.strip()
        self.domain = (domain or "").lstrip(".")
        self.auth = (auth or "").strip()
        self._http: httpx.AsyncClient | None = None

    def hostname(self, token: str) -> str:
        if self.domain:
            return f"{token}.{self.domain}"
        return token

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        return self._http

    async def _poll_once(self) -> str:
        headers: dict[str, str] = {}
        if self.auth:
            headers["Authorization"] = (
                self.auth if " " in self.auth else f"Bearer {self.auth}"
            )
        client = await self._client()
        resp = await client.get(self.poll_url, headers=headers)
        return resp.text or ""

    async def seen(self, token: str, *, timeout: float = 8.0) -> DnsHit | None:
        needle = (token or "").lower()
        if not needle or not self.poll_url:
            return None
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            body = await self._poll_once()
            if needle in body.lower():
                return DnsHit(token=token, evidence=body[:400], source="poll-url")
            if asyncio.get_event_loop().time() >= deadline:
                return None
            await asyncio.sleep(1.5)

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None


async def open_dns_collaborator(
    *,
    interactsh: str = "",
    interactsh_token: str = "",
    poll_url: str = "",
    poll_auth: str = "",
    domain: str = "",
) -> DnsCollaborator | None:
    """Build the best available DNS collaborator, or None if none is configured."""
    if interactsh.strip():
        client = InteractshCollaborator(interactsh, interactsh_token)
        await client.register()
        return client
    if poll_url.strip() and domain.strip():
        return PollUrlCollaborator(poll_url, domain=domain, auth=poll_auth)
    return None
