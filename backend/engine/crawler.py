"""In-scope crawler that turns pages and forms into scan Targets.

The crawler is deliberately conservative: it only follows links and forms
whose host passes the same ``Scope`` gate as the rest of the engine, caps
depth and page count, and never leaves the allowlist. Query-string keys and
form field names become the parameters the detectors later mutate.
"""

from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from .http_client import HttpClient
from .safety import Scope, ScopeError
from .target import Target

# Paths that are almost never worth injecting into (logout / static).
_SKIP_PATH_FRAGMENTS = (
    "logout",
    "log-out",
    "signout",
    "sign-out",
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".pdf",
    ".zip",
)


class _PageParser(HTMLParser):
    """Collect same-document links and forms from one HTML page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and ad.get("href"):
            self.links.append(ad["href"])
        elif tag == "form":
            self._form = {
                "action": ad.get("action", ""),
                "method": (ad.get("method") or "GET").upper(),
                "inputs": {},
            }
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            itype = (ad.get("type") or "text").lower()
            if itype in {"submit", "button", "image", "reset", "file"}:
                return
            name = ad.get("name")
            if name:
                self._form["inputs"][name] = ad.get("value") or "1"
        elif tag == "option" and self._form is not None:
            # First option value becomes a usable baseline for a <select>.
            pass

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    # Drop fragments; keep query (it is how we discover GET params).
    return urlunparse(parsed._replace(fragment=""))


def _should_skip(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(frag in path for frag in _SKIP_PATH_FRAGMENTS)


def _query_params(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    out: dict[str, str] = {}
    for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
        if key:
            out[key] = values[0] if values else "1"
    return out


def _page_url(url: str) -> str:
    """URL without the query string — the endpoint we will request."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def target_from_url(
    url: str,
    *,
    method: str = "GET",
    extra_params: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> Target:
    """Build a Target, folding any query-string keys into ``params``."""
    params = _query_params(url)
    if extra_params:
        params.update(extra_params)
    return Target(
        url=_page_url(url) if urlparse(url).query else url,
        method=method,
        params=params,
        cookies=dict(cookies or {}),
    )


def _in_scope(scope: Scope, url: str) -> bool:
    try:
        scope.check(url)
        return True
    except ScopeError:
        return False


async def crawl(
    client: HttpClient,
    seeds: list[str],
    scope: Scope,
    *,
    cookies: dict[str, str] | None = None,
    extra_params: dict[str, str] | None = None,
    max_depth: int = 2,
    max_pages: int = 50,
) -> list[Target]:
    """BFS-crawl ``seeds`` and return de-duplicated injectable Targets."""
    cookies = dict(cookies or {})
    extra_params = dict(extra_params or {})
    seen_pages: set[str] = set()
    seen_targets: set[tuple[str, str, tuple[str, ...]]] = set()
    found: list[Target] = []
    queue: deque[tuple[str, int]] = deque()

    for seed in seeds:
        if _in_scope(scope, seed) and not _should_skip(seed):
            queue.append((_normalize_url(seed), 0))

    def _add_target(url: str, method: str, params: dict[str, str]) -> None:
        if extra_params:
            params = {**params, **extra_params}
        if not params:
            return
        key = (method.upper(), _page_url(url), tuple(sorted(params)))
        if key in seen_targets:
            return
        seen_targets.add(key)
        found.append(
            Target(
                url=_page_url(url),
                method=method.upper(),
                params=params,
                cookies=cookies,
            )
        )

    while queue and len(seen_pages) < max_pages:
        url, depth = queue.popleft()
        page = _page_url(url)
        if page in seen_pages:
            # Still harvest this URL's own query params.
            qs = _query_params(url)
            if qs:
                _add_target(url, "GET", qs)
            continue
        seen_pages.add(page)

        qs = _query_params(url)
        if qs:
            _add_target(url, "GET", qs)

        if depth >= max_depth:
            continue

        try:
            resp = await client.request("GET", url, cookies=cookies)
        except Exception:
            continue

        ctype = ""
        for k, v in resp.headers.items():
            if k.lower() == "content-type":
                ctype = v.lower()
                break
        if ctype and "html" not in ctype and "xml" not in ctype:
            continue

        parser = _PageParser()
        try:
            parser.feed(resp.text or "")
            parser.close()
        except Exception:
            continue

        for href in parser.links:
            absolute = _normalize_url(urljoin(url, href))
            if _should_skip(absolute) or not _in_scope(scope, absolute):
                continue
            child_qs = _query_params(absolute)
            if child_qs:
                _add_target(absolute, "GET", child_qs)
            if _page_url(absolute) not in seen_pages:
                queue.append((absolute, depth + 1))

        for form in parser.forms:
            action = _normalize_url(urljoin(url, form.get("action") or url))
            if _should_skip(action) or not _in_scope(scope, action):
                continue
            method = (form.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                method = "GET"
            fields = dict(form.get("inputs") or {})
            # A GET form's action may also carry query params.
            if method == "GET":
                fields = {**_query_params(action), **fields}
            _add_target(action, method, fields)

    return found
