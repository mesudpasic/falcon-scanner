"""Pydantic request/response schemas for the web API."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class ScanRequest(BaseModel):
    url: str = Field("", examples=["http://testphp.vulnweb.com/listproducts.php"])
    urls: list[str] = Field(
        default_factory=list,
        description="Additional (or alternative) target URLs; scanned in parallel.",
    )
    method: str = "GET"
    params: dict[str, str] = Field(default_factory=dict, examples=[{"cat": "1"}])
    cookies: dict[str, str] = Field(
        default_factory=dict,
        description="Session cookies forwarded with every request (name → value).",
    )

    # --- Safety / scope (required to actually run) ---
    consent: bool = Field(
        False,
        description="Operator confirms they are authorized to test this target.",
    )
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Glob allowlist of hostnames this scan may touch.",
    )
    allow_private: bool = Field(
        False, description="Permit private/loopback targets (only for networks you own)."
    )

    # --- Tuning ---
    rate_limit_per_sec: float = 10.0
    timeout: float = 30.0
    proxy: str | None = None
    verify_tls: bool = True
    concurrency: int = Field(
        3, ge=1, le=20, description="How many URLs / endpoints to scan at once."
    )
    extract_data: bool = Field(
        True,
        description="After confirming an injection, attempt to extract data (version, user, tables).",
    )
    dump_data: bool = Field(
        True,
        description="Over a UNION channel, dump table contents for the whole database.",
    )
    max_dump_tables: int | None = Field(
        None, ge=1, description="Cap the number of tables to dump; omit to dump all."
    )
    max_dump_rows: int | None = Field(
        None, ge=1, description="Cap rows pulled per table; omit to dump every row."
    )

    # --- Discovery / evasion / OOB ---
    crawl: bool = Field(
        False, description="Crawl starting URLs to auto-discover endpoints and parameters."
    )
    crawl_depth: int = Field(2, ge=0, le=6)
    crawl_max_pages: int = Field(50, ge=1, le=500)
    detect_waf: bool = Field(True, description="Fingerprint a WAF / IPS before probing.")
    tampers: list[str] = Field(
        default_factory=list,
        description="Named evasion scripts applied to every injected value.",
    )
    auto_tamper: bool = Field(
        True, description="If a WAF is detected and tampers is empty, enable a default chain."
    )
    oob_callback: str = Field(
        "",
        description="Base URL the database server can reach (e.g. http://YOUR_IP:8000).",
    )
    oob_domain: str = Field(
        "",
        description="Collaborator DNS domain (token.domain) for DNS OOB probes.",
    )
    oob_poll_url: str = Field(
        "",
        description="Burp Collaborator / custom poll URL. GET after DNS probes; confirm if the token appears.",
    )
    oob_poll_auth: str = Field(
        "",
        description="Optional Authorization value for oob_poll_url (Bearer token or raw header value).",
    )
    oob_interactsh: str = Field(
        "",
        description="Interactsh server host (e.g. oast.pro). Registers, uses its domain, polls and decrypts.",
    )
    oob_interactsh_token: str = Field(
        "",
        description="Optional Interactsh Authorization token for a private server.",
    )
    blind_enumerate: bool = Field(
        True,
        description="On a boolean-blind channel, also reconstruct database/schema/table names.",
    )
    max_blind_catalog_len: int = Field(
        256,
        ge=16,
        le=1024,
        description="Character cap for each blind-enumerated catalog list.",
    )

    @model_validator(mode="after")
    def _need_a_url(self) -> "ScanRequest":
        if not (self.url or "").strip() and not any(u.strip() for u in self.urls):
            raise ValueError("Provide url or urls.")
        return self

    def all_urls(self) -> list[str]:
        seen: list[str] = []
        for raw in [self.url, *self.urls]:
            url = (raw or "").strip()
            if url and url not in seen:
                seen.append(url)
        return seen


class ScanCreated(BaseModel):
    scan_id: str


class ScanSummary(BaseModel):
    scan_id: str
    status: str
    url: str
    urls: list[str] = []
    method: str = "GET"
    created_at: str = ""
    findings_count: int = 0


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    url: str
    urls: list[str] = []
    findings: list[dict]
    extracted: list[dict] = []
    dumps: list[dict] = []
    events: list[dict]
    waf: list[dict] = []
