"""Pydantic request/response schemas for the web API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., examples=["http://testphp.vulnweb.com/listproducts.php"])
    method: str = "GET"
    params: dict[str, str] = Field(default_factory=dict, examples=[{"cat": "1"}])
    cookies: dict[str, str] = Field(default_factory=dict)

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


class ScanCreated(BaseModel):
    scan_id: str


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    url: str
    findings: list[dict]
    extracted: list[dict] = []
    dumps: list[dict] = []
    events: list[dict]
