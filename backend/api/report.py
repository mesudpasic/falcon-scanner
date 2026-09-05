"""Renders a scan into a self-contained, downloadable HTML report.

The output is a single HTML file with inline CSS (no external assets), so it can
be saved, emailed, or archived and still render anywhere.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manager import ScanState

_SEV_COLORS = {
    "info": "#58a6ff",
    "low": "#3fb950",
    "medium": "#d29922",
    "high": "#f85149",
    "critical": "#ff5c8a",
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _severity_summary(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _finding_rows(findings: list[dict]) -> str:
    if not findings:
        return (
            '<tr><td colspan="5" class="empty">No SQL injection was detected in '
            "this scan.</td></tr>"
        )
    rows = []
    # Show most severe first.
    ordered = sorted(
        findings,
        key=lambda f: _SEV_ORDER.index(f.get("severity", "info"))
        if f.get("severity") in _SEV_ORDER
        else len(_SEV_ORDER),
    )
    for f in ordered:
        sev = f.get("severity", "info")
        color = _SEV_COLORS.get(sev, "#8b949e")
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{color}">{escape(sev)}</span></td>'
            f"<td>{escape(str(f.get('technique', '')))}</td>"
            f"<td><code>{escape(str(f.get('parameter', '')))}</code></td>"
            f"<td>{escape(str(f.get('confidence', '')))}</td>"
            f"<td><div class='evidence'>{escape(str(f.get('evidence', '')))}</div>"
            f"<div class='payload'>{escape(str(f.get('payload', '')))}</div></td>"
            "</tr>"
        )
    return "\n".join(rows)


def _params_html(params: dict) -> str:
    if not params:
        return "<em>none</em>"
    return ", ".join(
        f"<code>{escape(str(k))}={escape(str(v))}</code>" for k, v in params.items()
    )


def _extracted_html(extracted: list[dict]) -> str:
    if not extracted:
        return ""
    blocks = []
    for item in extracted:
        rows = "".join(
            f"<tr><td><code>{escape(str(k))}</code></td>"
            f"<td class='exval'>{escape(str(v))}</td></tr>"
            for k, v in (item.get("values") or {}).items()
        )
        tables = item.get("tables") or []
        databases = item.get("databases") or []
        schemas = item.get("schemas") or []
        extra_bits = []
        if databases:
            extra_bits.append(
                "<div class='tables'><strong>Databases:</strong> "
                + ", ".join(f"<code>{escape(str(d))}</code>" for d in databases)
                + "</div>"
            )
        if schemas:
            extra_bits.append(
                "<div class='tables'><strong>Schemas:</strong> "
                + ", ".join(f"<code>{escape(str(s))}</code>" for s in schemas)
                + "</div>"
            )
        tables_html = (
            (
                "<div class='tables'><strong>Tables:</strong> "
                + ", ".join(f"<code>{escape(str(t))}</code>" for t in tables)
                + "</div>"
            )
            if tables
            else ""
        )
        tables_html = "".join(extra_bits) + tables_html
        values_table = (
            f"<table class='exvalues'><tbody>{rows}</tbody></table>" if rows else ""
        )
        blocks.append(
            "<div class='exblock'>"
            f"<div class='exhead'>Parameter <code>{escape(str(item.get('parameter', '')))}</code>"
            f" &middot; via {escape(str(item.get('channel', '')))}"
            f" &middot; {escape(str(item.get('dbms', 'unknown')))}</div>"
            f"{values_table}{tables_html}"
            "</div>"
        )
    return (
        '<div class="card"><h2 style="margin-top:0;font-size:18px;">Extracted data</h2>'
        + "".join(blocks)
        + "</div>"
    )


def _dumps_html(dumps: list[dict]) -> str:
    if not dumps:
        return ""
    blocks = []
    for d in dumps:
        columns = d.get("columns") or []
        rows = d.get("rows") or []
        head = "".join(f"<th>{escape(str(c))}</th>" for c in columns)
        body = "".join(
            "<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in row) + "</tr>"
            for row in rows
        )
        count_note = f"{len(rows)}"
        if d.get("truncated"):
            count_note += f" of {d.get('row_count', len(rows))} (capped)"
        blocks.append(
            "<div class='exblock'>"
            f"<div class='exhead'><code>{escape(str(d.get('table', '')))}</code>"
            f" &middot; {escape(count_note)} rows</div>"
            f"<div class='dumpwrap'><table class='dumptable'>"
            f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
            "</div>"
        )
    return (
        '<div class="card"><h2 style="margin-top:0;font-size:18px;">Database dump</h2>'
        + "".join(blocks)
        + "</div>"
    )


def render_report(state: "ScanState") -> str:
    findings = state.findings
    counts = _severity_summary(findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    summary_chips = "".join(
        f'<span class="chip" style="border-color:{_SEV_COLORS.get(sev, "#8b949e")}">'
        f'{escape(sev)}: <strong>{counts[sev]}</strong></span>'
        for sev in _SEV_ORDER
        if counts.get(sev)
    ) or '<span class="chip">no findings</span>'

    status_class = "ok" if state.status == "finished" else "warn"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SQLi Scan Report - {escape(state.id)}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
         margin: 0; background: #f6f8fa; color: #1f2328; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }}
  .muted {{ color: #656d76; font-size: 13px; }}
  .notice {{ background: #fff8c5; border: 1px solid #d4a72c; border-radius: 8px;
            padding: 12px 14px; margin: 20px 0; font-size: 13px; }}
  .card {{ background: #fff; border: 1px solid #d0d7de; border-radius: 10px;
          padding: 20px; margin-top: 20px; }}
  .meta {{ display: grid; grid-template-columns: 160px 1fr; gap: 6px 16px; font-size: 14px; }}
  .meta dt {{ color: #656d76; }}
  .meta dd {{ margin: 0; word-break: break-all; }}
  .status.ok {{ color: #1a7f37; font-weight: 600; }}
  .status.warn {{ color: #bc4c00; font-weight: 600; }}
  .chips {{ margin-top: 8px; display: flex; flex-wrap: wrap; gap: 8px; }}
  .chip {{ border: 1px solid #d0d7de; border-left-width: 4px; border-radius: 6px;
          padding: 4px 10px; font-size: 13px; background: #fff; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 14px; }}
  th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #d0d7de; vertical-align: top; }}
  th {{ color: #656d76; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }}
  .sev {{ color: #fff; font-weight: 700; font-size: 11px; text-transform: uppercase;
         padding: 2px 8px; border-radius: 999px; }}
  code {{ background: #eff1f3; padding: 1px 5px; border-radius: 4px; font-size: 13px; }}
  .evidence {{ margin-bottom: 6px; }}
  .payload {{ font-family: ui-monospace, Consolas, monospace; font-size: 12px;
             color: #6e4b00; word-break: break-all; }}
  .empty {{ color: #656d76; text-align: center; padding: 24px; }}
  .exblock {{ border: 1px solid #d0d7de; border-radius: 8px; padding: 12px; margin-bottom: 10px; }}
  .exhead {{ font-size: 13px; color: #656d76; margin-bottom: 8px; }}
  .exvalues {{ width: auto; }}
  .exvalues td {{ border-bottom: 1px solid #eaeef2; padding: 6px 12px 6px 0; }}
  .exval {{ font-family: ui-monospace, Consolas, monospace; word-break: break-all; }}
  .tables {{ font-size: 13px; margin-top: 8px; }}
  .dumpwrap {{ overflow-x: auto; }}
  .dumptable {{ font-size: 12px; }}
  .dumptable th {{ background: #f6f8fa; }}
  .dumptable td {{ font-family: ui-monospace, Consolas, monospace; white-space: nowrap; }}
  footer {{ margin-top: 32px; font-size: 12px; color: #8b949e; text-align: center; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>SQL Injection Scan Report</h1>
  <div class="muted">Generated {escape(generated)} &middot; report id {escape(state.id)}</div>

  <div class="notice">
    <strong>Authorized testing record.</strong> This report documents an
    automated SQL-injection assessment. It should only exist for a target the
    operator was authorized to test.
  </div>

  <div class="card">
    <dl class="meta">
      <dt>Target URL</dt><dd>{escape(state.url)}</dd>
      <dt>All URLs</dt><dd>{escape(", ".join(getattr(state, "urls", None) or [state.url]))}</dd>
      <dt>Method</dt><dd>{escape(state.method)}</dd>
      <dt>Parameters</dt><dd>{_params_html(state.params)}</dd>
      <dt>Started</dt><dd>{escape(state.created_at or "n/a")}</dd>
      <dt>Status</dt><dd class="status {status_class}">{escape(state.status)}</dd>
      <dt>Total findings</dt><dd>{len(findings)}</dd>
    </dl>
    <div class="chips">{summary_chips}</div>
  </div>

  <div class="card">
    <h2 style="margin-top:0;font-size:18px;">Findings</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Technique</th><th>Parameter</th><th>Confidence</th><th>Evidence &amp; payload</th></tr>
      </thead>
      <tbody>
        {_finding_rows(findings)}
      </tbody>
    </table>
  </div>

  {_extracted_html(state.extracted)}

  {_dumps_html(state.dumps)}

  <footer>Generated by Falcon Scanner v1.0.0 &middot; SETEC d.o.o. &middot; <a href="https://www.setec.ba">www.setec.ba</a> &middot; authorized use only</footer>
</div>
</body>
</html>
"""
