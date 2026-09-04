"""Serialize a dumped table into CSV, JSON, or HTML for download.

A "dump" here is the dict produced by ``engine.extraction.TableDump.to_dict``:
``{"table", "columns", "rows", "row_count", "truncated"}``.
"""

from __future__ import annotations

import csv
import io
import json
from html import escape

# format -> (file extension, content type)
FORMATS: dict[str, tuple[str, str]] = {
    "csv": ("csv", "text/csv; charset=utf-8"),
    "json": ("json", "application/json; charset=utf-8"),
    "html": ("html", "text/html; charset=utf-8"),
}


def to_csv(dump: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(dump.get("columns", []))
    for row in dump.get("rows", []):
        writer.writerow(row)
    return buf.getvalue()


def to_json(dump: dict) -> str:
    columns = dump.get("columns", [])
    records = [dict(zip(columns, row)) for row in dump.get("rows", [])]
    payload = {
        "table": dump.get("table"),
        "columns": columns,
        "row_count": dump.get("row_count", len(records)),
        "truncated": dump.get("truncated", False),
        "rows": records,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_html(dump: dict) -> str:
    table = escape(str(dump.get("table", "")))
    columns = dump.get("columns", [])
    rows = dump.get("rows", [])
    row_count = dump.get("row_count", len(rows))
    truncated = dump.get("truncated", False)

    head = "".join(f"<th>{escape(str(c))}</th>" for c in columns)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{escape(str(c))}</td>" for c in row)
        body_rows.append(f"<tr>{cells}</tr>")
    body = "\n".join(body_rows)

    note = ""
    if truncated:
        note = (
            f"<p class='note'>Showing {len(rows)} of {row_count} rows "
            "(dump capped by scan configuration).</p>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{table} — Falcon Scanner</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ font-size: 1.3rem; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.9rem; }}
  th, td {{ border: 1px solid #d0d0d0; padding: 6px 10px; text-align: left; }}
  th {{ background: #f2f4f8; }}
  tr:nth-child(even) td {{ background: #fafbfc; }}
  .note {{ color: #666; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>{table} <small>({row_count} rows)</small></h1>
{note}
<table>
<thead><tr>{head}</tr></thead>
<tbody>
{body}
</tbody>
</table>
</body>
</html>"""


def render(dump: dict, fmt: str) -> str:
    if fmt == "csv":
        return to_csv(dump)
    if fmt == "json":
        return to_json(dump)
    if fmt == "html":
        return to_html(dump)
    raise ValueError(f"unsupported format: {fmt}")
