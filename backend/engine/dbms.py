"""DBMS error signatures and fingerprinting helpers.

These regex signatures identify which database backend produced an error
message. They are a clean-room set of well-known, publicly documented error
strings (the same *facts* many scanners key on), not copied source. Used by both
the error-based detector and the DBMS fingerprint detector.
"""

from __future__ import annotations

import re

# DBMS name -> list of case-insensitive regex signatures found in error output.
ERROR_SIGNATURES: dict[str, list[str]] = {
    "MySQL": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\bmysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"You have an error in your SQL syntax",
        r"com\.mysql\.jdbc",
        r"\bMariaDB\b.*?error",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\bpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
        r"org\.postgresql\.util\.PSQLException",
    ],
    "Microsoft SQL Server": [
        r"Driver.*? SQL[\-\_ ]*Server",
        r"OLE DB.*? SQL Server",
        r"Warning.*?\bmssql_",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
    ],
    "Oracle": [
        r"\bORA-\d{4,5}",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?\boci_",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*?\bsqlite_",
        r"\[SQLITE_ERROR\]",
        r"SQL logic error",
        r"unrecognized token:",
        r'near ".*?": syntax error',
    ],
}

# Precompile for speed.
_COMPILED: dict[str, list[re.Pattern]] = {
    dbms: [re.compile(sig, re.IGNORECASE) for sig in sigs]
    for dbms, sigs in ERROR_SIGNATURES.items()
}


def identify_dbms(text: str) -> tuple[str, str] | None:
    """Return (dbms_name, matched_signature) if any signature matches, else None."""
    for dbms, patterns in _COMPILED.items():
        for pattern in patterns:
            if pattern.search(text):
                return dbms, pattern.pattern
    return None


# Boolean-inference fingerprints for *silent* targets (no leaked errors).
#
# Each condition is written so it evaluates TRUE on exactly one DBMS and raises a
# syntax/function error (which a boolean-blind-vulnerable app reflects as FALSE)
# on the others. Ordered so the most distinctive probes run first.
BOOLEAN_FINGERPRINTS: list[tuple[str, str]] = [
    ("MySQL", "CONNECTION_ID()=CONNECTION_ID()"),
    ("PostgreSQL", "1::int=1"),
    ("Microsoft SQL Server", "@@PACK_RECEIVED=@@PACK_RECEIVED"),
    ("Oracle", "ROWNUM=ROWNUM"),
    ("SQLite", "sqlite_version()>''"),
]

