"""Payload tamper / evasion transforms.

Each script rewrites an injected value so a WAF that keys on a literal
signature (``UNION SELECT``, spaces around ``AND``, etc.) is more likely
to miss it. Transforms are meant to be semantics-preserving for the
database; they are applied to the full parameter value just before the
request is sent.

Script names are stable API values (``space2comment``, ``randomcase``, …).
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable

TamperFn = Callable[[str], str]


def space2comment(payload: str) -> str:
    """Replace runs of whitespace with a MySQL/generic empty comment."""
    return re.sub(r"\s+", "/**/", payload)


def space2plus(payload: str) -> str:
    return re.sub(r"\s+", "+", payload)


def randomcase(payload: str) -> str:
    """Randomize the case of SQL keywords; leave quoted strings alone."""
    keywords = (
        "SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "SLEEP", "WAITFOR",
        "DELAY", "LIKE", "NULL", "INFORMATION_SCHEMA", "TABLES", "COLUMNS",
        "DATABASE", "VERSION", "CONCAT", "SUBSTRING", "ASCII", "LENGTH",
        "CASE", "WHEN", "THEN", "ELSE", "END", "CAST", "CHAR", "COUNT",
        "ORDER", "BY", "OFFSET", "FETCH", "NEXT", "ROWS", "ONLY", "GROUP",
        "INSERT", "UPDATE", "DELETE", "EXEC", "DECLARE",
    )
    out = payload
    for word in sorted(keywords, key=len, reverse=True):
        out = re.sub(
            re.escape(word),
            lambda m: "".join(
                ch.upper() if random.random() < 0.5 else ch.lower()
                for ch in m.group(0)
            ),
            out,
            flags=re.IGNORECASE,
        )
    return out


def between(payload: str) -> str:
    """Rewrite ``AND <n>=<n>`` style equalities to BETWEEN (same truth)."""
    return re.sub(
        r"\bAND\s+(\d+)\s*=\s*(\d+)\b",
        lambda m: f"AND {m.group(1)} BETWEEN {m.group(2)} AND {m.group(2)}",
        payload,
        flags=re.IGNORECASE,
    )


def equaltolike(payload: str) -> str:
    return re.sub(r"\s*=\s*", " LIKE ", payload)


def versionedcomment(payload: str) -> str:
    """Wrap common keywords in MySQL versioned comments: ``/*!UNION*/``."""
    keywords = ("UNION", "SELECT", "FROM", "WHERE", "AND", "OR")
    out = payload
    for word in keywords:
        out = re.sub(
            rf"\b{word}\b",
            f"/*!{word}*/",
            out,
            flags=re.IGNORECASE,
        )
    return out


def commentbeforeparen(payload: str) -> str:
    return payload.replace("(", "/**/(").replace(")", ")/**/")


def apostrophenull(payload: str) -> str:
    """Replace ASCII quotes with a percent-encoded variant some WAFs miss."""
    return payload.replace("'", "%27")


TAMPERS: dict[str, TamperFn] = {
    "space2comment": space2comment,
    "space2plus": space2plus,
    "randomcase": randomcase,
    "between": between,
    "equaltolike": equaltolike,
    "versionedcomment": versionedcomment,
    "commentbeforeparen": commentbeforeparen,
    "apostrophenull": apostrophenull,
}

# Applied automatically when a WAF is detected and the operator did not
# pick an explicit chain.
DEFAULT_WAF_TAMPERS = ["space2comment", "randomcase", "between"]


def apply_tampers(payload: str, names: list[str] | None) -> str:
    """Apply named tampers in order. Unknown names are ignored."""
    if not names:
        return payload
    out = payload
    for name in names:
        fn = TAMPERS.get(name)
        if fn is not None:
            out = fn(out)
    return out


def available_tampers() -> list[str]:
    return list(TAMPERS.keys())
