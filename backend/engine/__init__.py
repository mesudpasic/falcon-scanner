"""Core SQL-injection detection engine (UI-independent)."""

from .scanner import Scanner, ScanConfig
from .safety import Scope, ScopeError, AuditLog
from .detectors.base import Finding, Severity
from .tamper import available_tampers

__all__ = [
    "Scanner",
    "ScanConfig",
    "Scope",
    "ScopeError",
    "AuditLog",
    "Finding",
    "Severity",
    "available_tampers",
]
