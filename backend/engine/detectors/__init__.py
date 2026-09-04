"""Detectors package."""

from .base import Detector, Finding, Severity
from .boolean_blind import BooleanBlindDetector
from .error_based import ErrorBasedDetector
from .fingerprint import FingerprintDetector
from .time_blind import TimeBlindDetector
from .union_based import UnionBasedDetector

# Default detector set, ordered cheapest/most-informative first, with the slow
# time-based technique last.
DEFAULT_DETECTORS: list[type[Detector]] = [
    FingerprintDetector,
    ErrorBasedDetector,
    BooleanBlindDetector,
    UnionBasedDetector,
    TimeBlindDetector,
]

__all__ = [
    "Detector",
    "Finding",
    "Severity",
    "FingerprintDetector",
    "ErrorBasedDetector",
    "BooleanBlindDetector",
    "UnionBasedDetector",
    "TimeBlindDetector",
    "DEFAULT_DETECTORS",
]
