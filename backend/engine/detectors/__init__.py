"""Detectors package."""

from .base import Detector, Finding, Severity
from .boolean_blind import BooleanBlindDetector
from .error_based import ErrorBasedDetector
from .fingerprint import FingerprintDetector
from .oob import OobDetector
from .stacked import StackedQueryDetector
from .time_blind import TimeBlindDetector
from .union_based import UnionBasedDetector

# Default detector set, ordered cheapest/most-informative first. Time-based
# and OOB probes come last (they wait on sleeps / collaborator callbacks).
DEFAULT_DETECTORS: list[type[Detector]] = [
    FingerprintDetector,
    ErrorBasedDetector,
    BooleanBlindDetector,
    UnionBasedDetector,
    StackedQueryDetector,
    TimeBlindDetector,
    OobDetector,
]

__all__ = [
    "Detector",
    "Finding",
    "Severity",
    "FingerprintDetector",
    "ErrorBasedDetector",
    "BooleanBlindDetector",
    "UnionBasedDetector",
    "StackedQueryDetector",
    "TimeBlindDetector",
    "OobDetector",
    "DEFAULT_DETECTORS",
]
