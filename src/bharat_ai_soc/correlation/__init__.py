"""
Bharat AI-SoC Cross-Channel Threat Correlation Module.
Provides deterministic correlation of security observations across SMS, URL, and Network IDS channels.
"""

from .normalizer import (
    normalize_domain,
    normalize_ip,
    normalize_phone,
    extract_and_normalize_indicators
)
from .models import (
    SEVERITY_ORDER,
    UnifiedIncidentRecord,
    SharedIndicatorMatch,
    canonical_json,
    compute_incident_sha256,
    verify_incident_integrity
)
from .engine import CorrelationEngine
from .summary_formatter import format_judge_summary, sanitize_text

__all__ = [
    "CorrelationEngine",
    "UnifiedIncidentRecord",
    "SharedIndicatorMatch",
    "normalize_domain",
    "normalize_ip",
    "normalize_phone",
    "extract_and_normalize_indicators",
    "canonical_json",
    "compute_incident_sha256",
    "verify_incident_integrity",
    "SEVERITY_ORDER",
    "format_judge_summary",
    "sanitize_text"
]

