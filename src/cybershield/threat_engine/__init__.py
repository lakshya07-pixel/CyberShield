"""
Unified threat engine interface bridging to Person 3's Shared Threat Engine functions.
Preserves Person 3's implementation in person3/ without modifying original files.
"""

from threat_engine.severity import calculate_severity
from threat_engine.rules import get_threat_explanation, get_indicator_explanation
from threat_engine.recommendations import get_recommendation
from schemas import create_threat_result

from detectors.network.advisory_adapter import build_network_advisory
from detectors.url.advisory_adapter import build_url_advisory
from detectors.sms.advisory_adapter import build_sms_advisory

__all__ = [
    "calculate_severity",
    "get_threat_explanation",
    "get_indicator_explanation",
    "get_recommendation",
    "create_threat_result",
    "build_network_advisory",
    "build_url_advisory",
    "build_sms_advisory",
]
