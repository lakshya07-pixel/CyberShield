"""
Bharat AI-SoC Challenge: Core Package
Cybersecurity Network Intrusion Detection System + Shared Threat Engine
"""

__version__ = "1.0.0"
__author__ = "Bharat AI-SoC Team"

from detectors.network.inference import detect_network_threat
from detectors.network.schemas import ThreatResult
from detectors.network.advisory_adapter import build_network_advisory

__all__ = [
    "detect_network_threat",
    "ThreatResult",
    "build_network_advisory",
]

