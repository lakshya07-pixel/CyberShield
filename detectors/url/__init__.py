"""
URL Phishing Detection Subsystem for Bharat AI-SoC Challenge.
"""

from .inference import detect_url_threat, get_url_model
from .advisory_adapter import build_url_advisory
from .features import extract_features, extract_indicators, FEATURE_NAMES

__all__ = [
    "detect_url_threat",
    "build_url_advisory",
    "extract_features",
    "extract_indicators",
    "get_url_model",
    "FEATURE_NAMES",
]

