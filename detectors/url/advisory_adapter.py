"""
Advisory adapter integrating Person 2's URL Phishing classifications with
Person 3's Shared Threat Engine rules, severity, and recommendations.
"""

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Union

from threat_engine.severity import calculate_severity
from threat_engine.rules import get_threat_explanation, get_indicator_explanation
from threat_engine.recommendations import get_recommendation


def build_url_advisory(
    threat_result: Dict[str, Any],
    url_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Constructs a unified cybersecurity threat advisory from a URL Phishing
    threat result and Person 3's threat engine functions.

    Args:
        threat_result: Dictionary matching the unified ThreatResult schema.
        url_metadata: Optional extra metadata dictionary.

    Returns:
        Structured advisory dictionary conforming to the Bharat AI-SoC standards.

    Raises:
        ValueError: If input structure or required fields are missing/malformed.
    """
    if not isinstance(threat_result, dict):
        raise ValueError(f"threat_result must be a dictionary, got {type(threat_result).__name__}")

    required_fields = ("source", "threat_type", "attack_class", "severity", "confidence")
    missing = [f for f in required_fields if f not in threat_result]
    if missing:
        raise ValueError(f"Missing required field(s) in threat_result: {', '.join(missing)}")

    source = threat_result["source"]
    threat_type = threat_result["threat_type"]
    attack_class = threat_result["attack_class"]
    detector_severity = threat_result["severity"]
    confidence = float(threat_result["confidence"])
    raw_indicators = threat_result.get("indicators", [])

    if threat_type not in ("safe", "phishing", "unknown", "review"):
        raise ValueError(f"Unsupported URL threat_type: '{threat_type}'. Must be 'safe' or 'phishing'.")

    # Clean indicators
    indicators: List[str] = [str(item) for item in raw_indicators] if isinstance(raw_indicators, (list, tuple)) else []

    # Metadata assembly
    metadata = dict(threat_result.get("metadata", {}))
    if url_metadata:
        metadata.update(url_metadata)
    metadata["detector_severity"] = detector_severity
    metadata["attack_class"] = attack_class

    timestamp = threat_result.get("timestamp") or datetime.now(timezone.utc).isoformat()

    # Route logic: Benign vs Phishing
    if threat_type == "safe":
        # Benign URL: apply routing guard to avoid Person 3's alarmist fallback
        severity = "low"
        threat_explanation = "Routine web traffic; no phishing indicators detected in URL."
        indicator_explanations: List[str] = []
        recommendation = "No action required. The URL conforms to standard operational web parameters."
    elif threat_type == "phishing":
        # Phishing threat: calculate severity using Person 3 policy
        severity = calculate_severity(confidence)
        threat_explanation = get_threat_explanation(threat_type, indicators)
        indicator_explanations = get_indicator_explanation(indicators)
        recommendation = get_recommendation(threat_type)
    else:
        # Unknown / Review
        severity = "low"
        threat_explanation = "URL input is unverified or ambiguous; manual review recommended."
        indicator_explanations = []
        recommendation = "Exercise caution before accessing unverified web addresses."

    return {
        "source": source,
        "threat_type": threat_type,
        "attack_class": attack_class,
        "severity": severity,
        "confidence": confidence,
        "indicators": indicators,
        "threat_explanation": threat_explanation,
        "indicator_explanations": indicator_explanations,
        "recommendation": recommendation,
        "metadata": metadata,
        "timestamp": timestamp,
    }

