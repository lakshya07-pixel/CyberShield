"""
Advisory adapter integrating Person 2's SMS Scam classifications with
Person 3's Shared Threat Engine rules, severity, and recommendations.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from threat_engine.severity import calculate_severity
from threat_engine.rules import get_threat_explanation, get_indicator_explanation
from threat_engine.recommendations import get_recommendation


def build_sms_advisory(
    threat_result: Dict[str, Any],
    sms_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Constructs a unified cybersecurity threat advisory from an SMS Scam
    threat result and Person 3's threat engine functions.

    Args:
        threat_result: Dictionary matching the unified ThreatResult schema.
        sms_metadata: Optional extra metadata dictionary.

    Returns:
        Structured advisory dictionary conforming to the CyberShield standards.

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

    if threat_type not in ("safe", "scam", "unknown", "review"):
        raise ValueError(f"Unsupported SMS threat_type: '{threat_type}'. Must be 'safe' or 'scam'.")

    # Clean indicators
    indicators: List[str] = [str(item) for item in raw_indicators] if isinstance(raw_indicators, (list, tuple)) else []

    # Metadata assembly
    metadata = dict(threat_result.get("metadata", {}))
    if sms_metadata:
        metadata.update(sms_metadata)
    metadata["detector_severity"] = detector_severity
    metadata["attack_class"] = attack_class

    timestamp = threat_result.get("timestamp") or datetime.now(timezone.utc).isoformat()

    # Route logic: Benign vs Scam
    if threat_type == "safe":
        # Benign SMS: apply routing guard to avoid Person 3's alarmist fallback
        severity = "low"
        threat_explanation = "Routine SMS message; no scam indicators detected."
        indicator_explanations: List[str] = []
        recommendation = "No action required. The message appears legitimate."
    elif threat_type == "scam":
        # Scam threat: calculate severity using Person 3 policy
        severity = calculate_severity(confidence)
        threat_explanation = get_threat_explanation(threat_type, indicators)
        indicator_explanations = get_indicator_explanation(indicators)
        recommendation = get_recommendation(threat_type)
    else:
        # Unknown / Review
        severity = "low"
        threat_explanation = "SMS message content is ambiguous; manual review recommended."
        indicator_explanations = []
        recommendation = "Exercise caution before replying or interacting with unknown senders."

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

