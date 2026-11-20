"""
Advisory adapter integrating Person 1's Network IDS classifications with
Person 3's Shared Threat Engine rules, severity, and recommendations.
"""

from datetime import datetime, timezone
import math
import os
from typing import Any, Dict, List, Optional, Union

from .schemas import ThreatResult

from threat_engine.severity import calculate_severity
from threat_engine.rules import get_threat_explanation, get_indicator_explanation
from threat_engine.recommendations import get_recommendation


def build_network_advisory(
    threat_result: Union[ThreatResult, Dict[str, Any]],
    flow_metadata: Optional[Dict[str, Any]] = None,
    use_llama: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Constructs a unified cybersecurity threat advisory from a Person 1 Network IDS
    threat result and Person 3's threat engine functions.

    Args:
        threat_result: A ThreatResult dataclass instance or a compatible dictionary.
        flow_metadata: Optional dictionary with additional flow metadata (e.g. flow_id, IP).

    Returns:
        A structured dictionary conforming to Person 3's advisory standards,
        preserving network-specific indicators and metadata.

    Raises:
        ValueError: If input structure, field types, confidence ranges, or label combinations
                    are invalid or malformed.
    """
    if flow_metadata is not None and not isinstance(flow_metadata, dict):
        raise ValueError(f"flow_metadata must be a dictionary or None, got {type(flow_metadata).__name__}")

    # 1. Extract fields without mutating input
    if isinstance(threat_result, ThreatResult):
        source = threat_result.source
        threat_type = threat_result.threat_type
        attack_class = threat_result.attack_class
        detector_severity = threat_result.severity
        confidence = threat_result.confidence
        raw_indicators = threat_result.indicators
        explicit_timestamp = None
        base_metadata: Dict[str, Any] = {}
    elif isinstance(threat_result, dict):
        required_fields = ("source", "threat_type", "attack_class", "severity", "confidence")
        missing = [f for f in required_fields if f not in threat_result]
        if missing:
            raise ValueError(f"Missing required field(s) in threat_result: {', '.join(missing)}")

        source = threat_result["source"]
        threat_type = threat_result["threat_type"]
        attack_class = threat_result["attack_class"]
        detector_severity = threat_result["severity"]
        confidence = threat_result["confidence"]
        raw_indicators = threat_result.get("indicators")
        explicit_timestamp = threat_result.get("timestamp")
        base_metadata = (
            dict(threat_result["metadata"])
            if isinstance(threat_result.get("metadata"), dict)
            else {}
        )
    else:
        raise ValueError(
            f"Expected threat_result to be a ThreatResult instance or dict, got {type(threat_result).__name__}"
        )

    # 2. Type validation for string fields
    if not isinstance(source, str) or not source.strip():
        raise ValueError("Field 'source' must be a non-empty string.")
    if not isinstance(threat_type, str) or not threat_type.strip():
        raise ValueError("Field 'threat_type' must be a non-empty string.")
    if not isinstance(attack_class, str) or not attack_class.strip():
        raise ValueError("Field 'attack_class' must be a non-empty string.")
    if not isinstance(detector_severity, str) or not detector_severity.strip():
        raise ValueError("Field 'severity' must be a non-empty string.")

    # 3. Validate confidence: finite numeric value in [0.0, 1.0], no bool, no str, no NaN, no inf
    if isinstance(confidence, bool):
        raise ValueError("Confidence cannot be a boolean.")
    if not isinstance(confidence, (int, float)):
        raise ValueError(f"Confidence must be a numeric value, got {type(confidence).__name__}.")
    if math.isnan(confidence) or math.isinf(confidence):
        raise ValueError("Confidence must be a finite number.")
    if confidence < 0.0 or confidence > 1.0:
        raise ValueError(f"Confidence must be between 0.0 and 1.0, got {confidence}.")
    confidence = float(confidence)

    # 4. Validate threat_type and label consistency
    if threat_type not in ("normal", "intrusion"):
        raise ValueError(f"Unsupported threat_type '{threat_type}'. Must be 'normal' or 'intrusion'.")

    if threat_type == "normal" and attack_class != "BENIGN":
        raise ValueError(f"Inconsistent labels: threat_type is 'normal' but attack_class is '{attack_class}'.")

    if threat_type == "intrusion" and attack_class == "BENIGN":
        raise ValueError("Inconsistent labels: threat_type is 'intrusion' but attack_class is 'BENIGN'.")

    # 5. Normalize indicators safely
    # Prevent strings from being treated as iterables of characters
    if raw_indicators is None:
        normalized_indicators: List[str] = []
    elif isinstance(raw_indicators, str):
        raise ValueError("Indicators must be a list or tuple of strings, not a single string.")
    elif isinstance(raw_indicators, (list, tuple)):
        normalized_indicators = []
        for idx, item in enumerate(raw_indicators):
            if not isinstance(item, str):
                raise ValueError(f"Indicator at index {idx} must be a string, got {type(item).__name__}.")
            normalized_indicators.append(item)
    else:
        raise ValueError(f"Indicators must be a list or tuple, got {type(raw_indicators).__name__}.")

    # 6. Copy metadata safely without fabricating network metadata
    metadata: Dict[str, Any] = dict(base_metadata)
    if flow_metadata is not None:
        metadata.update(flow_metadata)
    metadata["detector_severity"] = detector_severity
    metadata["attack_class"] = attack_class

    # 7. Resolve timestamp
    timestamp: str
    if flow_metadata is not None and isinstance(flow_metadata.get("timestamp"), str) and flow_metadata["timestamp"].strip():
        timestamp = flow_metadata["timestamp"]
    elif isinstance(explicit_timestamp, str) and explicit_timestamp.strip():
        timestamp = explicit_timestamp
    else:
        timestamp = datetime.now(timezone.utc).isoformat()

    # 8. Route logic: Optional Llama Generation vs Deterministic Baseline
    should_use_llama = use_llama if use_llama is not None else (
        os.environ.get("ENABLE_LLAMA_NETWORK_ADVISORY", "0").lower() in ("1", "true")
    )
    if should_use_llama:
        try:
            from threat_engine.llama.adapter import generate_threat_advisory
            threat_record = {
                "source": source,
                "threat_type": threat_type,
                "attack_class": attack_class,
                "severity": detector_severity,
                "confidence": confidence,
                "indicators": normalized_indicators,
                "metadata": metadata,
                "timestamp": timestamp,
            }
            adv = generate_threat_advisory(threat_record, use_llama=True)
            adv_meta = dict(adv.get("metadata", {}))
            adv_meta.update(metadata)
            adv["metadata"] = adv_meta
            return adv
        except Exception:
            pass  # Fall through to deterministic rule baseline below

    if threat_type == "normal":
        # Benign flow: avoid Person 3's suspicious fallbacks
        severity = "low"
        threat_explanation = "Routine benign network flow; no threat detected."
        indicator_explanations: List[str] = []
        recommendation = "No action required. Traffic is within normal operational parameters."
    else:
        # Intrusion flow: use Person 3's pure functions
        severity = calculate_severity(confidence)
        threat_explanation = get_threat_explanation(threat_type, normalized_indicators)
        indicator_explanations = get_indicator_explanation(normalized_indicators)
        recommendation = get_recommendation(threat_type)

    return {
        "source": source,
        "threat_type": threat_type,
        "attack_class": attack_class,
        "severity": severity,
        "confidence": confidence,
        "indicators": normalized_indicators,
        "threat_explanation": threat_explanation,
        "indicator_explanations": indicator_explanations,
        "recommendation": recommendation,
        "metadata": metadata,
        "timestamp": timestamp,
    }

