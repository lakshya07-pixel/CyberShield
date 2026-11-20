from typing import Dict, Any
from .schemas import ThreatResult, SEVERITY_MAP
from .features import load_feature_list, validate_and_prepare_features

from .preprocess import preprocess_features
from .model import NetworkIDSModel

# Lazy-loaded singleton instance
_detector = None
_expected_features = None

def get_detector() -> NetworkIDSModel:
    global _detector
    if _detector is None:
        _detector = NetworkIDSModel()
        _detector.load()
    return _detector

def get_expected_features() -> list:
    global _expected_features
    if _expected_features is None:
        detector = get_detector()
        _expected_features = load_feature_list(detector.models_dir)
    return _expected_features

def detect_network_threat(input_data: Dict[str, Any]) -> ThreatResult:
    """
    Exposes a standardized interface for detecting network threats.
    
    Args:
        input_data: A dictionary mapping feature names to values.
        
    Returns:
        ThreatResult representing the network intrusion classification.
    """
    # 1. Lazy load components
    detector = get_detector()
    expected_features = get_expected_features()

    # 2. Validate and prepare features deterministically
    feature_df = validate_and_prepare_features(input_data, expected_features)

    # 3. Preprocess (handled internally by the sklearn pipeline wrapper, but explicitly passed here)
    processed_df = preprocess_features(feature_df)

    # 4. Predict class and probabilities
    class_idx = detector.predict(processed_df)[0]
    probabilities = detector.predict_proba(processed_df)[0]
    
    # 5. Calculate confidence
    confidence = float(probabilities[class_idx])

    # 6. Map class
    attack_class = detector.decode_label(class_idx)

    # 7. Determine severity
    # Handle CSV encoding quirks if present (e.g., 'Web Attack  Brute Force')
    clean_attack_class = attack_class.replace('', '-').replace('  ', ' ')
    severity = SEVERITY_MAP.get(attack_class, "high") # Fallback to high if unknown attack

    threat_type = "normal" if attack_class == "BENIGN" else "intrusion"

    # 8. Generate simple indicators
    indicators = []
    if threat_type == "intrusion":
        indicators.append(f"Classified as {attack_class} traffic")
        if confidence > 0.8:
            indicators.append("High-confidence intrusion classification")
        else:
            indicators.append("Moderate-confidence intrusion classification")
    else:
        indicators.append("Normal network traffic detected")

    # 9. Return structured result
    return ThreatResult(
        source="network",
        threat_type=threat_type,
        attack_class=attack_class,
        severity=severity,
        confidence=confidence,
        indicators=indicators
    )
