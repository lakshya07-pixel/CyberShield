"""
URL Phishing Inference Engine.
Coordinates URL feature extraction, model scoring, heuristic risk adjustments,
and output formatting adhering to the team's shared ThreatResult contract.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from .features import extract_features, extract_indicators, FEATURE_NAMES
from .model import URLPhishingModel

# Lazy singleton model instance
_model_instance: Optional[URLPhishingModel] = None


def get_url_model() -> URLPhishingModel:
    """Returns the singleton URLPhishingModel instance."""
    global _model_instance
    if _model_instance is None:
        _model_instance = URLPhishingModel()
    return _model_instance


def adjust_probability(raw_prob: float, features: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Applies transparent heuristic risk adjustments when unambiguous structural signals
    indicate elevated phishing risk that raw statistical models may underestimate.

    Returns:
        Tuple of (adjusted_probability: float, triggered_rules: List[str]).
    """
    adjusted = raw_prob
    triggered: List[str] = []

    # 1. IP address literal host is an authoritative phishing/malware signal
    if features.get("is_ip", 0):
        adjusted = max(adjusted, 0.90)
        triggered.append("IP address literal used as host")

    # 2. Strong combination: unencrypted connection + multiple hyphens + domain keyword
    if (
        not features.get("https", 0)
        and features.get("hyphens", 0) >= 2
        and features.get("domain_keywords", 0) >= 1
    ):
        adjusted = max(adjusted, 0.85)
        triggered.append("Missing HTTPS with multiple domain hyphens and brand keywords")

    # 3. Strong combination: unencrypted connection + domain keyword + path keyword
    if (
        not features.get("https", 0)
        and features.get("domain_keywords", 0) >= 1
        and features.get("path_keywords", 0) >= 1
    ):
        adjusted = max(adjusted, 0.85)
        triggered.append("Missing HTTPS with suspicious keywords in both domain and path")

    # 4. Compound structural anomaly signals
    strong_signals = 0
    if not features.get("https", 0): strong_signals += 1
    if features.get("hyphens", 0) >= 2: strong_signals += 1
    if features.get("domain_keywords", 0) >= 1: strong_signals += 1
    if features.get("entropy", 0) > 3.8: strong_signals += 1
    if features.get("is_ip", 0): strong_signals += 1

    if strong_signals >= 3:
        adjusted = max(adjusted, 0.80)
        triggered.append(f"Multiple ({strong_signals}) compounding structural anomalies")

    return min(adjusted, 1.0), triggered


def detect_url_threat(
    url: str,
    use_lite: bool = False,
    models_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates a URL and returns a standardized ThreatResult dictionary.

    Args:
        url: URL string to inspect.
        use_lite: If True, uses the lightweight Logistic Regression model.
        models_dir: Optional custom model directory path.

    Returns:
        Structured dictionary conforming to the unified ThreatResult schema.

    Raises:
        ValueError: If url is empty or whitespace-only.
    """
    if not url or not url.strip():
        raise ValueError("URL input cannot be empty or whitespace-only.")

    t0 = time.perf_counter()

    # 1. Extract 16 canonical features with RFC 3986 path normalization
    features = extract_features(url)
    indicators = extract_indicators(url, features)

    # 2. Load model and compute raw ML probability
    model_wrapper = URLPhishingModel(models_dir=models_dir) if models_dir else get_url_model()
    raw_prob, model_id = model_wrapper.predict_proba(features, use_lite=use_lite)

    # 3. Apply transparent heuristic risk adjustments
    adjusted_prob, triggered_heuristics = adjust_probability(raw_prob, features)

    latency_ms = (time.perf_counter() - t0) * 1000

    # 4. Map classification and confidence
    if adjusted_prob > 0.50:
        threat_type = "phishing"
        attack_class = "Phishing"
        confidence = round(adjusted_prob, 4)
        # Severity mapped adhering to Person 3 threshold policy
        if confidence >= 0.90:
            severity = "critical"
        elif confidence >= 0.75:
            severity = "high"
        else:
            severity = "medium"
    else:
        threat_type = "safe"
        attack_class = "BENIGN"
        # For safe outcomes, confidence expresses certainty of being benign
        confidence = round(1.0 - adjusted_prob, 4)
        severity = "low"

    # Merge heuristic rationales into indicators list if not already present
    for h in triggered_heuristics:
        if h not in indicators:
            indicators.append(h)

    indicators.insert(0, url)

    return {
        "source": "url",
        "url": url,
        "threat_type": threat_type,
        "attack_class": attack_class,
        "severity": severity,
        "confidence": confidence,
        "indicators": indicators,
        "metadata": {
            "model": model_id,
            "raw_phishing_probability": round(raw_prob, 4),
            "adjusted_phishing_probability": round(adjusted_prob, 4),
            "latency_ms": round(latency_ms, 3),
            "feature_count": len(FEATURE_NAMES),
            "heuristics_triggered": triggered_heuristics,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
