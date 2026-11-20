"""
SMS Scam Inference Engine.
Coordinates text cleaning, TF-IDF inference, indicator extraction,
and ThreatResult formatting adhering to the team's shared contract.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional

from .preprocess import clean_sms_text, extract_sms_indicators
from .model import SMSScamModel

# Lazy singleton model instance
_sms_model_instance: Optional[SMSScamModel] = None


def get_sms_model() -> SMSScamModel:
    """Returns the singleton SMSScamModel instance."""
    global _sms_model_instance
    if _sms_model_instance is None:
        _sms_model_instance = SMSScamModel()
    return _sms_model_instance


def detect_sms_threat(
    text: str,
    models_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates an SMS message and returns a standardized ThreatResult dictionary.

    Args:
        text: Raw SMS message string.
        models_dir: Optional custom model directory path.

    Returns:
        Structured dictionary conforming to the unified ThreatResult schema.

    Raises:
        ValueError: If text is empty or whitespace-only.
    """
    if not text or not text.strip():
        raise ValueError("SMS text cannot be empty or whitespace-only.")

    t0 = time.perf_counter()

    # 1. Clean and normalize text
    cleaned = clean_sms_text(text)

    # 2. Predict scam probability
    model_wrapper = SMSScamModel(models_dir=models_dir) if models_dir else get_sms_model()
    scam_prob = model_wrapper.predict_proba(cleaned)

    latency_ms = (time.perf_counter() - t0) * 1000

    # 3. Classify outcome
    is_scam = scam_prob > 0.50
    if is_scam:
        threat_type = "scam"
        attack_class = "Scam"
        confidence = round(scam_prob, 4)
        if confidence >= 0.90:
            severity = "critical"
        elif confidence >= 0.75:
            severity = "high"
        else:
            severity = "medium"
    else:
        threat_type = "safe"
        attack_class = "BENIGN"
        confidence = round(1.0 - scam_prob, 4)
        severity = "low"

    # 4. Extract contextual indicators
    indicators = extract_sms_indicators(text, is_threat=is_scam)

    # Extract any embedded URLs for correlation
    import re
    found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    extracted_urls = []
    for u in found_urls:
        extracted_urls.append(u)
        indicators.insert(0, u)

    return {
        "source": "sms",
        "text": text,
        "threat_type": threat_type,
        "attack_class": attack_class,
        "severity": severity,
        "confidence": confidence,
        "indicators": indicators,
        "metadata": {
            "model": "tfidf_logistic_regression",
            "raw_scam_probability": round(scam_prob, 4),
            "cleaned_text_preview": cleaned[:80],
            "extracted_urls": extracted_urls,
            "latency_ms": round(latency_ms, 3),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

