"""
Advisory Integration Contract & Protocol Validator for Bharat AI-SoC.
Defines schemas, sanitization rules, and bidirectional validation for threat advisories,
enforcing 100% authoritative detector field immutability and correlation tracking.
"""

from datetime import datetime, timezone
import math
import re
from typing import Any, Dict, List, Optional, Union

# Allowed detector types
ALLOWED_DETECTOR_TYPES = {"ids", "network_ids", "url", "sms"}

# Allowed severities (case-insensitive canonical)
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# Control characters to strip from untrusted evidence (except standard whitespace \t, \n, \r)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

# Maximum sizes to protect against memory exhaustion or DoS
MAX_ID_LEN = 64
MAX_CATEGORY_LEN = 64
MAX_SUMMARY_LEN = 512
MAX_EVIDENCE_BYTES = 65536


class AdvisoryContractError(ValueError):
    """Raised when an advisory request or response violates the contract."""
    pass


def sanitize_text(text: Any, max_len: int = 512) -> str:
    """Sanitizes text by stripping control characters and enforcing length limits."""
    if text is None:
        return ""
    s = str(text)
    s = CONTROL_CHAR_RE.sub("", s)
    return s[:max_len]


def validate_advisory_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates and sanitizes an inbound advisory request payload.

    Args:
        payload: Inbound dictionary representing the advisory request.

    Returns:
        Sanitized, contract-compliant request dictionary.

    Raises:
        AdvisoryContractError: If required fields are missing or invalid.
    """
    if not isinstance(payload, dict):
        raise AdvisoryContractError(f"Request payload must be a dict, got {type(payload).__name__}")

    # 1. Schema version
    version = str(payload.get("schema_version", "1.0.0")).strip()
    if version != "1.0.0":
        raise AdvisoryContractError(f"Unsupported schema_version '{version}'. Expected '1.0.0'")

    # 2. Request ID / Correlation ID
    raw_req_id = payload.get("request_id") or payload.get("correlation_id")
    if not raw_req_id or not isinstance(raw_req_id, str) or not raw_req_id.strip():
        raise AdvisoryContractError("Missing or invalid 'request_id'. Must be a non-empty string.")
    req_id = raw_req_id.strip()
    if len(req_id) > MAX_ID_LEN:
        raise AdvisoryContractError(f"'request_id' exceeds maximum length of {MAX_ID_LEN} characters.")

    # 3. Detector Type
    det_type = str(payload.get("detector_type", "")).strip().lower()
    if det_type not in ALLOWED_DETECTOR_TYPES:
        raise AdvisoryContractError(
            f"Invalid detector_type '{det_type}'. Allowed types: {sorted(ALLOWED_DETECTOR_TYPES)}"
        )

    # 4. Threat Category / Attack Class
    raw_cat = payload.get("threat_category") or payload.get("attack_class")
    if not raw_cat or not isinstance(raw_cat, str) or not raw_cat.strip():
        raise AdvisoryContractError("Missing or empty 'threat_category' / 'attack_class'.")
    threat_category = raw_cat.strip()[:MAX_CATEGORY_LEN]

    # 5. Severity
    raw_sev = str(payload.get("severity", "")).strip().upper()
    if raw_sev not in ALLOWED_SEVERITIES:
        raise AdvisoryContractError(
            f"Invalid severity '{raw_sev}'. Allowed values: {sorted(ALLOWED_SEVERITIES)}"
        )
    severity = raw_sev

    # 6. Confidence score
    conf = payload.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)):
        raise AdvisoryContractError(f"Confidence must be a numeric float, got {type(conf).__name__}")
    if math.isnan(conf) or math.isinf(conf):
        raise AdvisoryContractError("Confidence cannot be NaN or Infinite.")
    if not (0.0 <= conf <= 1.0):
        raise AdvisoryContractError(f"Confidence must be between 0.0 and 1.0, got {conf}")
    confidence = float(conf)

    # 7. Detection summary
    detection_summary = sanitize_text(
        payload.get("detection_summary", f"{det_type.upper()} detected {threat_category}"),
        max_len=MAX_SUMMARY_LEN
    )

    # 8. Evidence
    raw_evidence = payload.get("evidence", payload.get("indicators", {}))
    if isinstance(raw_evidence, list):
        sanitized_evidence: Dict[str, Any] = {"indicators": [sanitize_text(x, 128) for x in raw_evidence[:20]]}
    elif isinstance(raw_evidence, dict):
        sanitized_evidence = {
            sanitize_text(k, 64): sanitize_text(v, 256) for k, v in list(raw_evidence.items())[:30]
        }
    else:
        sanitized_evidence = {}

    # 9. Model ID & Timestamp
    model_id = str(payload.get("model_id", "llama3_2_1b_spinquant")).strip()
    timestamp_utc = payload.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()
    indicators_list = []
    if isinstance(raw_evidence, list):
        indicators_list = [sanitize_text(x, 128) for x in raw_evidence[:20]]
    elif isinstance(raw_evidence, dict) and "indicators" in raw_evidence and isinstance(raw_evidence["indicators"], list):
        indicators_list = [sanitize_text(x, 128) for x in raw_evidence["indicators"][:20]]

    return {
        "schema_version": "1.0.0",
        "request_id": req_id,
        "correlation_id": req_id,
        "detector_type": det_type,
        "source": det_type,
        "threat_category": threat_category,
        "attack_class": threat_category,
        "threat_type": threat_category,
        "severity": severity,
        "confidence": confidence,
        "detection_summary": detection_summary,
        "evidence": sanitized_evidence,
        "indicators": indicators_list,
        "model_id": model_id,
        "timestamp_utc": timestamp_utc,
        "max_new_tokens": int(payload.get("max_new_tokens", 80)),
        "temperature": float(payload.get("temperature", 0.1)),
    }


def validate_advisory_response(
    response: Dict[str, Any],
    original_request: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Validates an outbound advisory response from the model runner and asserts
    strict 100% authoritative detector field immutability.

    Args:
        response: Response dictionary received from runner/bridge.
        original_request: The validated request dictionary that initiated inference.

    Returns:
        The validated response dictionary.

    Raises:
        AdvisoryContractError: If correlation ID mismatches or authoritative fields were altered.
    """
    if not isinstance(response, dict):
        raise AdvisoryContractError(f"Response must be a dict, got {type(response).__name__}")

    # Check status
    res_status = response.get("status")
    if res_status not in ("success", "error", "fallback", "timeout"):
        raise AdvisoryContractError(f"Invalid response status '{res_status}'")

    # Check correlation ID match
    resp_id = response.get("request_id") or response.get("correlation_id")
    orig_id = original_request["request_id"]
    if resp_id != orig_id:
        raise AdvisoryContractError(
            f"Correlation ID mismatch: request had '{orig_id}', response returned '{resp_id}'"
        )

    # Immutability verification of threat context
    context = response.get("threat_context", {})
    if context:
        req_cat = original_request["threat_category"]
        res_cat = context.get("attack_class") or context.get("threat_category")
        if res_cat and res_cat != req_cat:
            raise AdvisoryContractError(
                f"Authoritative attack_class mutated! Expected '{req_cat}', got '{res_cat}'"
            )

        req_sev = original_request["severity"].upper()
        res_sev = str(context.get("severity", "")).upper()
        if res_sev and res_sev != req_sev:
            raise AdvisoryContractError(
                f"Authoritative severity mutated! Expected '{req_sev}', got '{res_sev}'"
            )

        req_conf = original_request["confidence"]
        res_conf = context.get("confidence")
        if res_conf is not None and abs(float(res_conf) - req_conf) > 1e-4:
            raise AdvisoryContractError(
                f"Authoritative confidence score mutated! Expected {req_conf}, got {res_conf}"
            )

    return response

