"""
Cryptographically Hardened Models & Canonical Integrity Sealing for Bharat AI-SoC.
Provides deterministic canonical JSON serialization, HMAC-SHA256 authenticated sealing,
legacy SHA-256 verification, and constant-time side-channel protection.
"""

from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("bharat_ai_soc.integrity")

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "BENIGN": 0,
}

# Default deterministic key for test/edge development when no environment key is supplied
DEFAULT_EDGE_HMAC_KEY = b"bharat-ai-soc-edge-integrity-secret-seed-20261021"
DEFAULT_KEY_ID = "k1-edge-default"


def get_integrity_hmac_key() -> Tuple[bytes, str]:
    """
    Retrieves the provisioned HMAC secret key and key ID.
    Priority:
    1. BHARAT_INCIDENT_HMAC_KEY environment variable.
    2. Fallback to DEFAULT_EDGE_HMAC_KEY for standalone edge development.
    """
    env_key = os.environ.get("BHARAT_INCIDENT_HMAC_KEY")
    key_id = os.environ.get("BHARAT_INCIDENT_KEY_ID", DEFAULT_KEY_ID)
    if env_key:
        # Support hex or raw UTF-8 string
        try:
            return bytes.fromhex(env_key), key_id
        except ValueError:
            return env_key.encode("utf-8"), key_id
    return DEFAULT_EDGE_HMAC_KEY, key_id


def canonical_json(data: Dict[str, Any]) -> str:
    """
    Produces deterministic canonical JSON (sorted keys, no extraneous whitespace, UTF-8).
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def extract_authenticated_fields(incident_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts strictly the security-relevant core fields protected by the integrity seal.
    Excludes seal/signature containers to prevent self-referential hash loops.
    """
    protected_keys = (
        "incident_id",
        "created_at",
        "status",
        "severity",
        "confidence",
        "summary",
        "shared_indicators",
        "correlated_events",
        "advisory",
    )
    extracted = {}
    for k in protected_keys:
        if k in incident_dict:
            extracted[k] = incident_dict[k]
    return extracted


def compute_incident_sha256(incident_dict: Dict[str, Any]) -> str:
    """
    Legacy unkeyed SHA-256 digest over protected incident fields.
    """
    auth_data = extract_authenticated_fields(incident_dict)
    canonical = canonical_json(auth_data)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_incident_hmac(incident_dict: Dict[str, Any], key: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Computes a cryptographic HMAC-SHA256 tag over canonical protected incident fields.
    Returns (hex_mac, key_id).
    """
    if key is None:
        key_bytes, key_id = get_integrity_hmac_key()
    else:
        key_bytes, key_id = key, os.environ.get("BHARAT_INCIDENT_KEY_ID", DEFAULT_KEY_ID)

    auth_data = extract_authenticated_fields(incident_dict)
    canonical = canonical_json(auth_data)
    mac = hmac.new(key_bytes, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return mac, key_id


def verify_incident_integrity(
    incident_dict: Dict[str, Any],
    key: Optional[bytes] = None,
    allow_legacy_unkeyed: bool = True,
) -> bool:
    """
    Cryptographically verifies the authenticity and tamper-resistance of an incident record.
    Returns True if HMAC or valid legacy seal matches; False otherwise.
    Uses constant-time comparison (hmac.compare_digest).
    """
    if not isinstance(incident_dict, dict):
        return False

    # 1. Prefer modern HMAC-SHA256 evidence_seal
    seal = incident_dict.get("evidence_seal")
    if isinstance(seal, dict):
        algo = seal.get("algorithm")
        sig = seal.get("signature")
        if algo == "HMAC-SHA256" and isinstance(sig, str) and sig.strip():
            expected_mac, _ = compute_incident_hmac(incident_dict, key=key)
            return hmac.compare_digest(sig.strip().lower(), expected_mac.lower())

    # 2. Backward-compatible unkeyed SHA-256 fallback
    if allow_legacy_unkeyed:
        legacy_sig = incident_dict.get("sha256_signature")
        if isinstance(legacy_sig, str) and legacy_sig.strip():
            expected_sha = compute_incident_sha256(incident_dict)
            return hmac.compare_digest(legacy_sig.strip().lower(), expected_sha.lower())

    return False


@dataclass
class SharedIndicatorMatch:
    indicator_type: str
    indicator_value: str
    participating_sources: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceSeal:
    algorithm: str
    key_id: str
    signature: str
    sealed_at: str
    canonical_version: str = "v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UnifiedIncidentRecord:
    incident_id: str
    created_at: str
    status: str
    severity: str
    confidence: float
    summary: str
    shared_indicators: List[Dict[str, Any]]
    correlated_events: List[Dict[str, Any]]
    advisory: Dict[str, Any]
    sha256_signature: str = ""
    evidence_seal: Optional[Dict[str, Any]] = None

    def seal(self, key: Optional[bytes] = None) -> "UnifiedIncidentRecord":
        """
        Signs and seals the incident record with HMAC-SHA256 and legacy SHA-256 digests.
        """
        d = self.to_dict()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Compute keyed HMAC-SHA256 tag
        mac, kid = compute_incident_hmac(d, key=key)
        self.evidence_seal = {
            "algorithm": "HMAC-SHA256",
            "key_id": kid,
            "signature": mac,
            "sealed_at": now_iso,
            "canonical_version": "v1",
        }

        # Also store legacy unkeyed SHA-256 for backward compatibility
        self.sha256_signature = compute_incident_sha256(d)
        return self

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if not self.sha256_signature:
            d.pop("sha256_signature", None)
        if self.evidence_seal is None:
            d.pop("evidence_seal", None)
        return d
