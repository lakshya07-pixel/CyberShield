"""
URL Feature Extraction Module for CyberShield Challenge.
Extracts 16 canonical lexical, structural, and information-theoretic features
from URL strings for machine-learning-based phishing detection.

Conforms to RFC 3986 URL parsing and path normalization standards to prevent
spurious empty-path misclassifications on bare domain names.
"""

import math
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Canonical 16 feature names in exact required order
FEATURE_NAMES: List[str] = [
    "len",
    "host_len",
    "path_len",
    "https",
    "dots",
    "hyphens",
    "digits",
    "at",
    "is_ip",
    "subdomains",
    "params",
    "domain_keywords",
    "path_keywords",
    "domain_digits",
    "entropy",
    "special",
]

KEYWORDS: List[str] = [
    "login", "verify", "update", "secure", "account", "bank", "confirm",
    "password", "signin", "wallet", "free", "bonus", "kyc", "claim", "prize",
]


def calculate_entropy(s: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def normalize_url(url: str) -> Tuple[str, Any]:
    """
    Normalizes a URL string and parses its components according to RFC 3986.
    Ensures empty paths on HTTP/HTTPS URLs resolve to root path '/'.
    """
    u = url.strip()
    if not u:
        raise ValueError("URL string cannot be empty or whitespace-only.")

    # Prepend scheme if missing for standard parsing
    if "://" not in u:
        u_with_scheme = "http://" + u
    else:
        u_with_scheme = u

    try:
        parsed = urlparse(u_with_scheme)
    except Exception:
        parsed = urlparse("http://invalid")

    return u, parsed


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extracts the 16 canonical numerical features from a URL string.

    Args:
        url: Raw URL string.

    Returns:
        Dictionary mapping all 16 feature names to numerical values.

    Raises:
        ValueError: If input is empty or whitespace-only.
    """
    raw_url, parsed = normalize_url(url)

    host = (parsed.netloc or "").lower()
    
    # RFC 3986 normalization: bare domains have an implicit root path '/'
    raw_path = parsed.path or ""
    if host and not raw_path:
        norm_path = "/"
    else:
        norm_path = raw_path

    path_lower = norm_path.lower()
    query_lower = (parsed.query or "").lower()

    # Remove port number from hostname if present
    host_without_port = host.split(":")[0]

    # Keyword frequencies
    domain_keywords = sum(k in host_without_port for k in KEYWORDS)
    path_keywords = sum(k in (path_lower + " " + query_lower) for k in KEYWORDS)

    # IP address literal detection (IPv4 or bracketed IPv6)
    is_ip = int(bool(re.fullmatch(r"[\d.]+", host_without_port) or host_without_port.startswith("[")))

    # Parameter count
    param_count = (parsed.query.count("&") + 1) if parsed.query else 0

    return {
        "len": len(raw_url),
        "host_len": len(host_without_port),
        "path_len": len(norm_path),
        "https": int(parsed.scheme.lower() == "https"),
        "dots": host_without_port.count("."),
        "hyphens": host_without_port.count("-"),
        "digits": sum(c.isdigit() for c in raw_url),
        "at": int("@" in raw_url),
        "is_ip": is_ip,
        "subdomains": max(host_without_port.count(".") - 1, 0),
        "params": param_count,
        "domain_keywords": domain_keywords,
        "path_keywords": path_keywords,
        "domain_digits": sum(c.isdigit() for c in host_without_port),
        "entropy": round(calculate_entropy(host_without_port), 3),
        "special": len(re.findall(r"[^\w./:-]", raw_url)),
    }


def extract_indicators(url: str, features: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Generates human-readable security indicators from extracted URL features.
    """
    if features is None:
        features = extract_features(url)
    reasons: List[str] = []

    if features["is_ip"]:
        reasons.append("IP address used as host")

    if features["domain_keywords"] >= 1:
        reasons.append("Suspicious keyword in domain")

    if features["path_keywords"] >= 1:
        reasons.append("Suspicious keyword in path or query")

    if not features["https"]:
        reasons.append("Missing HTTPS encryption")

    if features["subdomains"] >= 2:
        reasons.append("Unusual number of subdomains")

    if features["hyphens"] >= 2:
        reasons.append("Multiple hyphens in domain")

    if features["at"]:
        reasons.append("'@' symbol in URL (potential userinfo spoofing)")

    if features["entropy"] > 3.8:
        reasons.append("High domain name randomness/entropy")

    return reasons

