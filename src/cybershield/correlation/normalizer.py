import re
import urllib.parse
import ipaddress
from typing import Dict, Any, Set, Tuple, List, Optional

# Standard RFC / infrastructure domains or IPs that should not trigger correlation on their own
GENERIC_EXCLUSION_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "broadcast", "255.255.255.255",
    "google.com", "www.google.com", "apple.com", "microsoft.com",
    "dns.google", "cloudflare-dns.com", "one.one.one.one"
}

GENERIC_EXCLUSION_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255"
}

URL_REGEX = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
PHONE_REGEX = re.compile(r'(?:\+?91[\-\s]?)?[6-9]\d{2,4}[\-\s]?\d{4,7}\b')

def normalize_domain(domain_str: str) -> Optional[str]:
    """
    Normalizes a FQDN / domain name: lowercase, strip trailing dot, strip port if present.
    Returns None if empty or invalid.
    """
    if not domain_str:
        return None
    d = domain_str.strip().lower()
    if ":" in d:
        d = d.split(":")[0]
    d = d.rstrip(".")
    if not d or d in GENERIC_EXCLUSION_HOSTS:
        return None
    return d

def normalize_ip(ip_str: str) -> Optional[str]:
    """
    Normalizes an IPv4 or IPv6 address string.
    Returns canonical compressed IP representation or None if invalid.
    """
    if not ip_str:
        return None
    s = ip_str.strip()
    if ":" in s and not s.startswith("[") and s.count(":") == 1:
        # Host:port format
        s = s.split(":")[0]
    try:
        ip_obj = ipaddress.ip_address(s)
        canonical = str(ip_obj)
        if canonical in GENERIC_EXCLUSION_IPS:
            return None
        return canonical
    except ValueError:
        return None

def normalize_phone(phone_str: str) -> Optional[str]:
    """
    Normalizes phone numbers to standard 10-digit or E.164 without separators.
    """
    if not phone_str:
        return None
    cleaned = re.sub(r'[\s\-\(\)]', '', phone_str.strip())
    if cleaned.startswith("+91"):
        cleaned = cleaned[3:]
    elif cleaned.startswith("91") and len(cleaned) == 12:
        cleaned = cleaned[2:]
    if re.fullmatch(r'\d{10}', cleaned):
        return f"+91{cleaned}"
    return None

def extract_and_normalize_indicators(record: Dict[str, Any]) -> Set[Tuple[str, str]]:
    """
    Extracts high-entropy indicators from a detector output record.
    Returns a set of tuples: (indicator_type, indicator_value).
    Types: 'domain', 'host', 'ip', 'url', 'phone'
    """
    indicators: Set[Tuple[str, str]] = set()

    # 1. Inspect existing 'indicators' list in the record
    raw_indicators = record.get("indicators", [])
    for ind in raw_indicators:
        if isinstance(ind, str):
            if ":" in ind and not (ind.startswith("http://") or ind.startswith("https://")):
                itype, ival = ind.split(":", 1)
                itype = itype.strip().lower()
                ival = ival.strip()

                if itype in ("domain", "host", "fqdn", "dns_query", "sni"):
                    norm_d = normalize_domain(ival)
                    if norm_d:
                        indicators.add(("domain", norm_d))
                elif itype in ("src_ip", "dst_ip", "ip"):
                    norm_ip = normalize_ip(ival)
                    if norm_ip:
                        indicators.add(("ip", norm_ip))
                elif itype in ("url", "embedded_url"):
                    parsed = urllib.parse.urlparse(ival)
                    if parsed.netloc:
                        norm_d = normalize_domain(parsed.netloc)
                        if norm_d:
                            indicators.add(("domain", norm_d))
                    indicators.add(("url", ival.strip()))
                elif itype in ("phone", "sender", "phone_token"):
                    norm_p = normalize_phone(ival)
                    if norm_p:
                        indicators.add(("phone", norm_p))
            else:
                # Direct URL or domain without type prefix (e.g. http://domain.com/path)
                val_str = ind.strip()
                if val_str.startswith("http://") or val_str.startswith("https://"):
                    parsed = urllib.parse.urlparse(val_str)
                    if parsed.netloc:
                        norm_d = normalize_domain(parsed.netloc)
                        if norm_d:
                            indicators.add(("domain", norm_d))
                    indicators.add(("url", val_str))
                else:
                    norm_d = normalize_domain(val_str)
                    if norm_d:
                        indicators.add(("domain", norm_d))

    # 2. Source-specific deep extraction
    source = record.get("source", "").lower()

    # URL Detector
    if source == "url":
        url_val = record.get("url") or (raw_indicators[0] if raw_indicators else "")
        if url_val:
            parsed = urllib.parse.urlparse(url_val)
            if parsed.netloc:
                norm_d = normalize_domain(parsed.netloc)
                if norm_d:
                    indicators.add(("domain", norm_d))
            indicators.add(("url", url_val.strip()))

    # SMS Detector
    elif source == "sms":
        meta = record.get("metadata", {})
        # Extracted URLs
        for u in meta.get("extracted_urls", []):
            parsed = urllib.parse.urlparse(u)
            if parsed.netloc:
                norm_d = normalize_domain(parsed.netloc)
                if norm_d:
                    indicators.add(("domain", norm_d))
            indicators.add(("url", u.strip()))
        # Raw text search if needed (prefer raw text to preserve unmasked URLs and phone tokens)
        text = record.get("text", "") or meta.get("cleaned_text_preview", "")
        if text:
            for found_url in URL_REGEX.findall(text):
                parsed = urllib.parse.urlparse(found_url)
                if parsed.netloc:
                    norm_d = normalize_domain(parsed.netloc)
                    if norm_d:
                        indicators.add(("domain", norm_d))
            for found_phone in PHONE_REGEX.findall(text):
                norm_p = normalize_phone(found_phone)
                if norm_p:
                    indicators.add(("phone", norm_p))

    # Network Flow Detector
    elif source == "network":
        # Check flow_index or threat_result indicators
        for k in ("dst_ip", "src_ip"):
            val = record.get(k)
            if val:
                norm_ip = normalize_ip(val)
                if norm_ip:
                    indicators.add(("ip", norm_ip))
        for k in ("dns_query", "sni", "host"):
            val = record.get(k)
            if val:
                norm_d = normalize_domain(val)
                if norm_d:
                    indicators.add(("domain", norm_d))

    return indicators
