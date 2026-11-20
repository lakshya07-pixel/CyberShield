"""Evidence-based cross-channel event correlation and prioritization.

This module correlates submitted event records using shared indicators.
Priority is derived only from supplied severity values. It does not run
threat detectors or prove that events share an attacker.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
import re
from urllib.parse import urlparse


SUPPORTED_CHANNELS = {"network", "url", "sms"}
MAX_EVENTS = 500
MAX_INDICATORS_PER_EVENT = 100

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

PRIORITY_EXPLANATIONS = {
    "CRITICAL": (
        "At least one correlated event was supplied with CRITICAL severity. "
        "Review this group urgently; correlation does not confirm an attack."
    ),
    "HIGH": (
        "The highest supplied severity in this group is HIGH. "
        "Review it promptly; correlation does not confirm an attack."
    ),
    "MEDIUM": (
        "The highest supplied severity in this group is MEDIUM. "
        "Review it according to your security workflow."
    ),
    "LOW": (
        "The highest supplied severity in this group is LOW. "
        "Review it as appropriate for your security workflow."
    ),
    "UNKNOWN": (
        "No valid severity was supplied for the events in this group. "
        "Priority cannot be determined from the available evidence."
    ),
}

# Generic heuristic descriptions that should not be used as concrete correlation IOCs
_EXCLUDED_HEURISTIC_INDICATORS = {
    "missing https encryption",
    "suspicious keyword in domain",
    "suspicious keyword in path or query",
    "multiple hyphens in domain",
    "unusual number of subdomains",
    "high domain name randomness/entropy",
    "contains suspicious link or urgent call-to-click",
    "normal network traffic detected",
    "ip address used as host",
    "potential phishing link detected",
    "routine benign network flow; no threat detected.",
}


def normalize_indicator(value: str) -> str:
    """Normalize an indicator for exact, case-insensitive matching."""
    return re.sub(r"\s+", " ", value.strip()).casefold()


def extract_canonical_indicators(raw_indicator: str) -> list[str]:
    """
    Extracts canonical matched indicators from a raw indicator string.
    Decomposes URLs to hostnames, strips 'host:' prefixes, extracts IP from IP:port,
    and normalizes phone numbers while ignoring generic heuristic phrases.
    """
    raw = raw_indicator.strip()
    if not raw:
        return []

    val = normalize_indicator(raw)

    # Exclude descriptive heuristic strings
    if (
        val in _EXCLUDED_HEURISTIC_INDICATORS
        or val.startswith(("scam keywords detected:", "missing https with", "multiple (", "suspicious indicator:"))
    ):
        return []

    indicators = [val]

    # 1. host:<hostname> prefix stripping
    if val.startswith("host:"):
        h = val[5:].strip()
        if h:
            indicators.append(h)
            val = h  # allow subsequent domain matching

    # 2. URL decomposition to host/domain
    if "://" in val or val.startswith(("http:", "https:")):
        try:
            parsed = urlparse(val if "://" in val else "http://" + val)
            host = (parsed.netloc or "").split(":")[0].strip()
            if host:
                indicators.append(host)
        except Exception:
            pass
    elif re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(/.*)?$", val):
        try:
            parts = val.split("/")[0].split(":")[0].strip()
            if parts:
                indicators.append(parts)
        except Exception:
            pass

    # 3. IP with port decomposition (e.g., 192.168.1.100:8080 -> 192.168.1.100)
    ip_port_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$", val)
    if ip_port_match:
        indicators.append(ip_port_match.group(1))

    # 4. Phone number normalization (+91-9876543210 -> 9876543210)
    phone_clean = re.sub(r"[\s\-\(\)\+]", "", val)
    if phone_clean.startswith("91") and len(phone_clean) == 12 and phone_clean.isdigit():
        indicators.append(phone_clean[2:])
    elif len(phone_clean) == 10 and phone_clean.isdigit():
        indicators.append(phone_clean)

    # Preserve order and eliminate duplicates
    return list(dict.fromkeys(indicators))


def normalize_severity(value: Any) -> str | None:
    """Return a supported severity label, or None if it is unavailable."""
    if not isinstance(value, str):
        return None

    severity = value.strip().upper()
    return severity if severity in SEVERITY_RANK else None


def correlate_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Group submitted events that share indicators across channels."""

    if len(events) > MAX_EVENTS:
        raise ValueError(f"At most {MAX_EVENTS} events are allowed.")

    indicator_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    accepted_events = []

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event {index + 1} must be an object.")

        channel = str(event.get("source", "")).strip().lower()

        if channel not in SUPPORTED_CHANNELS:
            raise ValueError(
                f"Event {index + 1}: source must be network, url, or sms."
            )

        indicators = event.get("indicators", [])

        if not isinstance(indicators, list):
            raise ValueError(
                f"Event {index + 1}: indicators must be a list."
            )

        if len(indicators) > MAX_INDICATORS_PER_EVENT:
            raise ValueError(
                f"Event {index + 1}: too many indicators."
            )

        accepted_events.append(event)
        seen_in_event = set()

        for raw_indicator in indicators:
            if not isinstance(raw_indicator, str):
                continue

            # Extract canonical matched indicators (e.g. host extracted from URL)
            canonical_forms = extract_canonical_indicators(raw_indicator)

            for indicator in canonical_forms:
                if not indicator or indicator in seen_in_event:
                    continue

                seen_in_event.add(indicator)
                indicator_events[indicator].append({
                    "event_index": index,
                    "source": channel,
                })

    groups = []

    for indicator, matches in indicator_events.items():
        channels = sorted({match["source"] for match in matches})

        # Require the indicator to appear in at least two channels.
        if len(channels) < 2:
            continue

        event_indexes = sorted({
            match["event_index"] for match in matches
        })

        supplied_severities = []
        for event_index in event_indexes:
            severity = normalize_severity(
                accepted_events[event_index].get("severity")
            )
            if severity is not None:
                supplied_severities.append(severity)

        if supplied_severities:
            highest_severity = max(
                supplied_severities,
                key=lambda value: SEVERITY_RANK[value],
            )
            priority = highest_severity
        else:
            priority = "UNKNOWN"

        groups.append({
            "shared_indicator": indicator,
            "channels": channels,
            "event_indexes": event_indexes,
            "event_count": len(event_indexes),
            "evidence": [
                {
                    "event_index": match["event_index"],
                    "source": match["source"],
                }
                for match in matches
            ],
            "priority": priority,
            "severity_values_used": supplied_severities,
            "priority_explanation": PRIORITY_EXPLANATIONS[priority],
            "interpretation": (
                "The submitted events share an indicator. "
                "This is a data-level relationship, not proof of a "
                "common attacker or campaign."
            ),
        })

    groups.sort(
        key=lambda group: (
            -SEVERITY_RANK.get(group["priority"], 0),
            group["shared_indicator"],
        )
    )

    return {
        "success": True,
        "mode": "submitted_events",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_event_count": len(accepted_events),
        "correlated_group_count": len(groups),
        "correlated_groups": groups,
        "notice": (
            "Correlation uses submitted event records only. "
            "Priority is based only on supplied severity values. "
            "It does not perform network, URL, or SMS detection."
        ),
    }
