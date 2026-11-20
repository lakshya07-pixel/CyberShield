"""IP Geolocation and Telemetry Mapping Service.

Strict Standards:
- Rejects all fabricated or synthetic IP octet hashing/coordinate guessing.
- Private RFC 1918 addresses, loopbacks, link-local, reserved, and unmapped IPs
  are explicitly marked as unlocated.
- Geolocation coordinates are only returned if derived from an authentic database.
  In the absence of a local MaxMind/GeoIP database or reachable provider,
  the status is reported truthfully as 'geoip_unavailable' / 'unknown_location' with NO coordinates.
"""

import ipaddress
import re
from typing import Any, Dict, Optional


def classify_ip_address(ip_str: str) -> Dict[str, Any]:
    """
    Classifies an IP address string according to standard RFC specifications.
    Returns:
        dict with keys: 'ip', 'is_valid', 'version', 'category', 'is_routable'
    """
    if not ip_str or not isinstance(ip_str, str):
        return {"ip": str(ip_str), "is_valid": False, "category": "missing_ip", "is_routable": False}

    cleaned = ip_str.strip().split(":")[0].strip("[]")
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return {"ip": cleaned, "is_valid": False, "category": "invalid_ip", "is_routable": False}

    version = 4 if ip_obj.version == 4 else 6

    if ip_obj.is_loopback:
        category = "loopback"
    elif ip_obj.is_link_local:
        category = "link_local"
    elif ip_obj.is_private:
        category = "private_rfc1918" if version == 4 else "private_unique_local"
    elif ip_obj.is_reserved:
        category = "reserved"
    elif ip_obj.is_multicast:
        category = "multicast"
    elif ip_obj.is_global:
        category = "public_routable"
    else:
        category = "special_use"

    return {
        "ip": cleaned,
        "is_valid": True,
        "version": version,
        "category": category,
        "is_routable": (category == "public_routable"),
    }


def get_ip_geolocation(ip_str: str) -> Optional[Dict[str, Any]]:
    """
    Authentic IP geolocation lookup.
    Never fabricates coordinates or derives coordinates from IP octet hashes.
    If no authentic GeoIP database or provider is active, returns unlocated status.
    """
    cls = classify_ip_address(ip_str)
    if not cls["is_valid"]:
        return {
            "ip": cls["ip"],
            "location_available": False,
            "status": cls["category"],
            "reason": "Invalid or missing IP address string.",
            "city": "Unknown / Invalid",
            "country": "Unknown",
            "lat": None,
            "lon": None,
            "x": None,
            "y": None,
            "is_approximate": False,
        }

    if not cls["is_routable"]:
        reason_map = {
            "loopback": "Loopback address (127.0.0.0/8 or ::1); local host only.",
            "link_local": "Link-local address; non-routable on WAN.",
            "private_rfc1918": "Private RFC 1918 address (LAN); physical geolocation not available.",
            "private_unique_local": "IPv6 Unique Local Address (ULA); non-routable private network.",
            "reserved": "Reserved/special-use address block; no public geolocation.",
            "multicast": "Multicast group address; no single physical endpoint.",
        }
        return {
            "ip": cls["ip"],
            "location_available": False,
            "status": cls["category"],
            "reason": reason_map.get(cls["category"], "Non-routable network address."),
            "city": f"Internal Network ({cls['category']})",
            "country": "Private LAN / Special",
            "lat": None,
            "lon": None,
            "x": None,
            "y": None,
            "is_approximate": False,
        }

    # Public routable IP: Authentic lookup only
    # Check for genuine local GeoIP database (e.g. MaxMind mmdb) if present in environment
    try:
        import geoip2.database
        import os
        for candidate_path in ["data/GeoLite2-City.mmdb", "/usr/share/GeoIP/GeoLite2-City.mmdb"]:
            if os.path.exists(candidate_path):
                with geoip2.database.Reader(candidate_path) as reader:
                    resp = reader.city(cls["ip"])
                    if resp.location.latitude is not None and resp.location.longitude is not None:
                        lat = float(resp.location.latitude)
                        lon = float(resp.location.longitude)
                        if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
                            x_pct = round(((lon + 180.0) / 360.0) * 100.0, 2)
                            y_pct = round(((90.0 - lat) / 180.0) * 100.0, 2)
                            return {
                                "ip": cls["ip"],
                                "location_available": True,
                                "status": "located",
                                "city": resp.city.name or "Unknown City",
                                "country": resp.country.name or "Unknown Country",
                                "lat": lat,
                                "lon": lon,
                                "x": x_pct,
                                "y": y_pct,
                                "is_approximate": True,
                                "attribution_disclaimer": "MaxMind GeoLite2 lookup. Hosting/transit location, not physical attacker.",
                                "source": "maxmind_geolite2",
                            }
    except Exception:
        pass

    # No authentic database installed/available on this host.
    # Strictly report geoip_unavailable with NO coordinates.
    return {
        "ip": cls["ip"],
        "location_available": False,
        "status": "geoip_unavailable",
        "reason": "Authentic GeoLite2/MaxMind database not installed locally. Synthetic/guessed coordinates strictly prohibited.",
        "city": "Public IP (Location Unresolved)",
        "country": "Public WAN",
        "lat": None,
        "lon": None,
        "x": None,
        "y": None,
        "is_approximate": False,
        "source": "none",
    }
