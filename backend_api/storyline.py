"""Chronological attack storyline generator for correlated incidents.

Transforms correlated multi-channel security events into an evidence-backed
chronological attack narrative with simple-language analyst explanations.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
import sys
from pathlib import Path

# Ensure person1_submission is in path
root = Path(__file__).resolve().parent.parent
p1_path = root / "person1_submission" / "bharat_ai_soc"
if str(p1_path) not in sys.path:
    sys.path.append(str(p1_path))
    sys.path.append(str(p1_path / "src"))

from src.bharat_ai_soc.correlation.engine import CorrelationEngine
from src.bharat_ai_soc.correlation.models import verify_incident_integrity


def build_attack_storyline(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts a unified incident record into a chronological attack storyline.
    """
    events = incident.get("correlated_events", [])
    
    # Sort events chronologically by timestamp if available
    sorted_events = sorted(events, key=lambda e: e.get("timestamp") or "")

    stages: List[Dict[str, Any]] = []
    for idx, ev in enumerate(sorted_events, 1):
        src = str(ev.get("source", "unknown")).lower()
        sev = str(ev.get("severity", "LOW")).upper()
        ts = ev.get("timestamp") or "Sensor timestamp unrecorded"
        
        if src == "sms":
            title = "Stage 1: Social Engineering Lure Received (SMS)"
            text_preview = ev.get("text") or ev.get("metadata", {}).get("cleaned_text_preview") or "Suspicious message payload"
            desc = f'A smishing message was delivered containing an urgent call-to-action: "{text_preview}"'
            reason = "Initial attack vector designed to lure victim into visiting malicious credential harvesting portal."
        elif src == "url":
            title = "Stage 2: Deceptive Phishing Destination Analyzed"
            u = ev.get("url") or "Target phishing URL"
            desc = f'URL inspection of "{u}" revealed high-risk structural anomalies and brand impersonation.'
            reason = "Deceptive infrastructure matching the bait delivered in the initial SMS lure."
        elif src == "network":
            title = "Stage 3: Outbound Network Communication / Flow Observed"
            dst = ev.get("dst_ip") or "remote host"
            dns = ev.get("dns_query") or ev.get("sni") or "N/A"
            desc = f"Network telemetry recorded connection or DNS resolution to {dst} (query: {dns})."
            reason = "Active communication attempt verifying endpoint attempted to reach the malicious destination."
        else:
            title = f"Stage {idx}: {src.upper()} Telemetry Record"
            desc = f"Anomalous {src.upper()} observation recorded with severity {sev}."
            reason = "Correlated threat telemetry matching campaign indicator."

        stages.append({
            "stage_number": idx,
            "source": src,
            "title": title,
            "description": desc,
            "timestamp": ts,
            "severity": sev,
            "confidence": float(ev.get("confidence", 0.5)),
            "indicators": ev.get("indicators", []),
            "reason": reason,
        })

    shared_inds = [sh.get("indicator_value") for sh in incident.get("shared_indicators", []) if sh.get("indicator_value")]
    channels = sorted(list({s.get("source") for s in stages}))

    return {
        "incident_id": incident.get("incident_id", "UNKNOWN"),
        "overall_severity": incident.get("severity", "MEDIUM"),
        "confidence": incident.get("confidence", 0.5),
        "created_at": incident.get("created_at", datetime.now(timezone.utc).isoformat()),
        "sha256_signature": incident.get("sha256_signature", ""),
        "channels": channels,
        "shared_indicators": incident.get("shared_indicators", []),
        "stages": stages,
        "simple_explanation": {
            "what_happened": f"A coordinated attack campaign spanning {len(channels)} distinct channels ({', '.join(channels)}) was detected.",
            "why_suspicious": f"Separate security detectors independently observed matching indicators (e.g. {', '.join(shared_inds[:3])}) within a short time window.",
            "evidence": shared_inds,
            "what_affected": "User credentials, endpoint integrity, and corporate communications.",
            "next_steps": incident.get("advisory", {}).get("actionable_steps", [
                "Block malicious domain and DNS queries at firewall/proxy.",
                "Isolate impacted user endpoint for forensics review.",
                "Invalidate potentially compromised session tokens or credentials."
            ])
        }
    }


def generate_storyline_from_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Ingests raw events, executes correlation, and generates the attack storyline.
    """
    engine = CorrelationEngine()
    engine.ingest_events(events)
    incidents = engine.correlate()
    
    if not incidents:
        return {
            "success": True,
            "incident_count": 0,
            "storylines": [],
            "notice": "No multi-channel incidents were identified from the supplied events."
        }
        
    storylines = [build_attack_storyline(inc) for inc in incidents]
    return {
        "success": True,
        "incident_count": len(incidents),
        "storylines": storylines,
        "notice": "Chronological attack storylines constructed from verified detector evidence."
    }

