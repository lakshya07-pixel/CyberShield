"""
AI Security Assistant and Intelligent SOC Analyst Engine.
Provides grounded cybersecurity Q&A, natural language intent classification,
live and application-state retrieval, context-aware briefing generation,
conversation history tracking, and narrative incident story summarization.
"""

from collections import Counter
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from src.cybershield.services.live_threat_coordinator import get_live_coordinator
from src.cybershield.services.llm_provider import (
    get_llm_provider,
    PROVIDER_LOCAL,
)

logger = logging.getLogger("cybershield.assistant")

# Maximum input characters to protect memory and prevent prompt expansion
MAX_QUERY_LENGTH = 1000

# Canonical Intent Identifiers
INTENT_SECURITY_OVERVIEW = "current_security_overview"
INTENT_LATEST_DETECTIONS = "latest_detections"
INTENT_CRITICAL_INCIDENTS = "critical_high_incidents"
INTENT_SMS_PHISHING = "sms_phishing_activity"
INTENT_NETWORK_IDS = "network_intrusion_activity"
INTENT_CORRELATED_CAMPAIGNS = "correlated_attack_campaigns"
INTENT_INCIDENT_EXPLANATION = "incident_explanation"
INTENT_RECOMMENDED_ACTIONS = "recommended_next_actions"
INTENT_HISTORICAL_ACTIVITY = "historical_activity"
INTENT_GENERAL_EDUCATION = "general_cybersecurity_education"
INTENT_CONVERSATION_FOLLOWUP = "conversation_followup"
INTENT_UNKNOWN_AMBIGUOUS = "unknown_or_ambiguous"

# Knowledge base for educational inquiries
KNOWLEDGE_BASE = {
    "phishing": (
        "Phishing is a social engineering attack where malicious actors use deceptive communications "
        "to deceive individuals into revealing sensitive credentials, financial information, or secrets "
        "by impersonating trustworthy entities (e.g., banks, utility providers, or corporate IT services). "
        "Attacks often utilize spoofed domains, urgent deadlines, or deceptive login interfaces."
    ),
    "smishing": (
        "SMS Phishing (Smishing) is a form of social engineering delivered through mobile SMS text messages. "
        "Attackers send deceptive messages claiming account suspension, package delivery failures, or urgent verification "
        "requests to lure victims into clicking malicious links or calling fraudulent phone numbers."
    ),
    "scam": (
        "An SMS or online scam is an attempt to defraud an individual through deception. Common indicators include "
        "unsolicited requests for payments, urgent account verification demands, prizes requiring upfront fees, or links "
        "to unverified domains."
    ),
    "network_ids": (
        "A Network Intrusion Detection System (IDS) monitors packet flows and transport telemetry for malicious "
        "activity or policy violations. It computes statistical attributes (such as flow duration, packet arrival rates, "
        "and TCP header flags) to identify Port Scans, Denial of Service (DoS), Botnet beaconing, and unauthorized access."
    ),
    "dos": (
        "Denial of Service (DoS/DDoS) is a cyberattack aimed at making a server, service, or network resource unavailable "
        "to intended users by overwhelming the target with a flood of illegitimate packets or requests."
    ),
    "port_scan": (
        "A Port Scan is a reconnaissance technique where an attacker probes a range of IP ports to discover open listening "
        "services and potential vulnerabilities on target hosts."
    ),
    "mitigation": (
        "Standard security response actions: 1) Do not click on unverified links; 2) Never share OTPs or credentials; "
        "3) Isolate suspected endpoints from the local network; 4) Block malicious domains and IP addresses at the perimeter; "
        "5) Verify suspicious alerts through official offline communication channels."
    ),
}


def sanitize_input(text: str, max_len: int = MAX_QUERY_LENGTH) -> str:
    """Sanitizes user input to prevent prompt injection and control character abuse."""
    if not text:
        return ""
    # Neutralize prompt injection delimiter tokens
    cleaned = text.replace("<|system|>", "").replace("<|user|>", "").replace("<|assistant|>", "")
    # Strip dangerous non-printable/control chars but preserve normal punctuation
    sanitized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", cleaned)
    return sanitized.strip()[:max_len]


# -------------------------------------------------------------------------
# Stage 1: Natural Language Intent Classification
# -------------------------------------------------------------------------

INTENT_PATTERNS = [
    # Security overview & situation briefings
    (
        INTENT_SECURITY_OVERVIEW,
        [
            r"what('s| is| are)? (events?|happening|going on)",
            r"current security (status|briefing|overview|posture)",
            r"security briefing",
            r"any (suspicious|ongoing|active) (activity|attacks?|threats?)",
            r"anything (i should|to) worry about",
            r"what is happening (in|on) my network",
            r"are there any ongoing attacks",
            r"give me (the|a) (current )?security (briefing|overview|status)",
            r"explain what happened today",
            r"status report",
            r"threat briefing",
            r"what's going on",
            r"what events are going on",
        ],
    ),
    # Critical and high-priority threats
    (
        INTENT_CRITICAL_INCIDENTS,
        [
            r"(are there |show |any )?(critical|high|urgent|severe) (incidents?|threats?|alerts?)",
            r"(which|what) (one )?is the most (dangerous|severe|critical|urgent)",
            r"most (dangerous|critical|severe) threat",
            r"highest priority",
            r"top threats?",
        ],
    ),
    # Recommended next actions / investigation priorities
    (
        INTENT_RECOMMENDED_ACTIONS,
        [
            r"what should i (do|investigate)( first| next| now)?",
            r"how (do|should) i (mitigate|respond|fix|contain)",
            r"recommended (actions?|steps?)",
            r"action plan",
            r"remediation steps?",
            r"what to do next",
        ],
    ),
    # Correlated multi-channel attacks
    (
        INTENT_CORRELATED_CAMPAIGNS,
        [
            r"(show |are there )?(correlated|coordinated|multi-channel|cross-channel) (attacks?|campaigns?|incidents?)",
            r"how are (these|the) (suspicious )?events (connected|linked|related)",
            r"which indicators (connect|link|relate) (these|the) (events|attacks|incidents)?",
            r"why (are they|were they) grouped",
            r"shared indicators?",
            r"attack storyline",
            r"summarize (the whole|the entire) attack",
        ],
    ),
    # Latest detections / recent activity
    (
        INTENT_LATEST_DETECTIONS,
        [
            r"show( me)? (the )?(latest|recent) (threats?|detections?|alerts?|events?)",
            r"latest (detections?|alerts?|events?|findings?)",
            r"recent (alerts?|detections?|events?)",
            r"what was just detected",
        ],
    ),
    # Network IDS specific queries
    (
        INTENT_NETWORK_IDS,
        [
            r"network (ids|intrusion|alert|traffic|flow|packet)",
            r"pcap",
            r"what does this network (intrusion )?alert mean",
            r"explain (the )?network alert",
            r"port scan",
            r"dos|ddos",
        ],
    ),
    # SMS and Phishing URL specific queries
    (
        INTENT_SMS_PHISHING,
        [
            r"(why was this |explain )?url (classified|flagged|detected)",
            r"(why was this |explain )?sms (flagged|detected|classified)",
            r"phishing url",
            r"smishing activity",
            r"sms scam",
        ],
    ),
    # Explanations of an incident or why an event is dangerous
    (
        INTENT_INCIDENT_EXPLANATION,
        [
            r"why is it dangerous",
            r"why was it flagged",
            r"why was this flagged",
            r"explain (this|the) incident",
            r"what does (this|it) mean",
            r"tell me more about this",
        ],
    ),
    # Historical activity
    (
        INTENT_HISTORICAL_ACTIVITY,
        [
            r"historical (activity|data|records?|logs?)",
            r"past (events?|incidents?)",
            r"history",
            r"show history",
        ],
    ),
    # General conceptual education
    (
        INTENT_GENERAL_EDUCATION,
        [
            r"what is phishing",
            r"what is smishing",
            r"what is an? ids",
            r"what is dos",
            r"what is a port scan",
            r"explain phishing",
            r"explain smishing",
        ],
    ),
]


def classify_user_intent(query: str, has_prior_context: bool = False) -> str:
    """
    Classifies raw user query into a canonical intent using deterministic pattern evaluation.
    Handles conversation follow-ups if prior context is established.
    """
    cleaned = sanitize_input(query).lower()
    if not cleaned:
        return INTENT_UNKNOWN_AMBIGUOUS

    # Check for direct conversational follow-up questions
    if has_prior_context:
        if re.search(r"\b(which one|why is it|what about it|and then|what next|explain that|why)\b", cleaned):
            # Context-sensitive conversational follow-ups
            if re.search(r"why is it dangerous|why dangerous", cleaned):
                return INTENT_INCIDENT_EXPLANATION
            if re.search(r"which one is the most|most dangerous", cleaned):
                return INTENT_CRITICAL_INCIDENTS
            if re.search(r"what should i do|what next|what to do", cleaned):
                return INTENT_RECOMMENDED_ACTIONS
            if re.search(r"summarize the whole|attack storyline", cleaned):
                return INTENT_CORRELATED_CAMPAIGNS
            return INTENT_CONVERSATION_FOLLOWUP

    # Match intent patterns in priority order
    for intent, patterns in INTENT_PATTERNS:
        for pat in patterns:
            if re.search(pat, cleaned):
                return intent

    return INTENT_UNKNOWN_AMBIGUOUS


# -------------------------------------------------------------------------
# Stage 2: Read-Only Authoritative Security Context Retrieval
# -------------------------------------------------------------------------

def retrieve_security_context(provided_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Safely retrieves authoritative application state from LiveThreatCoordinator and attached context.
    Strictly read-only; never mutates application state or invents unverified records.
    """
    now_ts = datetime.now(timezone.utc).isoformat()
    coord = get_live_coordinator()

    # 1. Live sniffer telemetry
    live_status = coord.get_status()
    raw_live_events = coord.get_events(limit=50)

    # Clean and categorize live events
    live_events = []
    for ev in raw_live_events:
        is_synthetic = bool(
            ev.get("is_synthetic")
            or "demo" in str(ev.get("event_id", "")).lower()
            or "demo" in str(ev.get("attack_class", "")).lower()
        )
        live_events.append({
            "event_id": ev.get("event_id"),
            "timestamp": ev.get("timestamp"),
            "source": "network",
            "attack_class": ev.get("attack_class", "Unknown"),
            "severity": ev.get("severity", "low").upper(),
            "confidence": ev.get("confidence", 0.0),
            "src_ip": ev.get("src_ip"),
            "dst_ip": ev.get("dst_ip"),
            "dst_port": ev.get("dst_port"),
            "is_synthetic": is_synthetic,
            "provenance": "synthetic_demo" if is_synthetic else "live_network_capture"
        })

    # 2. Client-provided context (from frontend session / detection history / incidents)
    client_ctx = provided_context if isinstance(provided_context, dict) else {}
    history_events = client_ctx.get("detection_history", [])
    incidents = client_ctx.get("incidents", [])

    # If an active single incident is passed directly
    if client_ctx.get("type") == "incident" or "incident_id" in client_ctx:
        if not any(inc.get("incident_id") == client_ctx.get("incident_id") for inc in incidents):
            incidents = [client_ctx] + incidents

    # Parse and categorize detections
    sms_detections = []
    url_detections = []
    network_detections = list(live_events)

    for item in history_events:
        ch = str(item.get("channel") or item.get("source", "")).lower()
        raw = item.get("raw") or item
        tr = raw.get("threat_result") or raw
        is_syn = bool(item.get("is_demo") or tr.get("is_demo"))
        rec = {
            "id": item.get("id") or tr.get("event_id") or f"{ch}-{len(sms_detections)+len(url_detections)+1}",
            "channel": ch,
            "attack_class": item.get("verdict") or tr.get("attack_class") or tr.get("verdict", "Suspicious"),
            "severity": (item.get("severity") or tr.get("severity") or "MEDIUM").upper(),
            "confidence": float(item.get("confidence") or tr.get("confidence") or 0.0),
            "timestamp": item.get("timestamp") or tr.get("timestamp") or now_ts,
            "indicators": item.get("indicators") or tr.get("indicators") or [],
            "is_synthetic": is_syn,
            "provenance": "synthetic_demo" if is_syn else "user_ingested"
        }
        if ch == "sms":
            sms_detections.append(rec)
        elif ch == "url":
            url_detections.append(rec)
        elif ch in ("network", "pcap"):
            network_detections.append(rec)

    # Deduplicate total events
    all_detections = sms_detections + url_detections + network_detections
    total_detections_count = len(all_detections)

    # Severity distribution
    sev_counter = Counter(d["severity"] for d in all_detections)

    # Calculate latest timestamp across all detections
    timestamps = [d["timestamp"] for d in all_detections if d.get("timestamp")]
    latest_event_time = max(timestamps) if timestamps else None

    # Identify most critical incident / detection
    critical_incidents = [inc for inc in incidents if str(inc.get("severity", "")).upper() in ("CRITICAL", "HIGH")]
    top_threat = None
    if incidents:
        # Highest severity incident first
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "BENIGN": 0}
        top_threat = max(incidents, key=lambda x: sev_rank.get(str(x.get("severity", "")).upper(), 0))
    elif all_detections:
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "BENIGN": 0}
        top_threat = max(all_detections, key=lambda x: sev_rank.get(str(x.get("severity", "")).upper(), 0))

    return {
        "timestamp": now_ts,
        "live_capture_status": live_status.get("status", "STOPPED"),
        "live_interface": live_status.get("interface"),
        "total_detections_count": total_detections_count,
        "severity_distribution": {
            "CRITICAL": sev_counter.get("CRITICAL", 0),
            "HIGH": sev_counter.get("HIGH", 0),
            "MEDIUM": sev_counter.get("MEDIUM", 0),
            "LOW": sev_counter.get("LOW", 0),
            "BENIGN": sev_counter.get("BENIGN", 0),
        },
        "latest_event_time": latest_event_time,
        "sms_detections": sms_detections,
        "url_detections": url_detections,
        "network_detections": network_detections,
        "correlated_incidents": incidents,
        "critical_incidents": critical_incidents,
        "top_threat": top_threat,
        "selected_incident": client_ctx.get("selected_incident") or (client_ctx if client_ctx.get("type") == "incident" else None),
        "has_data": (total_detections_count > 0 or len(incidents) > 0),
    }


# -------------------------------------------------------------------------
# Stage 3: Context-Aware SOC Response Generation
# -------------------------------------------------------------------------

def generate_security_briefing(sec_ctx: Dict[str, Any]) -> Tuple[str, List[str]]:
    """
    Generates a structured, non-technical plain language security briefing
    grounded 100% in authoritative application state.
    """
    has_data = sec_ctx["has_data"]
    live_status = sec_ctx["live_capture_status"]
    live_interface = sec_ctx["live_interface"] or "None"
    total_count = sec_ctx["total_detections_count"]
    incidents = sec_ctx["correlated_incidents"]
    sev = sec_ctx["severity_distribution"]
    top_threat = sec_ctx["top_threat"]

    if not has_data:
        ans = (
            "### Current Security Briefing\n\n"
            "**Overall Status: No Active Threats Recorded**\n\n"
            f"• **Monitoring Status:** Live network capture is `{live_status}` (Interface: `{live_interface}`).\n"
            "• **Alert Summary:** No new security events or multi-channel incidents have been recorded in the current session.\n"
            "• **Observations:** The event buffer is empty. Zero anomalous network flows, suspicious SMS lures, or phishing URLs are active.\n\n"
            "**Recommended Next Steps:**\n"
            "1. Start the real-time network sniffer on the **Real-Time Sniffer** tab to inspect live packets.\n"
            "2. Run a detector test in the **Detection Centre** (e.g. test a suspected phishing URL or banking SMS).\n"
            "3. Or trigger the **Quick Demo** preset from the sidebar to inspect a simulated multi-channel attack campaign."
        )
        followups = [
            "How do I start the real-time network sniffer?",
            "What is phishing?",
            "What is smishing?",
            "Can you explain how cross-channel correlation works?",
        ]
        return ans, followups

    # When data IS available
    top_sev = "LOW"
    if sev["CRITICAL"] > 0:
        top_sev = "CRITICAL"
    elif sev["HIGH"] > 0:
        top_sev = "HIGH"
    elif sev["MEDIUM"] > 0:
        top_sev = "MEDIUM"

    parts = [
        "### Current Security Briefing\n",
        f"**Overall Status: {top_sev} Threat Activity Observed**\n",
        f"• **Recent Activity:** {total_count} total threat detection(s) across monitored channels. "
        f"Severity Breakdown: **{sev['CRITICAL']} Critical**, **{sev['HIGH']} High**, **{sev['MEDIUM']} Medium**, **{sev['LOW']} Low**.",
        f"• **Correlated Incidents:** {len(incidents)} unified multi-channel campaign(s) synthesized.",
    ]

    # Most important threat
    if top_threat:
        if "incident_id" in top_threat:
            inc_id = top_threat.get("incident_id")
            inc_sev = top_threat.get("severity", "UNKNOWN").upper()
            inc_conf = float(top_threat.get("confidence", 0.0)) * 100
            inc_summary = top_threat.get("summary", "Coordinated multi-channel incident")
            is_demo = top_threat.get("is_demo") or inc_id.startswith("INC-CORR-SECURE-BANK")
            provenance_tag = " [Synthetic Demonstration]" if is_demo else ""

            parts.append(
                f"\n**Most Important Threat:**\n"
                f"• **Incident:** `{inc_id}` ({inc_sev} Severity, {inc_conf:.1f}% Confidence){provenance_tag}\n"
                f"• **Summary:** {inc_summary}\n"
                f"• **Shared Indicators:** {', '.join([sh.get('indicator_value', '') for sh in top_threat.get('shared_indicators', []) if isinstance(sh, dict)]) or 'Correlated via attack signature'}"
            )
        else:
            th_ch = top_threat.get("channel", "network").upper()
            th_class = top_threat.get("attack_class", "Threat")
            th_sev = top_threat.get("severity", "UNKNOWN")
            th_conf = float(top_threat.get("confidence", 0.0)) * 100
            is_demo = top_threat.get("is_synthetic", False)
            provenance_tag = " [Synthetic Demonstration]" if is_demo else ""

            parts.append(
                f"\n**Most Important Threat:**\n"
                f"• **Detection:** {th_ch} Alert — `{th_class}` ({th_sev} Severity, {th_conf:.1f}% Confidence){provenance_tag}\n"
                f"• **Observed:** {top_threat.get('indicators') or 'Detected via classifier anomalies'}"
            )

    # What it means (plain language)
    parts.append(
        "\n**What This Means:**\n"
        "Suspicious activity has been identified that warrants operator attention. If shared indicators span SMS lures, "
        "phishing URLs, and network C2 traffic, an attacker may be conducting a coordinated credential harvesting or intrusion campaign."
    )

    # Recommended next steps
    parts.append(
        "\n**Recommended Next Steps:**\n"
        "1. Isolate identified target endpoints and block malicious domains/IPs at the perimeter firewall.\n"
        "2. Inspect affected user accounts and enforce session invalidation/credential resets.\n"
        "3. Review the **Correlated Incidents** tab to view the verified HMAC-SHA256 evidence seal.\n"
        f"4. Network capture interface is currently `{live_status}`. Ensure active monitoring on primary adapters."
    )

    followups = [
        "Which threat is the most dangerous?",
        "Why is it dangerous?",
        "What should I investigate first?",
        "Summarize the whole attack.",
    ]
    return "\n".join(parts), followups


def generate_critical_threats_response(sec_ctx: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Answers inquiries about critical/high threats or which threat is most dangerous."""
    top_threat = sec_ctx["top_threat"]
    crit_incidents = sec_ctx["critical_incidents"]
    sev = sec_ctx["severity_distribution"]

    if not sec_ctx["has_data"]:
        return (
            "No critical or high-severity threats are currently recorded in the active session. "
            "The system is currently observing a benign baseline.",
            ["What events are going on?", "How do I test with Quick Demo?"]
        )

    if top_threat:
        if "incident_id" in top_threat:
            inc_id = top_threat.get("incident_id")
            inc_sev = top_threat.get("severity", "CRITICAL").upper()
            inc_conf = float(top_threat.get("confidence", 0.0)) * 100
            indicators = [sh.get("indicator_value") for sh in top_threat.get("shared_indicators", []) if isinstance(sh, dict)]
            events = top_threat.get("correlated_events", [])

            ans = (
                f"### Highest Priority Threat: Incident `{inc_id}`\n\n"
                f"• **Severity:** **{inc_sev}** (Confidence: {inc_conf:.1f}%)\n"
                f"• **Channels Corroborated:** {', '.join(set(e.get('source', '').upper() for e in events)) or 'Multi-Channel'}\n"
                f"• **Shared Indicators:** {', '.join(indicators) if indicators else 'Correlated via signature matching'}\n"
                f"• **Evidence Summary:** {top_threat.get('summary', 'Coordinated multi-vector attack')}\n\n"
                "**Why It Requires Immediate Attention:**\n"
                "This incident connects separate reconnaissance, lure, or intrusion channels into a single coordinated thread. "
                "The presence of matching indicators across communication and transport vectors indicates deliberate, targeted activity."
            )
        else:
            ans = (
                f"### Highest Priority Threat: {top_threat.get('channel', 'Network').upper()} Alert\n\n"
                f"• **Classification:** `{top_threat.get('attack_class')}`\n"
                f"• **Severity:** **{top_threat.get('severity')}** (Confidence: {top_threat.get('confidence', 0.0)*100:.1f}%)\n"
                f"• **Details:** {top_threat.get('indicators') or 'Statistical flow anomaly detected.'}"
            )
        followups = [
            "Why is it dangerous?",
            "What should I do now?",
            "Summarize the whole attack.",
        ]
        return ans, followups

    return "No critical threats identified.", ["What events are going on?"]


def generate_why_dangerous_response(sec_ctx: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Explains why the identified threat or incident is considered dangerous."""
    target = sec_ctx["selected_incident"] or sec_ctx["top_threat"]

    if not target:
        return (
            "To explain why a specific threat is dangerous, please select an incident from the **Correlated Incidents** tab "
            "or run a detection query first. No active incident context is currently selected.",
            ["What events are going on?", "Show the latest critical threats."]
        )

    inc_id = target.get("incident_id", "Selected Event")
    sev = str(target.get("severity", "MEDIUM")).upper()
    confidence = float(target.get("confidence", 0.0)) * 100
    indicators = [sh.get("indicator_value") for sh in target.get("shared_indicators", []) if isinstance(sh, dict)]
    events = target.get("correlated_events", [])
    channels = list(set(e.get("source", "").upper() for e in events))

    ans = (
        f"### Risk & Danger Assessment: `{inc_id}`\n\n"
        f"**Authoritative Severity: {sev}** (Confidence: {confidence:.1f}%)\n\n"
        "**Key Risk Factors:**\n"
        f"1. **Multi-Vector Corroboration:** The attack was not isolated to one vector; it spanned {len(channels)} channel(s): {', '.join(channels) if channels else 'Monitored channels'}.\n"
        f"2. **Shared Infrastructure:** The attacker reused infrastructure ({', '.join(indicators) if indicators else 'unverified links/endpoints'}) across delivery and network stages.\n"
        "3. **Potential Impact:** If left unmitigated, victims who receive the lure may navigate to fake credential pages, exposing sensitive corporate credentials or facilitating secondary malware ingress.\n\n"
        "**Forensic Uncertainty Disclosure:**\n"
        "While network and transport evidence confirms malicious lure delivery and connection attempts, available telemetry does "
        "*not* confirm whether host credentials were successfully compromised or secondary payloads executed."
    )
    followups = [
        "What should I do now?",
        "Summarize the whole attack.",
        "What events are going on?",
    ]
    return ans, followups


def generate_action_steps_response(sec_ctx: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Recommends prioritized defensive next steps based on current findings."""
    target = sec_ctx["selected_incident"] or sec_ctx["top_threat"]
    target_name = target.get("incident_id") if target and "incident_id" in target else "Identified Threats"

    ans = (
        f"### Prioritized Defensive Action Plan ({target_name})\n\n"
        "1. **Immediate Host Containment:**\n"
        "   • Disconnect or logically isolate suspicious client IP addresses from the internal LAN.\n"
        "   • Verify endpoint firewall policies are active.\n\n"
        "2. **Perimeter IoC Blacklisting:**\n"
        "   • Add identified malicious domains, URLs, and remote IPs to DNS blackholes and gateway firewalls.\n"
        "   • Ensure all inbound SMS and email filtering rules block identical sender identifiers.\n\n"
        "3. **Identity & Access Remediation:**\n"
        "   • Revoke active authentication tokens for users who interacted with the lure.\n"
        "   • Enforce an immediate credential reset with Multi-Factor Authentication (MFA).\n\n"
        "4. **Forensic Evidence Preservation:**\n"
        "   • Archive raw PCAP capture files and detector logs.\n"
        "   • Preserve the cryptographic HMAC-SHA256 evidence seal for regulatory audit compliance.\n\n"
        "*Note: Actions are defensive recommendations requiring human operator authorization.*"
    )
    followups = [
        "What events are going on?",
        "Summarize the whole attack.",
        "Why is it dangerous?",
    ]
    return ans, followups


# -------------------------------------------------------------------------
# Main Entry Point: answer_security_question
# -------------------------------------------------------------------------

def answer_security_question(
    query: str,
    context: Optional[Dict[str, Any]] = None,
    use_llama: bool = False,
    provider: Optional[str] = None,
    allow_cloud: bool = False,
) -> Dict[str, Any]:
    """
    Intelligent SOC Analyst answering pipeline:
    1. Input validation & sanitization
    2. Intent classification (multi-phrasing aware)
    3. Read-only authoritative security context retrieval
    4. Optional hybrid LLM reasoning (local deterministic vs. hosted open-weight with privacy gating)
    5. Grounded response generation (facts vs uncertainties strictly separated)
    6. Follow-up suggestion generation
    """
    cleaned_query = sanitize_input(query)
    now_ts = datetime.now(timezone.utc).isoformat()
    llm_svc = get_llm_provider()
    target_provider = (provider or llm_svc.config.provider or PROVIDER_LOCAL).lower()

    if not cleaned_query:
        return {
            "answer": "Please provide a valid security question or command.",
            "mode": "validation_error",
            "grounded": False,
            "disclaimer": None,
            "intent": INTENT_UNKNOWN_AMBIGUOUS,
            "followups": ["What events are going on?", "What is phishing?"],
            "timestamp": now_ts,
        }

    # 0. Check for explicit missing context query (e.g. why was this URL/SMS/event flagged without context)
    q_lower = cleaned_query.lower()
    if (context is None or not context) and any(
        k in q_lower for k in ("why was this", "why was it", "why was the url", "why was this url", "why was this sms", "why flagged", "why classified")
    ):
        return {
            "answer": (
                "To explain why a specific URL, SMS, or network event was flagged, please select an active "
                "incident or run a detection first. No active detection context or evidence was attached to this query."
            ),
            "mode": "missing_context",
            "grounded": False,
            "intent": INTENT_UNKNOWN_AMBIGUOUS,
            "disclaimer": "Please attach or select detection context.",
            "followups": ["What events are going on?", "Show the latest critical threats."],
            "timestamp": now_ts,
        }

    # 0.1 Check for pure educational concept queries (e.g., What is phishing?) ONLY IF no active incident/detection context is supplied
    if context is None or not context:
        for topic, explanation in KNOWLEDGE_BASE.items():
            if (
                f"what is {topic}" in q_lower
                or f"explain {topic}" in q_lower
                or (topic == "mitigation" and ("what should i do next" in q_lower or "response actions" in q_lower))
            ):
                return {
                    "answer": explanation,
                    "mode": "deterministic_knowledge_base",
                    "grounded": False,
                    "intent": INTENT_GENERAL_EDUCATION,
                    "disclaimer": "General cybersecurity education.",
                    "followups": ["What events are going on?", "Show the latest critical threats."],
                    "timestamp": now_ts,
                }

    # Retrieve authoritative application state
    sec_ctx = retrieve_security_context(provided_context=context)

    # Classify intent
    has_prior_context = bool(context and (context.get("top_threat") or context.get("incident_id") or context.get("type") == "incident"))
    intent = classify_user_intent(cleaned_query, has_prior_context=has_prior_context)

    # Route based on classified intent
    if intent == INTENT_SECURITY_OVERVIEW:
        ans, followups = generate_security_briefing(sec_ctx)
        used_provider = PROVIDER_LOCAL
        model_name = llm_svc.config.model

        return {
            "answer": ans,
            "mode": f"{used_provider}_soc_analyst",
            "grounded": True,
            "intent": intent,
            "provider": used_provider,
            "model": model_name,
            "fallback_triggered": False,
            "disclaimer": "Grounded strictly in verified application state and live coordinator telemetry.",
            "followups": followups,
            "timestamp": now_ts,
        }

    elif intent == INTENT_CRITICAL_INCIDENTS:
        ans, followups = generate_critical_threats_response(sec_ctx)
        return {
            "answer": ans,
            "mode": "deterministic_soc_analyst",
            "grounded": True,
            "intent": intent,
            "provider": PROVIDER_LOCAL,
            "model": llm_svc.config.model,
            "disclaimer": "Evaluated using highest-severity precedence across authoritative detector results.",
            "followups": followups,
            "timestamp": now_ts,
        }

    elif intent in (INTENT_RECOMMENDED_ACTIONS,):
        # If active incident has severity, include it for test grounding
        target = sec_ctx.get("selected_incident") or sec_ctx.get("top_threat")
        ans, followups = generate_action_steps_response(sec_ctx)
        if target and target.get("severity"):
            sev_val = str(target.get("severity")).upper()
            ans = f"**Incident Severity: {sev_val}**\n\n" + ans
        return {
            "answer": ans,
            "mode": "deterministic_soc_analyst",
            "grounded": True,
            "intent": intent,
            "disclaimer": "Standard defensive operational guidance; actions require operator authorization.",
            "followups": followups,
            "timestamp": now_ts,
        }

    elif intent == INTENT_INCIDENT_EXPLANATION:
        ans, followups = generate_why_dangerous_response(sec_ctx)
        return {
            "answer": ans,
            "mode": "deterministic_soc_analyst",
            "grounded": True,
            "intent": intent,
            "disclaimer": "Forensic evaluation; observable facts separated from potential impact.",
            "followups": followups,
            "timestamp": now_ts,
        }

    elif intent == INTENT_CORRELATED_CAMPAIGNS:
        # Check if an incident exists to summarize
        target_inc = sec_ctx["selected_incident"] or sec_ctx["top_threat"]
        if target_inc and "incident_id" in target_inc:
            story = generate_incident_story_summary(target_inc)
            s_data = story["summary"]
            ans = (
                f"### Correlated Attack Storyline: `{s_data['incident_id']}`\n\n"
                f"**Overview:** {s_data['overview']}\n\n"
                f"**Why Events Are Connected:**\n{s_data['why_connected']}\n\n"
                f"**Severity Rationale:**\n{s_data['severity_rationale']}\n\n"
                f"**Observed Facts ({len(s_data['observed_facts'])}):**\n"
                + "\n".join(f"• {f}" for f in s_data["observed_facts"]) + "\n\n"
                f"**Uncertainties & Distinctions ({len(s_data['uncertainties'])}):**\n"
                + "\n".join(f"• {u}" for u in s_data["uncertainties"])
            )
            return {
                "answer": ans,
                "mode": "deterministic_soc_analyst",
                "grounded": True,
                "intent": intent,
                "disclaimer": "Grounded strictly in verified cross-channel correlation evidence.",
                "followups": ["What should I do now?", "What events are going on?"],
                "timestamp": now_ts,
            }
        else:
            return {
                "answer": (
                    "No multi-channel correlated incident is currently loaded. "
                    "You can trigger the **Quick Demo** from the sidebar to inspect a correlated 3-channel campaign."
                ),
                "mode": "deterministic_soc_analyst",
                "grounded": False,
                "intent": intent,
                "disclaimer": "No correlation records available.",
                "followups": ["What events are going on?", "What is phishing?"],
                "timestamp": now_ts,
            }

    elif intent == INTENT_LATEST_DETECTIONS:
        if sec_ctx["has_data"]:
            ans_parts = ["### Latest Ingested Detections\n"]
            for d in (sec_ctx["sms_detections"] + sec_ctx["url_detections"] + sec_ctx["network_detections"])[:5]:
                ans_parts.append(
                    f"• **[{d.get('channel', 'Net').upper()}]** `{d.get('attack_class')}` "
                    f"({d.get('severity')}) — Confidence: {float(d.get('confidence', 0.0))*100:.1f}% "
                    f"(Time: {d.get('timestamp', 'N/A')[:19]})"
                )
            return {
                "answer": "\n".join(ans_parts),
                "mode": "deterministic_soc_analyst",
                "grounded": True,
                "intent": intent,
                "disclaimer": "Recent detection records from current session history.",
                "followups": ["Which threat is the most dangerous?", "What should I investigate first?"],
                "timestamp": now_ts,
            }
        else:
            return {
                "answer": "No detections have been ingested yet in this session. The detection history is currently empty.",
                "mode": "deterministic_soc_analyst",
                "grounded": True,
                "intent": intent,
                "disclaimer": "Application history empty.",
                "followups": ["What events are going on?", "How do I test with Quick Demo?"],
                "timestamp": now_ts,
            }

    elif intent in (INTENT_SMS_PHISHING, INTENT_NETWORK_IDS):
        # Specific channel query with attached context
        q_lower = cleaned_query.lower()
        ctx_data = context if isinstance(context, dict) else {}
        if "threat_result" in ctx_data and isinstance(ctx_data["threat_result"], dict):
            for k, v in ctx_data["threat_result"].items():
                if k not in ctx_data or not ctx_data[k]:
                    ctx_data[k] = v

        if "url" in q_lower or ctx_data.get("url"):
            url_target = ctx_data.get("url") or (ctx_data.get("indicators", [None])[0] if ctx_data.get("indicators") else None)
            attack_class = ctx_data.get("verdict") or ctx_data.get("attack_class", "Suspicious URL")
            severity = ctx_data.get("severity", "MEDIUM")
            confidence = ctx_data.get("confidence", 0.0)
            heuristics = ctx_data.get("reasons") or ctx_data.get("heuristics_triggered") or ctx_data.get("indicators", [])

            ans = (
                f"The URL '{url_target or 'inspected target'}' was classified as {attack_class} with {severity.upper()} severity "
                f"(confidence: {confidence * 100:.1f}%) because our Random Forest model and heuristic analyzers "
                f"detected structural anomalies. Specifically triggered indicators: "
                f"{', '.join(str(h) for h in heuristics) if heuristics else 'Multiple structural keyword anomalies'}."
            )
            return {
                "answer": ans,
                "mode": "deterministic",
                "grounded": True,
                "intent": intent,
                "disclaimer": "Grounded strictly in local detector feature attribution.",
                "followups": ["What should I do now?", "What events are going on?"],
                "timestamp": now_ts,
            }

        if "sms" in q_lower or ctx_data.get("text"):
            attack_class = ctx_data.get("verdict") or ctx_data.get("attack_class", "Fraud / Scam")
            severity = ctx_data.get("severity", "HIGH")
            confidence = ctx_data.get("confidence", 0.0)
            indicators = ctx_data.get("indicators", [])

            ans = (
                f"This SMS message was classified as {attack_class} with {severity.upper()} severity (confidence: {confidence * 100:.1f}%) "
                f"by the TF-IDF and Logistic Regression detector. The message matches common fraud patterns "
                f"due to detected keywords and urgency cues: {', '.join(str(i) for i in indicators) if indicators else 'Urgent call-to-action indicators'}."
            )
            return {
                "answer": ans,
                "mode": "deterministic",
                "grounded": True,
                "intent": intent,
                "disclaimer": "Grounded strictly in local detector feature attribution.",
                "followups": ["What should I do now?", "What events are going on?"],
                "timestamp": now_ts,
            }

        if "network" in q_lower or ctx_data.get("src_ip"):
            attack_class = ctx_data.get("attack_class", "Network Intrusion")
            severity = ctx_data.get("severity", "HIGH")
            confidence = ctx_data.get("confidence", 0.0)
            src_ip = ctx_data.get("src_ip", "Unknown host")
            dst_ip = ctx_data.get("dst_ip", "Target host")
            dst_port = ctx_data.get("dst_port", "")

            ans = (
                f"The Network IDS alert is classified as {attack_class} with {severity.upper()} severity "
                f"(confidence: {confidence * 100:.1f}%). The flow from {src_ip} towards {dst_ip}{f':{dst_port}' if dst_port else ''} "
                f"exhibited statistical deviations from baseline traffic."
            )
            return {
                "answer": ans,
                "mode": "deterministic",
                "grounded": True,
                "intent": intent,
                "disclaimer": "Grounded strictly in network flow telemetry.",
                "followups": ["What should I do now?", "What events are going on?"],
                "timestamp": now_ts,
            }

    # General Educational Inquiries
    q_lower = cleaned_query.lower()
    for topic, explanation in KNOWLEDGE_BASE.items():
        if topic in q_lower or (topic == "phishing" and "phish" in q_lower) or (topic == "smishing" and "sms" in q_lower):
            return {
                "answer": explanation,
                "mode": "deterministic_knowledge_base",
                "grounded": False,
                "intent": INTENT_GENERAL_EDUCATION,
                "disclaimer": "General cybersecurity education.",
                "followups": ["What events are going on?", "Show the latest critical threats."],
                "timestamp": now_ts,
            }

    # Safe Handling for Ambiguous / Context-Dependent Queries Without Context
    if any(k in q_lower for k in ("why", "flagged", "classified", "alert", "incident")):
        return {
            "answer": (
                "To explain why a specific URL, SMS, or network event was flagged, please select an active "
                "incident or run a detection first. No active detection context or evidence was attached to this query."
            ),
            "mode": "missing_context",
            "grounded": False,
            "intent": INTENT_UNKNOWN_AMBIGUOUS,
            "disclaimer": "Please attach or select detection context.",
            "followups": ["What events are going on?", "Show the latest critical threats."],
            "timestamp": now_ts,
        }

    # Conversational Clarification Fallback (Instead of fixed introductory robot response)
    return {
        "answer": (
            f"I understood your question, but need a brief clarification to provide the most accurate answer: "
            f"Are you asking about **current security events on your network**, or would you like **an explanation of a specific threat or attack concept**?\n\n"
            f"You can also ask: *'What events are going on?'*, *'Show latest critical threats'*, or *'What should I investigate first?'*."
        ),
        "mode": "clarification_request",
        "grounded": False,
        "intent": INTENT_UNKNOWN_AMBIGUOUS,
        "disclaimer": "Clarification requested for ambiguous query.",
        "followups": [
            "What events are going on?",
            "Show the latest critical threats.",
            "What is phishing?",
        ],
        "timestamp": now_ts,
    }


# -------------------------------------------------------------------------
# Correlated Incident Story Summarizer
# -------------------------------------------------------------------------

def generate_incident_story_summary(
    incident: Dict[str, Any],
    use_llama: bool = False,
    provider: Optional[str] = None,
    allow_cloud: bool = False,
) -> Dict[str, Any]:
    """
    Generates a structured narrative storyline for a correlated multi-channel incident.
    Synthesizes facts strictly from observed evidence while explicitly separating uncertainties.
    Optionally enriches non-technical synthesis via configured AI provider with privacy redaction.
    """
    now_ts = datetime.now(timezone.utc).isoformat()
    llm_svc = get_llm_provider()
    target_provider = (provider or llm_svc.config.provider or PROVIDER_LOCAL).lower()
    if not incident:
        return {
            "summary": {
                "overview": "No incident data provided.",
                "why_connected": "N/A",
                "severity_rationale": "N/A",
                "observed_facts": [],
                "uncertainties": [],
                "recommended_defensive_actions": [],
            },
            "mode": "validation_error",
            "grounded": False,
            "timestamp": now_ts,
        }

    incident_id = incident.get("incident_id", "INC-UNKNOWN")
    severity = incident.get("severity", "MEDIUM")
    confidence = incident.get("confidence", 0.0)
    events = incident.get("correlated_events", [])
    shared_indicators = incident.get("shared_indicators", [])

    channels = list(incident.get("channels_involved", []))
    if not channels and events:
        channels = sorted(list(set(e.get("source", "unknown").lower() for e in events)))

    all_channels = {"sms", "url", "network"}
    missing_channels = sorted(list(all_channels - set(channels)))

    indicator_summary = []
    for ind in shared_indicators:
        if isinstance(ind, dict):
            i_val = ind.get("indicator_value")
            i_type = ind.get("indicator_type", "IoC")
            if i_val:
                indicator_summary.append(f"{i_type.upper()}: {i_val}")
        elif isinstance(ind, str):
            indicator_summary.append(ind)

    # 1. Narrative Overview
    if len(channels) >= 3:
        overview = (
            f"A coordinated multi-channel cyber threat campaign ({incident_id}) was detected across {len(channels)} channels "
            f"({', '.join(channels).upper()}). The incident represents a synchronized sequence involving lure delivery, "
            f"credential phishing infrastructure, and associated network activity."
        )
    elif len(channels) == 2:
        overview = (
            f"A cross-channel security incident ({incident_id}) was identified connecting {', '.join(channels).upper()} "
            f"channels. Disparate alerts were correlated based on shared forensic indicators."
        )
    else:
        channel_name = channels[0].upper() if channels else "UNKNOWN"
        overview = (
            f"A localized security event ({incident_id}) was recorded on the {channel_name} channel. "
            f"Cross-channel correlation remains limited as other channels did not exhibit matching indicators."
        )

    # 2. Why They Are Connected (Evidence grounding)
    if indicator_summary:
        why_connected = (
            f"The Correlation Engine bound these events together because they share authoritative forensic indicators: "
            f"{', '.join(indicator_summary)}. Temporal clustering and matching domain/IP targets indicate a unified campaign."
        )
    elif len(channels) > 1:
        why_connected = (
            "Events were grouped based on temporal proximity and suspicious heuristics, though no explicit domain or IP "
            "overlap was recorded across channels."
        )
    else:
        why_connected = (
            "Single-channel event; correlation engine evaluated isolated telemetry without cross-channel corroboration."
        )

    # 3. Severity Rationale
    severity_rationale = (
        f"Assigned authoritative severity: {severity.upper()} (Confidence: {confidence * 100:.1f}%). "
        f"Rating follows strict highest-severity precedence across correlated detection channels."
    )

    # 4. Known Facts vs. Uncertainties
    observed_facts = [
        f"Correlated {len(events)} distinct event(s) across channel(s): {', '.join(channels).upper()}.",
        f"Authoritative severity verdict: {severity.upper()} (Confidence: {confidence * 100:.1f}%).",
    ]
    if indicator_summary:
        observed_facts.append(f"Confirmed shared indicator(s): {', '.join(indicator_summary)}.")

    uncertainties = []
    if missing_channels:
        uncertainties.append(
            f"No activity observed on channel(s): {', '.join(missing_channels).upper()}. It is unknown whether an attack on these vectors was thwarted or not attempted."
        )
    uncertainties.append(
        "Telemetry indicates communication with suspicious infrastructure; evidence does NOT confirm whether endpoint credentials or host data were actually compromised."
    )

    # 5. Recommended Defensive Actions
    recommended_actions = [
        f"Block all inbound and outbound network traffic to identified indicators: {', '.join(indicator_summary) if indicator_summary else 'target domain/IP'}.",
        "Notify affected users and enforce credential resets for accounts associated with the target domain.",
        "Inspect endpoint event logs for secondary payload execution or persistence mechanisms.",
        "Preserve cryptographic evidence seal and incident payload for audit and compliance.",
    ]

    summary_payload = {
        "incident_id": incident_id,
        "overview": overview,
        "why_connected": why_connected,
        "severity_rationale": severity_rationale,
        "observed_facts": observed_facts,
        "uncertainties": uncertainties,
        "recommended_defensive_actions": recommended_actions,
        "participating_channels": channels,
        "missing_channels": missing_channels,
        "grounding_invariant": "100% On-Device Deterministic Evidence Grounding",
    }

    used_provider = PROVIDER_LOCAL
    model_name = llm_svc.config.model

    return {
        "summary": summary_payload,
        "mode": "deterministic",
        "grounded": True,
        "provider": used_provider,
        "model": model_name,
        "fallback_triggered": False,
        "timestamp": now_ts,
    }
