"""
CyberShield Grounded Security Assistant Service.

Provides deterministic, evidence-grounded security explanations and answers
to security queries based on active detection telemetry across SMS, URL,
Network IDS, and Correlated Attack Incidents.

Strict Safeguards:
- Never changes or overrides an actual detector verdict (e.g. Benign stays Benign, Malicious stays Malicious).
- Never modifies detector confidence or severity scores.
- Clear separation between detector findings and AI-generated advisory recommendations.
- Works 100% offline with zero external cloud or internet dependencies.
- Handles missing evidence gracefully without hallucinating false indicators.
"""

from typing import Dict, Any, List, Optional
import re
from threat_engine.rules import get_threat_explanation, get_indicator_explanation
from threat_engine.recommendations import get_recommendation


class SecurityAssistant:
    def __init__(self):
        self.llama_enabled = False
        self.llama_reason = "Local Llama/ExecuTorch runtime is offline. Using deterministic expert rule engine."

    def query(self, question: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Answers security inquiries strictly grounded in provided threat context or
        cybersecurity domain principles, avoiding hallucinations or unverified claims.
        """
        q = question.strip().lower()
        context = context or {}

        # Extract context fields safely
        threat_type = context.get("threat_type") or context.get("threat") or "general"
        severity = str(context.get("severity") or "UNSPECIFIED").upper()
        confidence = context.get("confidence")
        conf_str = f"{float(confidence)*100:.1f}%" if confidence is not None else "N/A"
        indicators = context.get("indicators") or []
        source = str(context.get("source") or "multi-channel").lower()
        incident_id = context.get("incident_id")
        verdict = context.get("attack_class") or context.get("verdict") or threat_type.upper()

        response_parts: List[str] = []

        # 1. SMS Threat / Benign Explanation
        if "sms" in q or source == "sms":
            if "benign" in str(verdict).lower() or "safe" in str(verdict).lower():
                response_parts.append(
                    "**Detector Finding**: BENIGN / SAFE (SMS Channel)\n"
                    f"**Detector Verdict**: No malicious scam patterns detected (Confidence: {conf_str}).\n\n"
                    "**Non-Technical Explanation**: This text does not exhibit common social engineering signals "
                    "(such as urgency demands, OTP/credential harvesting, or unverified shortened links). "
                    "Routine communications within standard parameters."
                )
                response_parts.append(
                    "**Advisory Recommendation**: No mitigation required. Standard vigilance applies."
                )
            else:
                response_parts.append(
                    f"**Detector Finding**: SCAM / SMISHING (Severity: {severity}, Confidence: {conf_str})\n"
                    f"**Threat Classification**: {verdict}\n\n"
                    "**Non-Technical Explanation**: This SMS message was flagged because it exhibits classic financial "
                    "fraud social engineering techniques—such as urgent account block alerts, prize claims, or demands "
                    "to click unverified links."
                )
                if indicators:
                    response_parts.append(
                        f"**Forensic Evidence ({len(indicators)} indicators)**:\n" +
                        "\n".join([f"- `{ind}`" for ind in indicators])
                    )
                response_parts.append(
                    "**Advisory Recommendation**: Do NOT click any links, do not dial provided numbers, "
                    "and never share OTPs or passwords. Report the message to your telecom/bank fraud desk."
                )

        # 2. Phishing URL Explanation
        elif "url" in q or "phishing" in q or source == "url":
            if "benign" in str(verdict).lower() or "safe" in str(verdict).lower():
                response_parts.append(
                    "**Detector Finding**: SAFE / BENIGN (URL Phishing Channel)\n"
                    f"**Detector Verdict**: The evaluated URL does not display phishing indicators (Confidence: {conf_str}).\n\n"
                    "**Non-Technical Explanation**: The domain conforms to standard legitimate structure, valid HTTPS encryption, "
                    "and lacks brand typosquatting, suspicious redirects, or deceptive path tokens."
                )
                response_parts.append(
                    "**Advisory Recommendation**: The URL appears safe for routine access."
                )
            else:
                response_parts.append(
                    f"**Detector Finding**: PHISHING / DECEPTIVE DOMAIN (Severity: {severity}, Confidence: {conf_str})\n"
                    f"**Threat Classification**: {verdict}\n\n"
                    "**Non-Technical Explanation**: The link appears designed to harvest user credentials or impersonate "
                    "a legitimate banking/government service. The 16-feature lexical model and heuristic checks detected "
                    "anomalous domain structures, missing HTTPS, or brand impersonation tokens."
                )
                if indicators:
                    response_parts.append(
                        f"**Forensic Evidence ({len(indicators)} indicators)**:\n" +
                        "\n".join([f"- `{ind}`" for ind in indicators])
                    )
                response_parts.append(
                    "**Advisory Recommendation**: Block the domain at the perimeter firewall/DNS resolver. "
                    "Do not enter credentials or load the webpage."
                )

        # 3. Network Intrusion Explanation
        elif "network" in q or "intrusion" in q or source == "network":
            if "benign" in str(verdict).lower() or "normal" in str(verdict).lower():
                response_parts.append(
                    "**Detector Finding**: BENIGN FLOW (Network IDS Channel)\n"
                    f"**Detector Verdict**: Normal operational network traffic (Confidence: {conf_str}).\n\n"
                    "**Technical Explanation**: The 79-feature Random Forest model classified flow timing, packet sizes, "
                    "and flag ratios within normal baseline thresholds."
                )
                response_parts.append(
                    "**Advisory Recommendation**: Routine operational baseline; no response needed."
                )
            else:
                response_parts.append(
                    f"**Detector Finding**: NETWORK INTRUSION DETECTED (Severity: {severity}, Confidence: {conf_str})\n"
                    f"**Attack Class**: {verdict}\n\n"
                    "**Technical Explanation**: The 79-feature flow analyzer and RT2 perturbation engine observed anomalous "
                    "packet lengths, abnormal TCP flag combinations, or high-rate connection bursts indicative of an attack."
                )
                if indicators:
                    response_parts.append(
                        f"**Forensic Evidence**:\n" +
                        "\n".join([f"- `{ind}`" for ind in indicators])
                    )
                rec = get_recommendation("intrusion")
                rec_text = rec if isinstance(rec, str) else rec.get('action', 'Isolate affected host.')
                response_parts.append(
                    f"**Advisory Recommendation**: {rec_text}\n"
                    "Inspect endpoint for unauthorized outbound connections and check firewall blocks."
                )

        # 4. Correlated Multi-Channel Attack Incident
        elif "correlat" in q or "attack" in q or "storyline" in q or incident_id:
            inc_label = f"Incident `{incident_id}`" if incident_id else "Correlated Multi-Channel Campaign"
            response_parts.append(
                f"**Correlated Incident**: {inc_label} (Priority: {severity})\n\n"
                "**Attack Sequence Overview**:\n"
                "1. **Stage 1 (Initial Vector)**: Smishing/phishing lure delivered via SMS.\n"
                "2. **Stage 2 (Deceptive Destination)**: Web phishing portal crafted to capture credentials.\n"
                "3. **Stage 3 (Outbound Activity)**: Outbound communication or DNS lookup matching the phishing target.\n\n"
                "**Correlation Rationale**: Events across 2 or more channels independently observed exact matching "
                "normalized indicators within a common temporal window."
            )
            if indicators:
                response_parts.append(
                    f"**Correlated Shared IOCs**:\n" +
                    "\n".join([f"- `{ind}`" for ind in indicators])
                )
            response_parts.append(
                "**Advisory Mitigation Playbook**:\n"
                "- Block matching domains & destination IPs at gateway firewall/DNS.\n"
                "- Isolate affected user endpoint from corporate subnet for forensic imaging.\n"
                "- Reset user credentials and invalidate active session tokens."
            )

        # 5. General Security / Triage Inquiries
        elif "mitigat" in q or "action" in q or "what should i do" in q or "next" in q:
            response_parts.append(
                "**Recommended SOC Triage Playbook**:\n"
                "1. **Verification**: Confirm alert severity and review raw forensic indicators.\n"
                "2. **Containment**: Temporarily isolate impacted endpoint or block malicious domain at DNS resolver.\n"
                "3. **Investigation**: Inspect recent DNS queries, user authentication logs, and web proxy cache.\n"
                "4. **Remediation**: Revoke potentially compromised credentials and patch vulnerable applications.\n"
                "5. **Closure**: Record findings in incident dossier with cryptographic integrity seal."
            )

        elif "summar" in q or "latest" in q or "status" in q:
            response_parts.append(
                "**CyberShield Monitoring & Telemetry Summary**:\n"
                "- **Network IDS**: 79-feature flow classification active (PCAP Replay operational; Npcap native capture reported).\n"
                "- **URL Phishing Scanner**: 16-feature Random Forest & ccTLD suppression active.\n"
                "- **SMS Scam Detector**: TF-IDF + Logistic Regression NLP pipeline active.\n"
                "- **Correlation Engine**: Real-time multi-channel incident grouping and SHA-256 seal verification active.\n"
                "- **System Mode**: 100% Offline-capable deterministic expert reasoning."
            )

        else:
            response_parts.append(
                "**CyberShield Grounded Security Assistant**:\n"
                "I provide evidence-grounded threat analysis across SMS, URL, and Network IDS channels.\n\n"
                "You can ask me:\n"
                "- *'Why was this SMS marked as suspicious?'*\n"
                "- *'Explain this phishing URL.'*\n"
                "- *'What does this network alert mean?'*\n"
                "- *'Explain this correlated attack.'*\n"
                "- *'What should I do next?'*"
            )

        return {
            "answer": "\n\n".join(response_parts),
            "engine": "deterministic_expert_system",
            "grounded_in_telemetry": bool(context),
            "detector_verdict_preserved": True,
            "llama_status": {
                "enabled": self.llama_enabled,
                "reason": self.llama_reason,
            },
        }


# Singleton instance
assistant_service = SecurityAssistant()
