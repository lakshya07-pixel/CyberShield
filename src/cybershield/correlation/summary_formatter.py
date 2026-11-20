import re
from typing import Dict, Any, List, Optional

ANSI_ESCAPE_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
CONTROL_CHARS_REGEX = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')

def sanitize_text(text: Any) -> str:
    """
    Strips ANSI escape codes and unprintable control characters to prevent
    terminal injection or formatting distortion when rendering untrusted strings.
    """
    if text is None:
        return "N/A"
    s = str(text)
    s = ANSI_ESCAPE_REGEX.sub('', s)
    s = CONTROL_CHARS_REGEX.sub('', s)
    return s.strip()

def mask_phone_token(val: str) -> str:
    """
    Masks the last 4 digits of a phone number for privacy in human reports.
    """
    clean = re.sub(r'\s+', '', val)
    if len(clean) >= 8:
        return clean[:-4] + "****"
    return clean

def format_judge_summary(incident: Dict[str, Any], verified_integrity: Optional[bool] = None) -> str:
    """
    Renders an 8-section, human-readable, judge-friendly summary of a Unified Incident Record.
    Adheres strictly to the authoritative incident fields and explains the derivation policies,
    provenance, and operational unknowns.
    """
    lines: List[str] = []
    sep = "=" * 80
    subsep = "-" * 80

    lines.append(sep)
    lines.append("                    CYBERSHIELD INCIDENT CORRELATION DOSSIER")
    lines.append(sep)

    # -------------------------------------------------------------------------
    # SECTION A: INCIDENT IDENTITY
    # -------------------------------------------------------------------------
    inc_id = sanitize_text(incident.get("incident_id", "UNKNOWN"))
    status = sanitize_text(incident.get("status", "UNSPECIFIED"))
    created_at = sanitize_text(incident.get("created_at", "N/A (Timestamp not provided)"))
    schema_ver = "1.0.0 (Unified CyberShield Incident Record)"
    sig = incident.get("sha256_signature", "")

    if verified_integrity is True:
        seal_status = f"{sig[:16]}... [VERIFIED / PASS]"
    elif verified_integrity is False:
        seal_status = f"{sig[:16]}... [VERIFICATION FAILED / TAMPER DETECTED]"
    elif sig:
        seal_status = f"{sig[:16]}... [SEALED (Integrity check not requested)]"
    else:
        seal_status = "UNSEALED / NO SIGNATURE PRESENT"

    lines.append("[SECTION A: INCIDENT IDENTITY]")
    lines.append(f"  Incident ID:         {inc_id}")
    lines.append(f"  Status:              {status}")
    lines.append(f"  Generated At (UTC):  {created_at}")
    lines.append(f"  Schema Version:      {schema_ver}")
    lines.append(f"  Integrity Seal:      {seal_status}")
    lines.append("")

    # -------------------------------------------------------------------------
    # SECTION B: CORRELATED EVIDENCE SOURCES
    # -------------------------------------------------------------------------
    events = incident.get("correlated_events", [])
    lines.append(f"[SECTION B: CORRELATED EVIDENCE SOURCES ({len(events)} Linked Channels)]")
    if not events:
        lines.append("  No event records attached to this incident.")
    else:
        for idx, ev in enumerate(events, 1):
            src = sanitize_text(ev.get("source", "unknown")).upper()
            atk_class = sanitize_text(ev.get("attack_class", ev.get("threat_type", "Unknown")))
            sev = sanitize_text(ev.get("severity", "BENIGN")).upper()
            conf = ev.get("confidence")
            conf_str = f"{float(conf):.4f}" if conf is not None else "N/A"
            ts = sanitize_text(ev.get("timestamp", "Timestamp unrecorded by sensor"))

            lines.append(f"  {idx}. [{src}] Source Observation:")
            lines.append(f"     - Verdict / Class:   {atk_class} (Severity: {sev}, Confidence: {conf_str})")
            lines.append(f"     - Sensor Timestamp:  {ts}")

            if src == "SMS":
                meta = ev.get("metadata", {})
                preview = sanitize_text(meta.get("cleaned_text_preview", ev.get("text", "N/A")))
                if len(preview) > 90:
                    preview = preview[:87] + "..."
                lines.append(f"     - Message Content:   \"{preview}\"")
                if "extracted_urls" in meta:
                    lines.append(f"     - Extracted URLs:    {', '.join(sanitize_text(u) for u in meta['extracted_urls'])}")

            elif src == "URL":
                u = sanitize_text(ev.get("url", "N/A"))
                lines.append(f"     - Evaluated URL:     {u}")
                heur = ev.get("metadata", {}).get("heuristics_triggered", [])
                if heur:
                    lines.append(f"     - Heuristics:        {', '.join(sanitize_text(h) for h in heur)}")

            elif src == "NETWORK":
                flow_idx = ev.get("flow_index", "N/A")
                dst_ip = sanitize_text(ev.get("dst_ip", "N/A"))
                dst_port = sanitize_text(ev.get("dst_port", "N/A"))
                dns_q = sanitize_text(ev.get("dns_query", ev.get("sni", "N/A")))
                lines.append(f"     - Flow Details:      Flow #{flow_idx} -> Target: {dst_ip}:{dst_port} (DNS/SNI: {dns_q})")
            lines.append("")

    # -------------------------------------------------------------------------
    # SECTION C: SHARED INDICATORS & MATCHING RULES
    # -------------------------------------------------------------------------
    shared = incident.get("shared_indicators", [])
    lines.append("[SECTION C: SHARED INDICATORS & MATCHING RULES]")
    if not shared:
        lines.append("  No shared indicators recorded.")
    else:
        for sh in shared:
            itype = sanitize_text(sh.get("indicator_type", "unknown"))
            ival = sanitize_text(sh.get("indicator_value", "unknown"))
            sources = [sanitize_text(s) for s in sh.get("participating_sources", [])]
            if itype == "domain":
                rule = "Canonical domain FQDN extracted via URL netloc / DNS query normalization (RFC 3986)"
            elif itype == "url":
                rule = "Exact normalized URL string match across lure and web evaluation"
            elif itype == "ip":
                rule = "Canonical IPv4/IPv6 address normalization (RFC 791/4291)"
            elif itype == "phone":
                rule = "Normalized phone token match (E.164 / 10-digit standard)"
                ival = mask_phone_token(ival)
            else:
                rule = "Syntactic token exact match"

            lines.append(f"  - [{itype}] \"{ival}\"")
            lines.append(f"    * Sources Linked:     {', '.join(sources)}")
            lines.append(f"    * Extraction Rule:    {rule}")
    lines.append("")

    # -------------------------------------------------------------------------
    # SECTION D: CORRELATION RATIONALE
    # -------------------------------------------------------------------------
    lines.append("[SECTION D: CORRELATION RATIONALE]")
    participating_sources = sorted(list({ev.get("source", "unknown") for ev in events}))
    domain_matches = [sh.get("indicator_value") for sh in shared if sh.get("indicator_type") == "domain"]

    if domain_matches:
        domain_str = ", ".join(f"'{d}'" for d in domain_matches)
        lines.append(f"  * Deterministic Linkage: Events across {len(participating_sources)} channels ({', '.join(participating_sources)})")
        lines.append(f"    were deterministically linked because they share exact matching normalized")
        lines.append(f"    target domain(s): {domain_str}.")
    else:
        lines.append(f"  * Deterministic Linkage: Events across {', '.join(participating_sources)} channels share normalized indicators.")

    if "network" in participating_sources:
        lines.append("  * Network Evidence Scope: The network observation confirms active communication")
        lines.append("    attempt / DNS lookup targeting this host. It does NOT assert application-layer")
        lines.append("    compromise without payload verification.")
    lines.append("")

    # -------------------------------------------------------------------------
    # SECTION E: SEVERITY DERIVATION
    # -------------------------------------------------------------------------
    final_sev = sanitize_text(incident.get("severity", "BENIGN")).upper()
    source_sevs = [f"{ev.get('source', 'unknown').upper()}:{ev.get('severity', 'BENIGN').upper()}" for ev in events]

    lines.append("[SECTION E: SEVERITY DERIVATION]")
    lines.append(f"  * Final Incident Severity: {final_sev}")
    lines.append("  * Policy Applied:          Highest-Severity Precedence (CRITICAL > HIGH > MEDIUM > LOW > BENIGN)")
    lines.append(f"  * Source Findings:         {', '.join(source_sevs)}")
    lines.append(f"  * Explanation:             The unified incident inherits the highest authoritative severity")
    lines.append(f"                             verdict ({final_sev}) from its participating detector inputs.")
    lines.append("")

    # -------------------------------------------------------------------------
    # SECTION F: CONFIDENCE DERIVATION
    # -------------------------------------------------------------------------
    final_conf = incident.get("confidence")
    conf_val_str = f"{float(final_conf):.4f}" if final_conf is not None else "N/A"
    source_confs = [f"{ev.get('source', 'unknown').upper()}:{float(ev.get('confidence', 0.5)):.4f}" for ev in events if ev.get("confidence") is not None]

    lines.append("[SECTION F: CONFIDENCE DERIVATION]")
    lines.append(f"  * Final Incident Confidence: {conf_val_str}")
    lines.append("  * Policy Applied:            Multi-Channel Boost Heuristic")
    lines.append(f"  * Source Confidences:        {', '.join(source_confs) if source_confs else 'None'}")
    lines.append("  * Calculation Rule:          min(1.0, max(source_confidences) + 0.05 * (distinct_channels - 1))")
    lines.append("  * Statistical Disclaimer:    This value represents an evidentiary boost based on multi-sensor")
    lines.append("                               reinforcement; it is not a calibrated Bayesian posterior probability.")
    lines.append("")

    # -------------------------------------------------------------------------
    # SECTION G: UNKNOWNS & OPERATIONAL LIMITATIONS
    # -------------------------------------------------------------------------
    lines.append("[SECTION G: UNKNOWNS & OPERATIONAL LIMITATIONS]")
    lines.append("  - Attribution: It cannot be determined from telemetry alone whether the SMS sender,")
    lines.append("    web server, and network destination are operated by the identical physical threat actor.")
    lines.append("  - Causality & Compromise: A shared indicator proves coordinated targeting; it does")
    lines.append("    not prove that malware successfully compromised the device or exfiltrated data.")
    lines.append("  - Temporal Ordering: Timestamps originate from independent local sensor clocks; microsecond")
    lines.append("    event sequencing is unverified.")
    lines.append("")

    # -------------------------------------------------------------------------
    # SECTION H: INTEGRITY STATUS
    # -------------------------------------------------------------------------
    lines.append("[SECTION H: INTEGRITY STATUS]")
    lines.append(f"  - SHA-256 Digest:     {sig if sig else 'None'}")
    lines.append(f"  - Verification Check: {'PERFORMED' if verified_integrity is not None else 'NOT REQUESTED'}")
    lines.append(f"  - Result:             {seal_status}")
    if verified_integrity is False:
        lines.append("  ! WARNING: The cryptographic signature does not match canonical incident contents!")
    lines.append(sep)

    return "\n".join(lines)

