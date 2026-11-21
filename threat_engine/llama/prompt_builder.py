def build_prompt(threat):
    indicators = ", ".join(threat["indicators"])

    return (
        "Cybersecurity report.\n"
        f"Threat: {threat['threat_type']}. "
        f"Severity: {threat['severity']}. "
        f"Confidence: {threat['confidence']}. "
        f"Indicators: {indicators}.\n"
        "Risk: This is a"
    )
