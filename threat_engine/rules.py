def get_threat_explanation(threat_type, indicators):
    if threat_type == "phishing":
        return "This may be a phishing attempt designed to steal sensitive information."

    elif threat_type == "scam":
        return "This message may be a scam attempting to trick the user into sending money or personal information."

    elif threat_type == "intrusion":
        return "Suspicious network activity was detected and may indicate an unauthorized intrusion."

    elif threat_type in ("normal", "benign"):
        return "Routine benign network activity was observed. Traffic characteristics are within normal operational baseline."

    else:
        return "A potentially suspicious activity was detected."


def get_indicator_explanation(indicators):
    explanations = []

    for indicator in indicators:
        if "normal" in indicator.lower() or "benign" in indicator.lower():
            explanations.append(f"Observed baseline: {indicator}")
        else:
            explanations.append(f"Suspicious indicator: {indicator}")

    return explanations
