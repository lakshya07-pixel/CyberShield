def get_recommendation(threat_type):
    if threat_type == "phishing":
        return "Do not open the link or enter your username, password, or other credentials."

    elif threat_type == "scam":
        return "Do not send money or share OTPs, passwords, or personal information."

    elif threat_type == "intrusion":
        return "Check the affected device and block or investigate suspicious network activity."

    elif threat_type in ("normal", "benign"):
        return "No threat-specific mitigation is required. Traffic is within normal operational parameters."

    else:
        return "Avoid interacting with the suspicious activity and investigate it further."
