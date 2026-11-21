def calculate_severity(confidence):
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        raise ValueError("Confidence must be a number between 0 and 1.")

    if not 0 <= confidence <= 1:
        raise ValueError("Confidence must be between 0 and 1.")

    if confidence >= 0.90:
        return "critical"
    elif confidence >= 0.75:
        return "high"
    elif confidence >= 0.50:
        return "medium"
    else:
        return "low"
