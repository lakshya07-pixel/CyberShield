def create_threat_result(
    source,
    threat_type,
    severity,
    confidence,
    indicators,
    metadata=None,
    timestamp=None
):
    return {
        "source": source,
        "threat_type": threat_type,
        "severity": severity,
        "confidence": confidence,
        "indicators": indicators,
        "metadata": metadata or {},
        "timestamp": timestamp
    }