from dataclasses import dataclass, field
from typing import List


@dataclass
class ThreatResult:
    source: str
    threat_type: str
    attack_class: str
    severity: str
    confidence: float
    indicators: List[str] = field(default_factory=list)


SEVERITY_MAP = {
    "BENIGN": "low",
    "Bot": "high",
    "DDoS": "high",
    "DoS": "medium",
    "DoS GoldenEye": "medium",
    "DoS Hulk": "medium",
    "DoS Slowhttptest": "medium",
    "DoS slowloris": "medium",
    "Patator": "medium",
    "FTP-Patator": "medium",
    "Heartbleed": "high",
    "Infiltration": "high",
    "PortScan": "medium",
    "SSH-Patator": "medium",
    "Web Attack": "high",
    "Web Attack – Brute Force": "high",
    "Web Attack – Sql Injection": "high",
    "Web Attack – XSS": "high",
}
