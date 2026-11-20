"""
Stateful Behavioral Port-Scan and Network Reconnaissance Detector.
Maintains cross-flow state per source IP within a configurable sliding time window
to detect horizontal, vertical, and distributed scanning patterns without modifying
underlying ML model weights or per-flow inference contracts.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
import datetime
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cybershield.behavioral_scanner")


@dataclass
class ScanObservation:
    timestamp: float
    dst_ip: str
    dst_port: int
    protocol: int
    tcp_flags: str
    packet_count: int


@dataclass
class ScanAlert:
    alert_id: str
    timestamp: str
    src_ip: str
    target_hosts: List[str]
    distinct_ports_count: int
    ports_targeted: List[int]
    window_duration_seconds: float
    scan_type: str  # "horizontal_port_scan", "vertical_host_scan", "syn_reconnaissance"
    severity: str   # "high", "critical"
    confidence: float
    evidence: str
    remediation_recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "target_hosts": self.target_hosts,
            "distinct_ports_count": self.distinct_ports_count,
            "ports_targeted": self.ports_targeted,
            "window_duration_seconds": round(self.window_duration_seconds, 2),
            "scan_type": self.scan_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "remediation_recommendation": self.remediation_recommendation,
        }


class BehavioralPortScanDetector:
    """
    Thread-safe, memory-bounded cross-flow port scan detector.
    Analyzes finalized and in-flight flows to detect multi-port probing patterns.
    """

    def __init__(
        self,
        window_seconds: float = 30.0,
        port_threshold: int = 5,
        max_tracked_ips: int = 5000,
        cleanup_interval_seconds: float = 10.0,
    ):
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        self.max_tracked_ips = max_tracked_ips
        self.cleanup_interval_seconds = cleanup_interval_seconds

        self._lock = threading.Lock()
        # Mapping: src_ip -> deque of ScanObservation
        self._history: Dict[str, deque] = defaultdict(deque)
        # Tracks already alerted signatures to prevent duplicate alerts per burst
        self._alerted_signatures: Dict[str, float] = {}
        self._last_cleanup = time.time()
        self.total_alerts_emitted = 0

    def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        proto: int,
        timestamp: Optional[float] = None,
        tcp_flags: str = "",
        packet_count: int = 1,
    ) -> Optional[ScanAlert]:
        """
        Records a flow observation and evaluates whether the source IP exceeds scanning thresholds.
        Returns a ScanAlert if a scan pattern is detected, otherwise None.
        """
        now = timestamp if timestamp is not None else time.time()

        with self._lock:
            # Periodic memory bounded cleanup
            if now - self._last_cleanup > self.cleanup_interval_seconds:
                self._prune_expired(now)

            # Prevent unbounded growth of tracked source IPs
            if len(self._history) >= self.max_tracked_ips and src_ip not in self._history:
                # Evict oldest tracked IP
                oldest_ip = next(iter(self._history))
                del self._history[oldest_ip]

            # Append new observation
            obs = ScanObservation(
                timestamp=now,
                dst_ip=str(dst_ip),
                dst_port=int(dport),
                protocol=int(proto),
                tcp_flags=tcp_flags,
                packet_count=packet_count,
            )
            dq = self._history[src_ip]
            dq.append(obs)

            # Evict observations outside the sliding window for this IP
            cutoff = now - self.window_seconds
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()

            # Analyze observations in the active window
            distinct_ports = {o.dst_port for o in dq}
            distinct_hosts = {o.dst_ip for o in dq}

            if len(distinct_ports) >= self.port_threshold:
                # Dedup alert signature: (src_ip, rounded port count) to avoid flood
                sig = f"{src_ip}:{len(distinct_ports) // 5}"
                last_alert_time = self._alerted_signatures.get(sig, 0.0)

                # Rate limit repeated alerts for same burst (minimum 10 seconds apart)
                if now - last_alert_time >= 10.0:
                    self._alerted_signatures[sig] = now
                    self.total_alerts_emitted += 1

                    win_duration = max(0.1, now - dq[0].timestamp)
                    sample_ports = sorted(list(distinct_ports))[:15]
                    is_critical = len(distinct_ports) >= 20

                    alert = ScanAlert(
                        alert_id=f"scan-{src_ip.replace('.', '-')}-{int(now)}",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        src_ip=src_ip,
                        target_hosts=sorted(list(distinct_hosts)),
                        distinct_ports_count=len(distinct_ports),
                        ports_targeted=sample_ports,
                        window_duration_seconds=win_duration,
                        scan_type="horizontal_port_scan" if len(distinct_hosts) == 1 else "distributed_network_sweep",
                        severity="critical" if is_critical else "high",
                        confidence=min(0.99, 0.80 + (len(distinct_ports) * 0.005)),
                        evidence=(
                            f"Host {src_ip} initiated reconnaissance against {len(distinct_ports)} distinct ports "
                            f"on target(s) {', '.join(sorted(list(distinct_hosts))[:3])} within {win_duration:.1f}s. "
                            f"Targeted ports include: {sample_ports}."
                        ),
                        remediation_recommendation=(
                            f"Apply containment rule to isolate {src_ip} at network edge. "
                            f"Audit target host(s) for exposed listening services."
                        ),
                    )
                    return alert

        return None

    def _prune_expired(self, now: float):
        """Removes expired source IP entries to enforce memory boundedness."""
        cutoff = now - self.window_seconds
        expired_ips = []

        for ip, dq in self._history.items():
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()
            if not dq:
                expired_ips.append(ip)

        for ip in expired_ips:
            del self._history[ip]

        # Clean alerted signatures older than window
        sig_cutoff = now - (self.window_seconds * 2)
        expired_sigs = [s for s, t in self._alerted_signatures.items() if t < sig_cutoff]
        for s in expired_sigs:
            del self._alerted_signatures[s]

        self._last_cleanup = now

    def reset(self):
        """Resets detector state."""
        with self._lock:
            self._history.clear()
            self._alerted_signatures.clear()
            self.total_alerts_emitted = 0

