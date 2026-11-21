"""
Isolated PCAP Replay Pipeline for CyberShield.
Feeds packets from a local PCAP file through the real packet decoding, FlowManager,
FlowExtractor, local Random Forest model inference, BehavioralPortScanDetector, and
LiveThreatCoordinator ring buffer without invoking AsyncSniffer or transmitting network traffic.
"""

from dataclasses import dataclass, field
import datetime
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import rdpcap, IP, TCP, UDP

from src.cybershield.services.live_threat_coordinator import (
    LiveThreatCoordinator, reset_live_coordinator
)
from src.cybershield.ingestion.live_sniffer import SnifferConfig

logger = logging.getLogger("cybershield.pcap_replay")


@dataclass
class PCAPReplaySummary:
    pcap_path: str
    total_packets_read: int
    packets_injected: int
    unsupported_packets: int
    flows_finalized: int
    inferences_attempted: int
    inferences_completed: int
    benign_predictions: int
    non_benign_ml_predictions: int
    behavioral_alerts: int
    processing_errors: int
    events_generated: int
    latency_mean_ms: float
    latency_max_ms: float
    replay_duration_seconds: float
    threat_events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pcap_path": self.pcap_path,
            "total_packets_read": self.total_packets_read,
            "packets_injected": self.packets_injected,
            "unsupported_packets": self.unsupported_packets,
            "flows_finalized": self.flows_finalized,
            "inferences_attempted": self.inferences_attempted,
            "inferences_completed": self.inferences_completed,
            "benign_predictions": self.benign_predictions,
            "non_benign_ml_predictions": self.non_benign_ml_predictions,
            "behavioral_alerts": self.behavioral_alerts,
            "processing_errors": self.processing_errors,
            "events_generated": self.events_generated,
            "latency_mean_ms": self.latency_mean_ms,
            "latency_max_ms": self.latency_max_ms,
            "replay_duration_seconds": round(self.replay_duration_seconds, 3),
            "threat_events_count": len(self.threat_events),
        }


def replay_pcap_through_live_pipeline(
    pcap_path: str,
    scan_port_threshold: int = 5,
    scan_window_seconds: float = 30.0,
    isolated_coordinator: Optional[LiveThreatCoordinator] = None,
) -> Tuple[PCAPReplaySummary, LiveThreatCoordinator]:
    """
    Deterministically replays a PCAP through the real coordinator pipeline.
    Never starts AsyncSniffer and never binds network sockets.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Use supplied coordinator or create fresh isolated test coordinator
    coord = isolated_coordinator or LiveThreatCoordinator(
        config=SnifferConfig(enabled=False),
        scan_port_threshold=scan_port_threshold,
        scan_window_seconds=scan_window_seconds,
    )

    t_start = time.perf_counter()
    pkts = rdpcap(pcap_path)
    total_pkts = len(pkts)

    injected = 0
    unsupported = 0

    # Ingest packets directly into FlowManager using actual packet metadata
    for p in pkts:
        if IP in p and (TCP in p or UDP in p):
            ip_layer = p[IP]
            is_tcp = TCP in p
            trans_layer = p[TCP] if is_tcp else p[UDP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            sport = int(trans_layer.sport)
            dport = int(trans_layer.dport)
            proto = 6 if is_tcp else 17
            pkt_time = float(p.time)
            pkt_len = len(p)
            payload_len = len(trans_layer.payload) if hasattr(trans_layer, "payload") else 0
            header_len = pkt_len - payload_len

            # Extract TCP flags if available
            tcp_flags = str(trans_layer.flags) if is_tcp and hasattr(trans_layer, "flags") else ""
            tcp_win = int(trans_layer.window) if is_tcp and hasattr(trans_layer, "window") else -1

            coord.flow_manager.process_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=sport,
                dport=dport,
                proto=proto,
                timestamp=pkt_time,
                packet_len=pkt_len,
                payload_len=payload_len,
                header_len=header_len,
                tcp_flags=tcp_flags,
                tcp_window=tcp_win,
            )
            injected += 1
        else:
            unsupported += 1

    # Deterministically finalize all remaining flows (simulating end of session)
    finalized_flows = coord.flow_manager.finalize_all(reason="pcap_replay_completion")

    t_end = time.perf_counter()
    duration = t_end - t_start

    # Collect pipeline metrics
    metrics = coord.get_metrics()
    events = coord.get_events(limit=1000)

    summary = PCAPReplaySummary(
        pcap_path=pcap_path,
        total_packets_read=total_pkts,
        packets_injected=injected,
        unsupported_packets=unsupported,
        flows_finalized=len(finalized_flows),
        inferences_attempted=metrics["inferences_attempted"],
        inferences_completed=metrics["inferences_completed"],
        benign_predictions=metrics["benign_predictions"],
        non_benign_ml_predictions=metrics["non_benign_predictions"],
        behavioral_alerts=metrics["behavioral_alerts"],
        processing_errors=metrics["processing_errors"],
        events_generated=len(events),
        latency_mean_ms=metrics["latency_mean_ms"],
        latency_max_ms=metrics["latency_max_ms"],
        replay_duration_seconds=duration,
        threat_events=events,
    )

    return summary, coord
