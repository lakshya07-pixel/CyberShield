"""
Feature conversion from FlowState to canonical 79-feature CICFlowMeter vector.
Maintains 100% semantic and numeric parity with src/cybershield/ingestion/pcap.py.
"""

from typing import Any, Dict, List, Optional
import numpy as np

from detectors.network.features import load_feature_list
from src.cybershield.ingestion.flow_manager import FlowState, PacketMetadata
from src.cybershield.ingestion.pcap import _resolve_models_dir


def extract_features_from_flow(
    flow: FlowState,
    canonical_features: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes all 79 CICFlowMeter features from an assembled FlowState object.
    Matches the exact formulas and heuristics of pcap.py.
    """
    if canonical_features is None:
        models_dir = _resolve_models_dir()
        canonical_features = load_feature_list(str(models_dir))

    all_pkts = flow.packets
    if not all_pkts:
        return {}

    fwd_pkts = flow.fwd_packets
    bwd_pkts = flow.bwd_packets

    src_ip, dst_ip, sport, dport, proto = flow.key

    start_time = float(all_pkts[0].timestamp)
    end_time = float(all_pkts[-1].timestamp)
    duration_us = max(0.0, (end_time - start_time) * 1e6)

    fwd_payloads = [p.payload_len for p in fwd_pkts]
    bwd_payloads = [p.payload_len for p in bwd_pkts]
    all_payloads = [p.payload_len for p in all_pkts]
    fwd_hdrs = [p.header_len for p in fwd_pkts]
    bwd_hdrs = [p.header_len for p in bwd_pkts]

    row: Dict[str, Any] = {f: 0.0 for f in canonical_features}

    # Metadata & Tracking
    row["src_ip"] = src_ip
    row["dst_ip"] = dst_ip
    row["src_port"] = int(sport)
    row["protocol"] = int(proto)
    row["timestamp"] = all_pkts[0].timestamp
    row["Label"] = "BENIGN"
    if flow.host_header:
        row["host"] = flow.host_header

    # Canonical statistical features
    row["Destination Port"] = float(dport)
    row["Flow Duration"] = duration_us
    row["Total Fwd Packets"] = float(len(fwd_pkts))
    row["Total Backward Packets"] = float(len(bwd_pkts))
    row["Total Length of Fwd Packets"] = float(sum(fwd_payloads))
    row["Total Length of Bwd Packets"] = float(sum(bwd_payloads))

    if fwd_payloads:
        row["Fwd Packet Length Max"] = float(max(fwd_payloads))
        row["Fwd Packet Length Min"] = float(min(fwd_payloads))
        row["Fwd Packet Length Mean"] = float(np.mean(fwd_payloads))
        row["Fwd Packet Length Std"] = float(np.std(fwd_payloads, ddof=1) if len(fwd_payloads) > 1 else 0.0)

    if bwd_payloads:
        row["Bwd Packet Length Max"] = float(max(bwd_payloads))
        row["Bwd Packet Length Min"] = float(min(bwd_payloads))
        row["Bwd Packet Length Mean"] = float(np.mean(bwd_payloads))
        row["Bwd Packet Length Std"] = float(np.std(bwd_payloads, ddof=1) if len(bwd_payloads) > 1 else 0.0)

    dur_sec = duration_us / 1e6
    if dur_sec > 0:
        row["Flow Bytes/s"] = (sum(fwd_payloads) + sum(bwd_payloads)) / dur_sec
        row["Flow Packets/s"] = len(all_pkts) / dur_sec
        row["Fwd Packets/s"] = len(fwd_pkts) / dur_sec
        row["Bwd Packets/s"] = len(bwd_pkts) / dur_sec

    all_times_us = [float(p.timestamp) * 1e6 for p in all_pkts]
    all_iats = [all_times_us[j] - all_times_us[j - 1] for j in range(1, len(all_times_us))]
    if all_iats:
        row["Flow IAT Mean"] = float(np.mean(all_iats))
        row["Flow IAT Std"] = float(np.std(all_iats, ddof=1) if len(all_iats) > 1 else 0.0)
        row["Flow IAT Max"] = float(max(all_iats))
        row["Flow IAT Min"] = float(min(all_iats))

    fwd_times_us = [float(p.timestamp) * 1e6 for p in fwd_pkts]
    fwd_iats = [fwd_times_us[j] - fwd_times_us[j - 1] for j in range(1, len(fwd_times_us))]
    if fwd_iats:
        row["Fwd IAT Total"] = float(sum(fwd_iats))
        row["Fwd IAT Mean"] = float(np.mean(fwd_iats))
        row["Fwd IAT Std"] = float(np.std(fwd_iats, ddof=1) if len(fwd_iats) > 1 else 0.0)
        row["Fwd IAT Max"] = float(max(fwd_iats))
        row["Fwd IAT Min"] = float(min(fwd_iats))

    bwd_times_us = [float(p.timestamp) * 1e6 for p in bwd_pkts]
    bwd_iats = [bwd_times_us[j] - bwd_times_us[j - 1] for j in range(1, len(bwd_times_us))]
    if bwd_iats:
        row["Bwd IAT Total"] = float(sum(bwd_iats))
        row["Bwd IAT Mean"] = float(np.mean(bwd_iats))
        row["Bwd IAT Std"] = float(np.std(bwd_iats, ddof=1) if len(bwd_iats) > 1 else 0.0)
        row["Bwd IAT Max"] = float(max(bwd_iats))
        row["Bwd IAT Min"] = float(min(bwd_iats))

    row["Fwd Header Length"] = float(sum(fwd_hdrs))
    row["Bwd Header Length"] = float(sum(bwd_hdrs))

    if fwd_payloads:
        simulated_length_stats = [fwd_payloads[0]] + fwd_payloads + bwd_payloads
        row["Min Packet Length"] = float(min(fwd_payloads + bwd_payloads))
        row["Max Packet Length"] = float(max(fwd_payloads + bwd_payloads))
        row["Packet Length Mean"] = float(np.mean(simulated_length_stats))
        row["Packet Length Std"] = float(np.std(simulated_length_stats, ddof=1) if len(simulated_length_stats) > 1 else 0.0)
        row["Packet Length Variance"] = float(np.var(simulated_length_stats, ddof=1) if len(simulated_length_stats) > 1 else 0.0)
        row["Average Packet Size"] = float(sum(simulated_length_stats) / len(all_pkts))
        row["Avg Fwd Segment Size"] = float(sum(fwd_payloads) / len(fwd_pkts))
    else:
        simulated_length_stats = [0.0]

    if bwd_payloads:
        row["Avg Bwd Segment Size"] = float(sum(bwd_payloads) / len(bwd_pkts))

    for p in all_pkts:
        flags = p.tcp_flags
        if "F" in flags: row["FIN Flag Count"] += 1.0
        if "S" in flags: row["SYN Flag Count"] += 1.0
        if "R" in flags: row["RST Flag Count"] += 1.0
        if "P" in flags: row["PSH Flag Count"] += 1.0
        if "A" in flags: row["ACK Flag Count"] += 1.0
        if "U" in flags: row["URG Flag Count"] += 1.0
        if "E" in flags: row["ECE Flag Count"] += 1.0
        if "C" in flags: row["CWE Flag Count"] += 1.0

    if len(all_pkts) <= 2 and row["SYN Flag Count"] >= 1.0:
        row["PSH Flag Count"] = 1.0

    if len(fwd_pkts) > 0:
        row["Down/Up Ratio"] = float(int(len(bwd_pkts) / len(fwd_pkts)))

    row["Subflow Fwd Packets"] = float(len(fwd_pkts))
    row["Subflow Fwd Bytes"] = float(sum(fwd_payloads))
    row["Subflow Bwd Packets"] = float(len(bwd_pkts))
    row["Subflow Bwd Bytes"] = float(sum(bwd_payloads))

    # TCP Window Advertisements
    init_fwd_win = fwd_pkts[0].tcp_window if fwd_pkts else -1
    init_bwd_win = bwd_pkts[0].tcp_window if bwd_pkts else -1
    row["Init_Win_bytes_forward"] = float(init_fwd_win)
    row["Init_Win_bytes_backward"] = float(init_bwd_win) if init_bwd_win != -1 else np.nan
    row["tcp_win_seen_forward"] = 1.0 if init_fwd_win != -1 else 0.0
    row["tcp_win_seen_backward"] = 1.0 if init_bwd_win != -1 else 0.0

    row["act_data_pkt_fwd"] = float(sum(1 for l in fwd_payloads if l > 2))
    row["min_seg_size_forward"] = float(min(fwd_hdrs)) if fwd_hdrs else 0.0

    return row

