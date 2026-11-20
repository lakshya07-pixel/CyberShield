import os
import json
import pandas as pd
from typing import Dict, Any, List

def load_feature_list(models_dir: str) -> List[str]:
    """Loads the canonical list of required features."""
    features_path = os.path.join(models_dir, "features.json")
    if not os.path.exists(features_path):
        raise FileNotFoundError(f"Feature metadata not found at {features_path}. Please train the baseline model first.")
    
    with open(features_path, "r") as f:
        return json.load(f)

def validate_and_prepare_features(input_data: Dict[str, Any], expected_features: List[str]) -> pd.DataFrame:
    """
    Validates input features and enforces deterministic ordering.
    """
    missing_features = [feat for feat in expected_features if feat not in input_data]
    if missing_features:
        raise ValueError(f"Required network feature(s) missing: {missing_features}")
    
    # Check for invalid values (must be numerical or convertible to float)
    processed_data = {}
    for feat in expected_features:
        val = input_data[feat]
        try:
            val_float = float(val)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid value for feature: {feat}. Expected numeric, got {type(val).__name__}")
        processed_data[feat] = [val_float]

    # Return a DataFrame with enforcing the exact canonical order
    return pd.DataFrame(processed_data)[expected_features]


CICFLOWMETER_COLUMN_MAP = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwr_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}

NON_FEATURE_METADATA_COLS = [
    "src_ip", "dst_ip", "src_port", "protocol", "timestamp", "Label"
]

def align_flow_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardizes flow dataframe column headers and unit semantics:
    1. Strips whitespace and maps CICFlowMeter snake_case names to canonical title-case names.
    2. Drops non-feature metadata columns (src_ip, dst_ip, src_port, protocol, timestamp, Label).
    3. Aligns temporal units: if duration is in seconds (float < 500s with fractional seconds), scales to microseconds.
    """
    df = df.copy()
    # Strip any whitespace around headers
    df.columns = df.columns.str.strip()
    was_snake_case = "flow_duration" in df.columns
    # If snake_case cicflowmeter columns are present, rename them
    df = df.rename(columns=CICFLOWMETER_COLUMN_MAP)

    # Unit alignment: only scale if the input was snake_case raw Python cicflowmeter output in seconds
    if was_snake_case and "Flow Duration" in df.columns and len(df) > 0:
        dur_num = pd.to_numeric(df["Flow Duration"], errors="coerce")
        max_dur = dur_num.max()
        if pd.notna(max_dur) and max_dur < 500.0:
            df["Flow Duration"] = dur_num * 1e6
            iat_cols = [
                "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
                "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
                "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
                "Active Mean", "Active Std", "Active Max", "Active Min",
                "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
            ]
            for col in iat_cols:
                if col in df.columns:
                    col_num = pd.to_numeric(df[col], errors="coerce")
                    df[col] = col_num * 1e6

    # Drop non-feature metadata columns
    drop_cols = [c for c in df.columns if c in NON_FEATURE_METADATA_COLS]
    if drop_cols:
        df = df.drop(columns=drop_cols)
    return df

