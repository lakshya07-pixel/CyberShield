"""
Data loading and cleaning module.
Concatenates all CSV files from the CICIDS2017 dataset.
"""

import glob
import os

import numpy as np
import pandas as pd
from tqdm import tqdm

# Raw label → merged class mapping
LABEL_MAP = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Web Attack – Sql Injection": "Web Attack",
    "FTP-Patator": "Patator",
    "SSH-Patator": "Patator",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "Heartbleed": "Heartbleed",
}

BINARY_MAP = {label: ("ATTACK" if label != "BENIGN" else "BENIGN") for label in LABEL_MAP}


def load_raw(data_dir: str, sample_frac: float = 1.0) -> pd.DataFrame:
    """Loads and concatenates all CSV files."""
    files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSV files found in: {data_dir}")

    frames = []
    for f in tqdm(files, desc="Loading CSVs"):
        df = pd.read_csv(f, low_memory=False)
        if sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=42)
        frames.append(df)

    data = pd.concat(frames, ignore_index=True)
    data.columns = data.columns.str.strip()
    print(f"Loaded: {len(data):,} rows from {len(files)} files")
    return data


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans the raw dataframe based on EDA findings."""
    print("Starting data cleaning...")
    
    # 1. Strip column names
    df.columns = df.columns.str.strip()
    
    # 2. Drop duplicate columns like 'Fwd Header Length.1'
    dot1_cols = [c for c in df.columns if c.endswith(".1")]
    if dot1_cols:
        df = df.drop(columns=dot1_cols)
        
    # 3. Handle sentinels (-1 in Init_Win_bytes means handshake not seen)
    sentinel_cols = ["Init_Win_bytes_forward", "Init_Win_bytes_backward"]
    for col in sentinel_cols:
        if col in df.columns:
            flag_col = col.replace("Init_Win_bytes_", "tcp_win_seen_")
            df[flag_col] = (df[col] != -1).astype(np.int8)
            df[col] = df[col].replace(-1, np.nan) # Will be imputed later in sklearn pipeline
            
    # 4. Handle genuine negative values (measurement errors)
    feature_cols = [c for c in df.columns if c != "Label" and c not in sentinel_cols and not c.startswith("tcp_win_seen_")]
    # Convert features to numeric, coerce errors
    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    
    # Clamp negative measurement errors to 0
    for col in feature_cols:
        if (df[col] < 0).any():
            df[col] = df[col].clip(lower=0)
            
    # 5. Remove infinite values and NaNs (except the sentinels we just replaced)
    df = df.replace([np.inf, -np.inf], np.nan)
    
    before = len(df)
    # We drop rows that have NaN in the original feature_cols (i.e. inf/NaNs from raw data)
    df_no_nan = df.dropna(subset=feature_cols)
    nan_dropped = before - len(df_no_nan)

    # 6. Drop duplicate rows
    before_dedup = len(df_no_nan)
    df_dedup = df_no_nan.drop_duplicates()
    dup_dropped = before_dedup - len(df_dedup)

    print(f"Cleaning: removed {before - len(df_dedup):,} rows -> {len(df_dedup):,} rows remaining")
    df_cleaned = df_dedup.reset_index(drop=True)
    df_cleaned.attrs["nan_dropped"] = int(nan_dropped)
    df_cleaned.attrs["dup_dropped"] = int(dup_dropped)
    return df_cleaned


def apply_labels(df: pd.DataFrame, task: str = "multiclass") -> pd.DataFrame:
    """task='multiclass' → 9 classes | task='binary' → BENIGN / ATTACK"""
    df = df.copy()
    mapping = BINARY_MAP if task == "binary" else LABEL_MAP
    df["Label"] = df["Label"].map(mapping).fillna(df["Label"])
    print("Class distribution:\n", df["Label"].value_counts().to_string())
    return df


def load_dataset(
    data_dir: str,
    sample_frac: float = 1.0,
    task: str = "multiclass",
) -> tuple[pd.DataFrame, pd.Series]:
    """Full pipeline: load → clean → label → return X, y."""
    df = load_raw(data_dir, sample_frac)
    df = clean(df)
    df = apply_labels(df, task)
    X = df.drop(columns=["Label"])
    y = df["Label"]
    return X, y
