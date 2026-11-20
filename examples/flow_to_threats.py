"""
Offline utility: Flow CSV to Threat Results Runner.
Converts extracted flow records (such as those output by CICFlowMeter)
into aligned, validated feature dictionaries and executes Network IDS threat detection.

Pipeline:
Flow CSV (e.g. CICFlowMeter output)
  -> Header cleaning & duplicate column resolution (.1)
  -> TCP window flag engineering (tcp_win_seen_*)
  -> Numerical validation & NaN/inf handling
  -> Alignment to canonical 79 features (features.json)
  -> detect_network_threat(flow_dict)
  -> Structured ThreatResult output (JSON / stream)
"""

import os
import sys
import json
import argparse
import dataclasses
import pandas as pd
from typing import List, Dict, Any, Generator

# Ensure repository root is on sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.utils.data_loader import clean
from detectors.network.features import load_feature_list, validate_and_prepare_features, align_flow_dataframe
from detectors.network.inference import detect_network_threat
from detectors.network.schemas import ThreatResult
from detectors.network.advisory_adapter import build_network_advisory



def process_flow_dataframe(
    df_raw: pd.DataFrame,
    models_dir: str = "models/network_ids/baseline_model",
    include_advisory: bool = True,
) -> Generator[Dict[str, Any], None, None]:
    """
    Cleans, engineers, aligns raw flow dataframe to the canonical 79 features,
    and runs threat detection for each flow record.
    Optionally enriches results with Person 3 Shared Threat Engine advisories.
    """
    expected_features = load_feature_list(models_dir)

    # Standardize column headers (mapping CICFlowMeter snake_case if present) and strip non-feature metadata/labels
    df_aligned = align_flow_dataframe(df_raw)

    # Reuse verified domain cleaning: drops .1 duplicates, engineers tcp_win_seen_* flags
    df_cleaned = clean(df_aligned)

    # Verify that all expected 79 features are present
    missing = [feat for feat in expected_features if feat not in df_cleaned.columns]
    if missing:
        raise ValueError(f"Incompatible flow CSV: missing required feature(s): {missing}")

    for idx, row in df_cleaned.iterrows():
        flow_dict = row[expected_features].to_dict()
        threat_res = detect_network_threat(flow_dict)
        flow_record: Dict[str, Any] = {
            "flow_index": int(idx),
            "threat_result": dataclasses.asdict(threat_res),
        }
        if include_advisory:
            flow_record["advisory"] = build_network_advisory(
                threat_res, flow_metadata={"flow_index": int(idx)}
            )
        yield flow_record


def process_flow_csv(
    csv_path: str,
    models_dir: str = "models/network_ids/baseline_model",
    nrows: int = None,
    include_advisory: bool = True,
) -> List[Dict[str, Any]]:
    """
    Reads a flow CSV file, runs threat detection, and returns the list of threat results.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Flow CSV file not found: {csv_path}")

    df_raw = pd.read_csv(csv_path, nrows=nrows, low_memory=False)
    return list(process_flow_dataframe(df_raw, models_dir=models_dir, include_advisory=include_advisory))


def main():
    parser = argparse.ArgumentParser(description="Offline Flow CSV to Threat Results Runner")
    parser.add_argument("--csv", required=True, help="Path to raw flow CSV file (e.g. from CICFlowMeter)")
    parser.add_argument("--output", default=None, help="Optional output JSON path for threat results")
    parser.add_argument("--nrows", type=int, default=None, help="Number of rows to read from CSV (for quick/sample execution)")
    parser.add_argument("--limit", type=int, default=10, help="Max flows to print to stdout (default: 10)")
    parser.add_argument("--no-advisory", action="store_true", help="Exclude Person 3 Threat Engine advisories from results")
    args = parser.parse_args()

    print(f"Loading flow CSV from: {args.csv}")
    try:
        results = process_flow_csv(args.csv, nrows=args.nrows, include_advisory=not args.no_advisory)
    except Exception as e:
        sys.stderr.write(f"Error processing flow CSV: {e}\n")
        sys.exit(1)

    print(f"Successfully processed {len(results)} flows.")

    # Print summary of first few flows
    print(f"\n--- First {min(len(results), args.limit)} Threat Results ---")
    for res in results[:args.limit]:
        tr = res["threat_result"]
        adv_info = ""
        if "advisory" in res:
            adv_info = f" | Advisory: {res['advisory']['severity']:<8}"
        print(f"Flow #{res['flow_index']:<5} | Class: {tr['attack_class']:<12} | Severity: {tr['severity']:<6}{adv_info} | Confidence: {tr['confidence']:.4f}")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            print(f"\nSaved all results to: {args.output}")
        except Exception as e:
            sys.stderr.write(f"Error writing output JSON: {e}\n")
            sys.exit(1)


if __name__ == "__main__":
    main()

