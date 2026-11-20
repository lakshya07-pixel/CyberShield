"""
Offline PCAP-to-Threat Pipeline Runner for Person 1 Network IDS.

Coordinates:
1. Validating input raw packet capture (.pcap / .pcapng).
2. Extracting bidirectional network flows into CSV using the verified CICFlowMeter engine.
3. Aligning flow features, cleaning sentinels, and validating canonical 79 features.
4. Running inference via detect_network_threat() and producing structured ThreatResult JSON output.
"""

import argparse
import json
import os
import sys
from typing import Dict, Any, List

# Ensure repository root is on sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from examples.flow_to_threats import process_flow_csv
from src.cybershield.ingestion.pcap import extract_flows_from_pcap


def run_pcap_pipeline(
    pcap_path: str,
    output_json_path: str = "outputs/pcap_demo/threat_results.json",
    flow_csv_path: str = "outputs/pcap_demo/extracted_flows.csv",
    models_dir: str = "models/network_ids/baseline_model",
    limit: int = 10,
    verbose: bool = False,
    include_advisory: bool = True,
) -> List[Dict[str, Any]]:
    """
    Executes the complete offline pipeline from raw PCAP to structured threat output.
    """
    # 1. Extraction
    flow_count = extract_flows_from_pcap(pcap_path, flow_csv_path, verbose=verbose)
    if flow_count == 0:
        raise ValueError(
            f"Extraction completed but 0 flows were generated from '{pcap_path}'. "
            "The capture may contain only non-IP or non-TCP/UDP packets."
        )

    print(f"Successfully extracted {flow_count} flows into '{flow_csv_path}'.")

    # 2. IDS Inference via verified flow runner
    print("Running Network IDS threat detection...")
    results = process_flow_csv(
        flow_csv_path, models_dir=models_dir, include_advisory=include_advisory
    )

    # 3. Save JSON
    out_dir = os.path.dirname(output_json_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Saved {len(results)} structured threat result(s) to '{output_json_path}'.")

    # 4. Summary display
    print(f"\n--- First {min(len(results), limit)} Threat Results ---")
    for res in results[:limit]:
        tr = res["threat_result"]
        adv_str = ""
        if "advisory" in res:
            adv_str = f" | Advisory: {res['advisory']['severity']:<8}"
        print(
            f"Flow #{res['flow_index']:<5} | Class: {tr['attack_class']:<12} | "
            f"Severity: {tr['severity']:<6}{adv_str} | Confidence: {tr['confidence']:.4f} | "
            f"Threat Type: {tr['threat_type']}"
        )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Offline Raw PCAP to Network Threat Pipeline"
    )
    parser.add_argument(
        "--pcap", required=True, help="Path to input raw PCAP/PCAPNG file"
    )
    parser.add_argument(
        "--output",
        default="outputs/pcap_demo/threat_results.json",
        help="Path for output JSON threat results (default: outputs/pcap_demo/threat_results.json)",
    )
    parser.add_argument(
        "--flow-csv",
        default="outputs/pcap_demo/extracted_flows.csv",
        help="Path to save intermediate flow CSV (default: outputs/pcap_demo/extracted_flows.csv)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Max threat results to display to stdout (default: 10)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--no-advisory",
        action="store_true",
        help="Exclude Person 3 Threat Engine advisories from results",
    )
    args = parser.parse_args()

    try:
        run_pcap_pipeline(
            pcap_path=args.pcap,
            output_json_path=args.output,
            flow_csv_path=args.flow_csv,
            limit=args.limit,
            verbose=args.verbose,
            include_advisory=not args.no_advisory,
        )
    except Exception as e:
        sys.stderr.write(f"Pipeline error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

