"""
Reusable Threat Detection & Advisory Orchestration Service.
Coordinates:
1. Input validation
2. Ingestion (CSV loading or PCAP extraction)
3. Schema alignment and sentinel cleaning
4. Model inference via Person 1's frozen Random Forest
5. ThreatResult validation
6. Advisory generation via Person 3's Shared Threat Engine adapter
7. Structured output serialization (JSON/CSV)
8. Summary reporting
"""

import dataclasses
import json
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union
import warnings
import pandas as pd

from src.utils.data_loader import clean
from detectors.network.features import load_feature_list, align_flow_dataframe
from detectors.network.inference import detect_network_threat
from detectors.network.schemas import ThreatResult
from detectors.network.advisory_adapter import build_network_advisory
from src.cybershield.ingestion.flow_csv import load_flow_csv
from src.cybershield.ingestion.pcap import extract_flows_from_pcap

DEFAULT_MODELS_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "models"
    / "network_ids"
    / "baseline_model"
)


class ThreatPipelineService:
    """
    Central orchestration service for processing network traffic flows into
    threat classifications and structured advisories.
    """

    def __init__(self, models_dir: Optional[Union[str, Path]] = None):
        self.models_dir = Path(models_dir) if models_dir is not None else DEFAULT_MODELS_DIR
        self.expected_features = load_feature_list(str(self.models_dir))
        self.last_run_stats: Dict[str, int] = {}

    def process_dataframe(
        self,
        df_raw: pd.DataFrame,
        include_advisory: bool = True
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Cleans, aligns, and performs threat detection on a DataFrame of flow records.

        Args:
            df_raw: Raw DataFrame of extracted or loaded flows.
            include_advisory: Whether to attach Person 3 Shared Threat Engine advisories.

        Yields:
            Dict containing flow_index, threat_result, and optionally advisory.
        """
        raw_count = len(df_raw)
        if raw_count == 0:
            raise ValueError("Input DataFrame contains no rows.")

        # 1. Align headers (maps CICFlowMeter snake_case and drops non-feature labels/IPs)
        df_aligned = align_flow_dataframe(df_raw)

        # 2. Domain cleaning (removes duplicate .1 columns, engineers tcp_win_seen_* sentinels)
        df_cleaned = clean(df_aligned)

        cleaned_count = len(df_cleaned)
        discarded_count = raw_count - cleaned_count
        invalid_count = df_cleaned.attrs.get("nan_dropped", discarded_count)
        duplicate_count = df_cleaned.attrs.get("dup_dropped", 0)

        self.last_run_stats = {
            "total_input_rows": raw_count,
            "valid_rows": cleaned_count,
            "discarded_rows": discarded_count,
            "invalid_rows": invalid_count,
            "duplicate_rows": duplicate_count,
        }

        # 3. Verify all canonical features are present
        missing = [feat for feat in self.expected_features if feat not in df_cleaned.columns]
        if missing:
            raise ValueError(f"Incompatible flow schema: missing required feature(s): {missing}")

        # 4. If no valid rows remain, fail clearly
        if cleaned_count == 0:
            raise ValueError(
                f"No valid flow records remained after cleaning: all {raw_count} input row(s) were discarded "
                f"({invalid_count} invalid/ragged/missing feature values, {duplicate_count} duplicate)."
            )

        # 5. If rows were discarded in a mixed batch, emit an observable warning
        if discarded_count > 0:
            warnings.warn(
                f"Discarded {discarded_count} of {raw_count} input row(s) during processing: "
                f"{invalid_count} invalid/ragged/missing feature values, {duplicate_count} duplicate. "
                f"{cleaned_count} valid flow(s) will be processed.",
                UserWarning,
                stacklevel=2,
            )

        for idx, row in df_cleaned.iterrows():
            flow_dict = row[self.expected_features].to_dict()
            threat_res: ThreatResult = detect_network_threat(flow_dict)

            record: Dict[str, Any] = {
                "flow_index": int(idx),
                "threat_result": dataclasses.asdict(threat_res),
            }

            if include_advisory:
                record["advisory"] = build_network_advisory(
                    threat_res, flow_metadata={"flow_index": int(idx)}
                )

            yield record

    def run_csv_pipeline(
        self,
        csv_path: Union[str, Path],
        output_json_path: Optional[Union[str, Path]] = None,
        nrows: Optional[int] = None,
        include_advisory: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Runs end-to-end threat detection on a flow CSV file.
        """
        df_raw = load_flow_csv(csv_path, nrows=nrows)
        results = list(self.process_dataframe(df_raw, include_advisory=include_advisory))

        if output_json_path:
            out_p = Path(output_json_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

        return results

    def run_pcap_pipeline(
        self,
        pcap_path: Union[str, Path],
        output_json_path: Optional[Union[str, Path]] = None,
        flow_csv_path: Optional[Union[str, Path]] = None,
        include_advisory: bool = True,
        verbose: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Runs end-to-end threat detection on a raw PCAP/PCAPNG capture file.
        """
        pcap_p = Path(pcap_path)
        if not flow_csv_path:
            flow_csv_path = Path("outputs") / f"{pcap_p.stem}_flows.csv"
        else:
            flow_csv_path = Path(flow_csv_path)

        flow_count = extract_flows_from_pcap(pcap_p, flow_csv_path, verbose=verbose)
        if flow_count == 0:
            raise ValueError(
                f"Extraction completed but 0 flows were generated from '{pcap_p}'. "
                "The capture may contain only non-IP or non-TCP/UDP packets."
            )

        return self.run_csv_pipeline(
            csv_path=flow_csv_path,
            output_json_path=output_json_path,
            include_advisory=include_advisory
        )

    @staticmethod
    def compute_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates high-level telemetry and advisory statistics.
        """
        total = len(results)
        normal_count = sum(1 for r in results if r["threat_result"]["threat_type"] == "normal")
        intrusion_count = total - normal_count

        severity_counts: Dict[str, int] = {}
        for r in results:
            if "advisory" in r:
                sev = r["advisory"]["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        attack_classes: Dict[str, int] = {}
        for r in results:
            ac = r["threat_result"]["attack_class"]
            attack_classes[ac] = attack_classes.get(ac, 0) + 1

        return {
            "total_flows": total,
            "benign_flows": normal_count,
            "intrusion_flows": intrusion_count,
            "advisory_severity_distribution": severity_counts,
            "attack_class_distribution": attack_classes,
        }

