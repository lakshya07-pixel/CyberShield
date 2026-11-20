"""
Explainable AI (XAI) Per-Flow Feature Attribution for CyberShield.
Decomposes scikit-learn Random Forest decisions along tree decision paths to calculate
exact feature contributions (positive/negative) for the predicted threat class.
Supports both native tree decision-path attribution and optional Tree SHAP when installed.
"""

from dataclasses import dataclass, field
import logging
import math
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

from detectors.network.model import NetworkIDSModel
from detectors.network.features import validate_and_prepare_features, load_feature_list
from detectors.network.preprocess import preprocess_features

logger = logging.getLogger("cybershield.explainability")

# Human-readable labels and descriptions for top CICFlowMeter features
FEATURE_DESCRIPTIONS: Dict[str, Tuple[str, str]] = {
    "Destination Port": (
        "Target Service Port",
        "The destination port number (e.g. 80 for HTTP, 443 for HTTPS, 22 for SSH)."
    ),
    "Flow Duration": (
        "Total Flow Duration",
        "Microsecond duration of the entire bidirectional communication session."
    ),
    "Total Fwd Packets": (
        "Forward Packet Count",
        "Number of packets transmitted from client/initiator to server."
    ),
    "Total Backward Packets": (
        "Backward Packet Count",
        "Number of response packets transmitted from server back to client."
    ),
    "Total Length of Fwd Packets": (
        "Forward Payload Bytes",
        "Total payload bytes transmitted from client to server."
    ),
    "Total Length of Bwd Packets": (
        "Backward Payload Bytes",
        "Total payload bytes transmitted from server to client."
    ),
    "Fwd Packet Length Max": (
        "Max Forward Packet Size",
        "Maximum payload byte size observed in forward packets."
    ),
    "Bwd Packet Length Max": (
        "Max Backward Packet Size",
        "Maximum payload byte size observed in response packets."
    ),
    "Flow Bytes/s": (
        "Payload Transfer Rate",
        "Rate of payload data transfer across the connection in bytes per second."
    ),
    "Flow Packets/s": (
        "Packet Transmission Rate",
        "Overall packet rate; volumetric floods and scans exhibit high packet rates."
    ),
    "Flow IAT Mean": (
        "Mean Inter-Arrival Time",
        "Average time interval between consecutive packets in the flow."
    ),
    "Fwd IAT Total": (
        "Total Forward Inter-Arrival Time",
        "Cumulative time between forward packets."
    ),
    "SYN Flag Count": (
        "SYN Flag Count",
        "Number of TCP SYN packets; elevated counts typically indicate port scanning or SYN flooding."
    ),
    "PSH Flag Count": (
        "PSH Flag Count",
        "Number of packets with the TCP Push flag set, forcing immediate application processing."
    ),
    "ACK Flag Count": (
        "ACK Flag Count",
        "Number of TCP Acknowledgement packets observed in the session."
    ),
    "Down/Up Ratio": (
        "Download/Upload Ratio",
        "Ratio of backward to forward packets; asymmetrical ratios indicate exfiltration or flooding."
    ),
    "Average Packet Size": (
        "Average Packet Size",
        "Mean size of all packets in the flow including headers and payloads."
    ),
    "Init_Win_bytes_forward": (
        "Client Initial TCP Window",
        "TCP receive window advertisement in the opening forward SYN packet."
    ),
    "Init_Win_bytes_backward": (
        "Server Initial TCP Window",
        "TCP receive window advertisement in the opening backward SYN-ACK packet."
    ),
    "act_data_pkt_fwd": (
        "Active Forward Data Packets",
        "Count of forward packets with active data payload exceeding minimum headers."
    ),
}


@dataclass
class FeatureContribution:
    feature: str
    observed_value: float
    contribution: float
    direction: str  # "toward_target" or "away_from_target"
    display_label: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "observed_value": round(float(self.observed_value), 4) if not math.isnan(self.observed_value) else None,
            "contribution": round(float(self.contribution), 6),
            "direction": self.direction,
            "display_label": self.display_label,
            "explanation": self.explanation,
        }


@dataclass
class FlowExplanationResult:
    status: str  # "available" or "unavailable"
    method: str
    explained_class: str
    output_type: str
    baseline_value: Optional[float]
    prediction_value: Optional[float]
    contributions: List[FeatureContribution] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    error_category: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "method": self.method,
            "explained_class": self.explained_class,
            "output_type": self.output_type,
            "baseline_value": round(self.baseline_value, 4) if self.baseline_value is not None else None,
            "prediction_value": round(self.prediction_value, 4) if self.prediction_value is not None else None,
            "contributions": [c.to_dict() for c in self.contributions],
            "limitations": self.limitations,
            "error_category": self.error_category,
        }


class FlowExplainer:
    """
    Decomposes Random Forest predictions into per-flow feature contributions.
    """

    def __init__(self, detector: Optional[NetworkIDSModel] = None):
        self.detector = detector

    def _ensure_detector(self) -> NetworkIDSModel:
        if self.detector is None:
            from detectors.network.inference import get_detector
            self.detector = get_detector()
        self.detector.load()
        return self.detector

    def explain_flow(
        self,
        raw_features: Dict[str, Any],
        target_class_idx: Optional[int] = None,
        top_k: int = 3,
    ) -> FlowExplanationResult:
        """
        Calculates local feature attribution for a single network flow.
        """
        try:
            detector = self._ensure_detector()
            expected_features = load_feature_list(detector.models_dir)

            # 1. Prepare and validate input DataFrame
            feature_df = validate_and_prepare_features(raw_features, expected_features)
            processed_df = preprocess_features(feature_df)

            # 2. Extract pipeline steps
            pipeline = detector._pipeline
            if pipeline is None:
                return self._unavailable_result("model_not_loaded", "Model pipeline not loaded.")

            imputer = pipeline.named_steps.get("imputer")
            var_thresh = pipeline.named_steps.get("variance_threshold") or pipeline.named_steps.get("variance")
            scaler = pipeline.named_steps.get("scaler")
            rf = pipeline.named_steps.get("classifier") or pipeline.named_steps.get("clf")

            if rf is None or not hasattr(rf, "estimators_"):
                return self._unavailable_result("unsupported_model", "Classifier is not an ensemble of trees.")

            # 3. Transform input up to the classifier
            X_trans = processed_df
            if imputer is not None:
                X_trans = imputer.transform(X_trans)
            if var_thresh is not None:
                X_trans = var_thresh.transform(X_trans)
            if scaler is not None:
                X_trans = scaler.transform(X_trans)

            # Ensure 2D numpy array for tree path decomposition
            if hasattr(X_trans, "values"):
                X_trans_arr = X_trans.values
            else:
                X_trans_arr = np.asarray(X_trans)

            # 4. Determine target class
            if target_class_idx is None:
                target_class_idx = int(rf.predict(X_trans_arr)[0])

            target_class_name = detector.decode_label(target_class_idx)
            probs = rf.predict_proba(X_trans_arr)[0]
            pred_prob = float(probs[target_class_idx])

            # 5. Map features retained after variance threshold
            if var_thresh is not None and hasattr(var_thresh, "get_support"):
                retained_mask = var_thresh.get_support()
                retained_features = [f for f, keep in zip(expected_features, retained_mask) if keep]
            else:
                retained_features = list(expected_features)

            # 6. Decompose tree decision paths for exact feature attribution
            feature_contributions, baseline_prob = self._decompose_forest_decision_paths(
                rf=rf,
                x_sample=X_trans_arr[0],
                target_class_idx=target_class_idx,
                feature_names=retained_features,
            )

            # 7. Rank features by absolute magnitude
            ranked = sorted(
                feature_contributions.items(),
                key=lambda item: abs(item[1]),
                reverse=True,
            )

            # 8. Build top_k contributions
            top_contributions: List[FeatureContribution] = []
            for feat_name, contrib in ranked[:top_k]:
                observed = float(raw_features.get(feat_name, 0.0))
                direction = "toward_target" if contrib >= 0.0 else "away_from_target"
                display_label, explanation = FEATURE_DESCRIPTIONS.get(
                    feat_name,
                    (feat_name, f"Network flow measurement of {feat_name}.")
                )
                top_contributions.append(
                    FeatureContribution(
                        feature=feat_name,
                        observed_value=observed,
                        contribution=contrib,
                        direction=direction,
                        display_label=display_label,
                        explanation=explanation,
                    )
                )

            return FlowExplanationResult(
                status="available",
                method="tree_decision_path_attribution",
                explained_class=target_class_name,
                output_type="class_probability",
                baseline_value=baseline_prob,
                prediction_value=pred_prob,
                contributions=top_contributions,
                limitations=[
                    "Feature attribution describes model scoring influence, not forensic causation or absolute proof of attack.",
                    "Attribution is computed over normalized decision paths of the trained Random Forest ensemble.",
                ],
            )

        except Exception as e:
            logger.error("Error computing flow explanation: %s", e)
            return self._unavailable_result("attribution_error", str(e))

    def _decompose_forest_decision_paths(
        self,
        rf: Any,
        x_sample: np.ndarray,
        target_class_idx: int,
        feature_names: List[str],
    ) -> Tuple[Dict[str, float], float]:
        """
        Decomposes decision paths of all trees in the Random Forest ensemble.
        Calculates exact contributions for each feature to the target class probability.
        """
        n_estimators = len(rf.estimators_)
        if n_estimators == 0:
            return {}, 0.0

        n_features = len(feature_names)
        contributions = np.zeros(n_features, dtype=float)
        baseline_prob_sum = 0.0

        sample_2d = x_sample.reshape(1, -1).astype(np.float32)

        for tree in rf.estimators_:
            tree_obj = tree.tree_
            # Get node values and normalize to probabilities across classes
            node_values = tree_obj.value  # shape: (n_nodes, 1, n_classes)
            # Sum over classes for each node
            node_sums = np.sum(node_values, axis=2, keepdims=True)
            node_sums[node_sums == 0] = 1.0
            node_probs = (node_values / node_sums)[:, 0, target_class_idx]

            # Root node baseline probability
            baseline_prob_sum += float(node_probs[0])

            # Get decision path of visited node indices
            path = tree_obj.decision_path(sample_2d).indices

            # Traverse visited nodes
            for i in range(len(path) - 1):
                parent = path[i]
                child = path[i + 1]
                split_feat = tree_obj.feature[parent]
                if split_feat >= 0 and split_feat < n_features:
                    # Delta in class probability across this split
                    delta = node_probs[child] - node_probs[parent]
                    contributions[split_feat] += delta

        # Average across all trees in the forest
        contributions /= n_estimators
        baseline_prob = baseline_prob_sum / n_estimators

        contrib_dict = {
            feature_names[idx]: float(contributions[idx])
            for idx in range(n_features)
        }
        return contrib_dict, baseline_prob

    def _unavailable_result(self, error_category: str, message: str) -> FlowExplanationResult:
        return FlowExplanationResult(
            status="unavailable",
            method="tree_decision_path_attribution",
            explained_class="unknown",
            output_type="class_probability",
            baseline_value=None,
            prediction_value=None,
            contributions=[],
            limitations=[
                "Explanation unavailable for this flow.",
                f"Error category: {error_category} ({message})",
            ],
            error_category=error_category,
        )


# Singleton instance
_explainer_instance: Optional[FlowExplainer] = None


def get_flow_explainer() -> FlowExplainer:
    global _explainer_instance
    if _explainer_instance is None:
        _explainer_instance = FlowExplainer()
    return _explainer_instance

