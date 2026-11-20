"""
Independent, Reproducible Evaluation Script for Network IDS Baseline Model.

Features:
- Evaluates the trained model (Random Forest baseline) on a broad, labeled held-out dataset.
- Never retrains or replaces the saved model or artifacts.
- Excludes 'Label' or any target-derived field from model features.
- Computes comprehensive multiclass metrics (accuracy, balanced accuracy, macro/weighted F1, per-class P/R/F1, support).
- Computes binary intrusion metrics (intrusion recall, intrusion precision, benign FPR, benign specificity).
- Analyzes false positives, false negatives, and confusion patterns.
- Saves:
  * summary_metrics.json
  * per_class_metrics.csv
  * confusion_matrix.png
  * evaluation_report.md
  * error_analysis.json
"""

import os
import sys
import json
import argparse
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

# Ensure repository root is on sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.utils.data_loader import load_dataset
from src.features.preprocessing import encode_labels
from detectors.network.features import load_feature_list


def run_evaluation(
    data_dir: str = "MachineLearningCVE",
    sample_frac: float = 0.2,
    models_dir: str = "models/network_ids/baseline_model",
    output_dir: str = "outputs/network_evaluation",
    random_state: int = 42,
    test_size: float = 0.2,
) -> dict:
    os.makedirs(output_dir, exist_ok=True)
    print(f"=== Network IDS Evaluation Running ===")
    print(f"Data directory: {data_dir} (sample_frac={sample_frac})")
    print(f"Models directory: {models_dir}")
    print(f"Output directory: {output_dir}")

    # 1. Load canonical features and saved artifacts
    expected_features = load_feature_list(models_dir)
    pipeline_path = os.path.join(models_dir, "random_forest_baseline.joblib")
    encoder_path = os.path.join(models_dir, "label_encoder.joblib")

    if not os.path.exists(pipeline_path) or not os.path.exists(encoder_path):
        raise FileNotFoundError(f"Missing model artifacts in {models_dir}. Train baseline model first.")

    pipeline = joblib.load(pipeline_path)
    label_encoder = joblib.load(encoder_path)
    class_names = list(label_encoder.classes_)
    print(f"Loaded pipeline and encoder. Classes ({len(class_names)}): {class_names}")

    # 2. Load dataset through verified clean pipeline
    X, y = load_dataset(data_dir=data_dir, sample_frac=sample_frac, task="multiclass")
    
    # Strictly ensure target label is separate
    assert "Label" not in X.columns, "Target column 'Label' leaked into feature matrix!"

    # 3. Label encode
    y_enc = label_encoder.transform(y)

    # 4. Partition into training/held-out test split matching training methodology
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc,
        test_size=test_size,
        random_state=random_state,
        stratify=y_enc,
    )
    print(f"Evaluation held-out test sample count: {len(X_test):,} flows")

    # 5. Enforce canonical 79 features
    missing_feats = [f for f in expected_features if f not in X_test.columns]
    if missing_feats:
        raise ValueError(f"Missing required model features in dataset: {missing_feats}")
    X_test_aligned = X_test[expected_features]

    # 6. Execute predictions (NO model retraining)
    print("Running model inference on held-out test set...")
    y_pred = pipeline.predict(X_test_aligned)
    
    y_proba = None
    if hasattr(pipeline, "predict_proba"):
        try:
            y_proba = pipeline.predict_proba(X_test_aligned)
        except Exception as e:
            print(f"Could not compute probabilities: {e}")

    # 7. Compute multiclass metrics
    acc = accuracy_score(y_test, y_pred)
    bal_acc = balanced_accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    macro_prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_test, y_pred, average="macro", zero_division=0)

    roc_auc = None
    if y_proba is not None:
        try:
            roc_auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro")
        except Exception:
            pass

    # Per-class metrics
    report_dict = classification_report(
        y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred, labels=range(len(class_names)))

    # Per-class summary dataframe
    per_class_rows = []
    for cls in class_names:
        stats = report_dict[cls]
        per_class_rows.append({
            "attack_class": cls,
            "precision": round(stats["precision"], 4),
            "recall": round(stats["recall"], 4),
            "f1_score": round(stats["f1-score"], 4),
            "support": int(stats["support"]),
        })
    df_per_class = pd.DataFrame(per_class_rows)
    df_per_class.to_csv(os.path.join(output_dir, "per_class_metrics.csv"), index=False)

    # 8. Binary Intrusion Metrics (BENIGN vs ATTACK)
    # Class index 0 is BENIGN (alphabetical first)
    benign_idx = class_names.index("BENIGN")
    y_test_binary = (y_test != benign_idx).astype(int)  # 0 = Benign, 1 = Intrusion
    y_pred_binary = (y_pred != benign_idx).astype(int)

    bin_cm = confusion_matrix(y_test_binary, y_pred_binary)  # [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = bin_cm.ravel()

    intrusion_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    intrusion_prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    benign_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    benign_spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    # 9. False-positive and False-negative analysis
    # Sample up to 10 representative errors of each type
    y_test_names = [class_names[idx] for idx in y_test]
    y_pred_names = [class_names[idx] for idx in y_pred]

    fps = []  # True Benign, Pred Attack
    fns = []  # True Attack, Pred Benign
    class_confusion = {}

    for i in range(len(y_test)):
        t_cls = y_test_names[i]
        p_cls = y_pred_names[i]
        if t_cls != p_cls:
            pair = f"{t_cls} -> {p_cls}"
            class_confusion[pair] = class_confusion.get(pair, 0) + 1

            if t_cls == "BENIGN" and p_cls != "BENIGN" and len(fps) < 10:
                conf = float(y_proba[i].max()) if y_proba is not None else 1.0
                fps.append({
                    "sample_idx": int(i),
                    "true_class": t_cls,
                    "pred_class": p_cls,
                    "confidence": round(conf, 4),
                })
            elif t_cls != "BENIGN" and p_cls == "BENIGN" and len(fns) < 10:
                conf = float(y_proba[i].max()) if y_proba is not None else 1.0
                fns.append({
                    "sample_idx": int(i),
                    "true_class": t_cls,
                    "pred_class": p_cls,
                    "confidence": round(conf, 4),
                })

    top_confusions = sorted(class_confusion.items(), key=lambda x: x[1], reverse=True)[:10]

    # 10. Generate and save Confusion Matrix Plot
    plt.figure(figsize=(10, 8))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=class_names, yticklabels=class_names
    )
    plt.title(f"Confusion Matrix (N={len(y_test):,})")
    plt.xlabel("Predicted Class")
    plt.ylabel("True Class")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    cm_path = os.path.join(output_dir, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=150)
    plt.close()

    # 11. Save machine-readable summary
    summary = {
        "dataset": data_dir,
        "sample_fraction": sample_frac,
        "evaluated_samples_count": len(y_test),
        "metrics": {
            "accuracy": round(float(acc), 4),
            "balanced_accuracy": round(float(bal_acc), 4),
            "macro_precision": round(float(macro_prec), 4),
            "macro_recall": round(float(macro_rec), 4),
            "macro_f1": round(float(macro_f1), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "roc_auc_ovr_macro": round(float(roc_auc), 4) if roc_auc is not None else None,
        },
        "binary_intrusion_metrics": {
            "true_positives": int(tp),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "intrusion_recall": round(float(intrusion_recall), 4),
            "intrusion_precision": round(float(intrusion_prec), 4),
            "benign_false_positive_rate": round(float(benign_fpr), 4),
            "benign_specificity": round(float(benign_spec), 4),
        },
        "per_class": per_class_rows,
        "frequent_confusion_pairs": top_confusions,
        "artifacts_evaluated": {
            "pipeline": pipeline_path,
            "encoder": encoder_path,
        }
    }

    with open(os.path.join(output_dir, "summary_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    error_analysis = {
        "frequent_confusion_pairs": top_confusions,
        "representative_false_positives": fps,
        "representative_false_negatives": fns,
    }
    with open(os.path.join(output_dir, "error_analysis.json"), "w", encoding="utf-8") as f:
        json.dump(error_analysis, f, indent=2)

    # 12. Generate Markdown Report
    report_md = f"""# Network IDS Model Evaluation Report

## 1. Evaluation Overview
- **Evaluated Dataset:** `{data_dir}` (sample fraction = {sample_frac})
- **Held-Out Test Sample Count:** {len(y_test):,} flows
- **Evaluated Model:** `{pipeline_path}`
- **Evaluated Classes:** {len(class_names)} classes

## 2. Global Performance Metrics
| Metric | Score |
| :--- | :--- |
| **Overall Accuracy** | {acc * 100:.2f}% |
| **Balanced Accuracy** | {bal_acc * 100:.2f}% |
| **Macro Precision** | {macro_prec:.4f} |
| **Macro Recall** | {macro_rec:.4f} |
| **Macro F1-Score** | {macro_f1:.4f} |
| **Weighted F1-Score** | {weighted_f1:.4f} |
| **ROC-AUC (OVR Macro)** | {f"{roc_auc:.4f}" if roc_auc else "N/A"} |

## 3. Binary Intrusion Detection Performance
| Metric | Value | Description |
| :--- | :--- | :--- |
| **Intrusion Recall** | {intrusion_recall * 100:.2f}% | Fraction of true attacks detected |
| **Intrusion Precision** | {intrusion_prec * 100:.2f}% | Reliability of positive intrusion alerts |
| **Benign FPR** | {benign_fpr * 100:.2f}% | False alarms on benign traffic |
| **Benign Specificity** | {benign_spec * 100:.2f}% | Correctly identified benign flows |
| **True Positives (TP)** | {tp:,} | Correctly classified attacks |
| **False Positives (FP)** | {fp:,} | Benign flows alerted as attacks |
| **True Negatives (TN)** | {tn:,} | Correctly classified benign flows |
| **False Negatives (FN)** | {fn:,} | Missed attacks |

## 4. Per-Class Breakdown
| Attack Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
"""
    for r in per_class_rows:
        report_md += f"| **{r['attack_class']}** | {r['precision']:.4f} | {r['recall']:.4f} | {r['f1_score']:.4f} | {r['support']:,} |\n"

    report_md += f"""
## 5. Most Frequent Confusion Patterns
| True Class -> Predicted Class | Count |
| :--- | :--- |
"""
    for pair, count in top_confusions:
        report_md += f"| `{pair}` | {count:,} |\n"

    report_md += f"""
## 6. Generated Visualizations & Artifacts
- Confusion Matrix: `confusion_matrix.png`
- Per-Class Table: `per_class_metrics.csv`
- Machine-Readable Summary: `summary_metrics.json`
- Error Breakdown: `error_analysis.json`
"""

    with open(os.path.join(output_dir, "evaluation_report.md"), "w", encoding="utf-8") as f:
        f.write(report_md)

    print("\n=== Evaluation Complete ===")
    print(f"Accuracy: {acc:.4f} | Macro F1: {macro_f1:.4f} | Intrusion Recall: {intrusion_recall:.4f}")
    print(f"Artifacts saved to: {output_dir}")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Evaluate Network IDS Model on Held-Out Data")
    parser.add_argument("--data-dir", default="MachineLearningCVE", help="Dataset directory")
    parser.add_argument("--sample", type=float, default=0.2, help="Sample fraction (e.g. 0.2)")
    parser.add_argument("--models-dir", default="models/network_ids/baseline_model", help="Path to models directory")
    parser.add_argument("--output-dir", default="outputs/network_evaluation", help="Directory to save evaluation artifacts")
    args = parser.parse_args()

    run_evaluation(
        data_dir=args.data_dir,
        sample_frac=args.sample,
        models_dir=args.models_dir,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()

