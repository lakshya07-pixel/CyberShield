import os
from pathlib import Path
from typing import Optional
import joblib

DEFAULT_MODELS_DIR = str(
    Path(__file__).resolve().parent.parent.parent / "models" / "network_ids" / "baseline_model"
)

class NetworkIDSModel:
    """
    Lazy-loaded singleton wrapper for the Network Intrusion Detection ML Model.
    Abstracts away the underlying Random Forest implementation and preprocessing steps.
    """
    
    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = str(models_dir) if models_dir is not None else DEFAULT_MODELS_DIR
        self._pipeline = None
        self._label_encoder = None

    def load(self):
        """Loads the pre-trained pipeline and label encoder from disk."""
        if self._pipeline is not None and self._label_encoder is not None:
            return

        pipeline_path = os.path.join(self.models_dir, "random_forest_baseline.joblib")
        encoder_path = os.path.join(self.models_dir, "label_encoder.joblib")

        if not os.path.exists(pipeline_path):
            raise FileNotFoundError(f"Network IDS model artifact not found at {pipeline_path}. Train the baseline model before inference.")
        if not os.path.exists(encoder_path):
            raise FileNotFoundError(f"Label encoder artifact not found at {encoder_path}. Train the baseline model before inference.")

        self._pipeline = joblib.load(pipeline_path)
        self._label_encoder = joblib.load(encoder_path)

    def predict(self, X):
        """Returns the raw predicted class index."""
        self.load()
        return self._pipeline.predict(X)

    def predict_proba(self, X):
        """Returns the prediction probabilities."""
        self.load()
        return self._pipeline.predict_proba(X)
    
    def decode_label(self, class_idx: int) -> str:
        """Decodes the predicted integer index back to a string attack class."""
        self.load()
        return self._label_encoder.inverse_transform([class_idx])[0]
    
    def get_classes(self):
        """Returns the list of classes."""
        self.load()
        return self._label_encoder.classes_
