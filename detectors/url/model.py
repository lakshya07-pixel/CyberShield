"""
URL Phishing Model Loader and Evaluator.
Manages lazy-loading, artifact path resolution, and model execution for
both the primary Random Forest model and lightweight Logistic Regression alternative.
"""

from pathlib import Path
from typing import Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd

DEFAULT_URL_MODELS_DIR = (
    Path(__file__).resolve().parent.parent.parent / "models" / "url_phishing"
)


class URLPhishingModel:
    """
    Lazy-loaded singleton model wrapper for URL phishing detection.
    """

    def __init__(self, models_dir: Optional[Union[str, Path]] = None):
        self.models_dir = Path(models_dir) if models_dir is not None else DEFAULT_URL_MODELS_DIR
        self._rf_model = None
        self._rf_names = None
        self._lr_model = None
        self._lr_scaler = None
        self._lr_names = None

    def load_rf(self):
        """Loads the primary Random Forest model."""
        if self._rf_model is not None:
            return self._rf_names, self._rf_model

        rf_path = self.models_dir / "url_rf.joblib"
        if not rf_path.exists():
            raise FileNotFoundError(f"URL Random Forest artifact not found at: {rf_path}")

        names, model = joblib.load(rf_path)
        self._rf_names = names
        self._rf_model = model
        return self._rf_names, self._rf_model

    def load_lite(self):
        """Loads the lightweight Logistic Regression model and scaler."""
        if self._lr_model is not None:
            return self._lr_names, self._lr_scaler, self._lr_model

        lr_path = self.models_dir / "url_lr.joblib"
        if not lr_path.exists():
            raise FileNotFoundError(f"URL Logistic Regression artifact not found at: {lr_path}")

        names, scaler, model = joblib.load(lr_path)
        self._lr_names = names
        self._lr_scaler = scaler
        self._lr_model = model
        return self._lr_names, self._lr_scaler, self._lr_model

    @property
    def rf_model(self):
        self.load_rf()
        return self._rf_model

    @property
    def lr_model(self):
        self.load_lite()
        return self._lr_model

    def predict_proba(
        self,
        features_dict: dict,
        use_lite: bool = False
    ) -> Tuple[float, str]:
        """
        Computes the phishing probability for an extracted feature dictionary.

        Args:
            features_dict: Dictionary containing the 16 extracted features.
            use_lite: If True, uses the lightweight Logistic Regression model.

        Returns:
            Tuple of (phishing_probability: float, model_identifier: str).
        """
        if use_lite:
            names, scaler, model = self.load_lite()
            vec = pd.DataFrame([[features_dict[n] for n in names]], columns=names)
            vec_scaled = scaler.transform(vec)
            prob = float(model.predict_proba(vec_scaled)[0][1])
            model_id = "logistic_regression_lite"
        else:
            names, model = self.load_rf()
            vec = pd.DataFrame([[features_dict[n] for n in names]], columns=names)
            prob = float(model.predict_proba(vec)[0][1])
            model_id = "random_forest"

        return prob, model_id

