"""
SMS Scam Model Loader and Predictor.
Manages lazy-loading, artifact path resolution, and TF-IDF inference
for the SMS scam classifier.
"""

from pathlib import Path
from typing import Optional, Tuple, Union
import joblib

DEFAULT_SMS_MODELS_DIR = (
    Path(__file__).resolve().parent.parent.parent / "models" / "sms_scam"
)


class SMSScamModel:
    """
    Lazy-loaded singleton model wrapper for SMS scam detection.
    """

    def __init__(self, models_dir: Optional[Union[str, Path]] = None):
        self.models_dir = Path(models_dir) if models_dir is not None else DEFAULT_SMS_MODELS_DIR
        self._vectorizer = None
        self._classifier = None

    def load(self):
        """Loads the pre-trained TF-IDF vectorizer and Logistic Regression model."""
        if self._classifier is not None and self._vectorizer is not None:
            return self._vectorizer, self._classifier

        model_path = self.models_dir / "sms.joblib"
        if not model_path.exists():
            raise FileNotFoundError(f"SMS scam detector artifact not found at: {model_path}")

        vec, clf = joblib.load(model_path)
        self._vectorizer = vec
        self._classifier = clf
        return self._vectorizer, self._classifier

    @property
    def vectorizer(self):
        self.load()
        return self._vectorizer

    @property
    def classifier(self):
        self.load()
        return self._classifier

    @property
    def pipeline(self):
        self.load()
        return (self._vectorizer, self._classifier)

    def predict_proba(self, cleaned_text: str) -> float:
        """
        Transforms cleaned text through TF-IDF and returns probability of scam.

        Args:
            cleaned_text: Preprocessed text string.

        Returns:
            Scam probability between 0.0 and 1.0.
        """
        vec, clf = self.load()
        X_vec = vec.transform([cleaned_text])
        proba = float(clf.predict_proba(X_vec)[0][1])
        return proba

