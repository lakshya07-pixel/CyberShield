"""
Preprocessing abstraction for the Network IDS module.
The underlying model uses a unified scikit-learn Pipeline that includes:
- SimpleImputer (median)
- VarianceThreshold
- StandardScaler

During inference, passing the raw DataFrame into the pipeline's predict() method
automatically handles all of these preprocessing steps deterministically based on
the parameters learned during training. No separate manual preprocessing is required.
"""

import numpy as np
import pandas as pd

def preprocess_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Sanitizes feature values prior to pipeline transformation.
    Replaces infinite values (np.inf, -np.inf) with np.nan so that
    the pipeline's SimpleImputer can impute them deterministically.
    """
    if isinstance(df, pd.DataFrame):
        return df.replace([np.inf, -np.inf], np.nan)
    return df
