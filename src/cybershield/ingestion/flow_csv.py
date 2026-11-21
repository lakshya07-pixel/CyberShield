"""
Flow CSV Ingestion Module.
Handles loading and validating flow CSV files (e.g. from CICFlowMeter or CICIDS2017).
"""

from pathlib import Path
from typing import Optional, Union
import pandas as pd


def load_flow_csv(
    csv_path: Union[str, Path],
    nrows: Optional[int] = None,
    low_memory: bool = False
) -> pd.DataFrame:
    """
    Safely reads a flow CSV file.

    Args:
        csv_path: Path to the CSV file.
        nrows: Optional max number of rows to load.
        low_memory: Whether to use pandas low_memory mode.

    Returns:
        pd.DataFrame containing raw flow records.

    Raises:
        FileNotFoundError: If the CSV file does not exist.
        ValueError: If the file is empty or cannot be parsed as a DataFrame.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Flow CSV file not found: {path}")
    if path.stat().st_size == 0:
        raise ValueError(f"Flow CSV file is empty: {path}")

    try:
        df = pd.read_csv(path, nrows=nrows, low_memory=low_memory)
    except Exception as e:
        raise ValueError(f"Failed to parse CSV file '{path}': {e}") from e

    if df.empty:
        raise ValueError(f"Flow CSV file contains no data rows: {path}")

    return df
