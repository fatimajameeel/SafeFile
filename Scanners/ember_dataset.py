from pathlib import Path
import pandas as pd
import numpy as np


def load_ember_parquet(data_dir: str | Path, split: str = "train", n_rows: int | None = None):
    data_dir = Path(data_dir)

    if split == "train":
        file_path = data_dir / "train_ember_2018_v2_features.parquet"
    else:
        file_path = data_dir / "test_ember_2018_v2_features.parquet"

    df = pd.read_parquet(file_path)

    if n_rows is not None:
        df = df.head(n_rows)

    return df


"""
    Turn EMBER DataFrame into:
      X: features (numpy array)
      y: labels (0=benign, 1=malware)
"""


def prepare_ember_xy(df: pd.DataFrame):
    labels = df["Label"].to_numpy()

    # keep only labeled rows
    mask_labeled = labels != 0
    df_labeled = df.loc[mask_labeled]
    labels = labels[mask_labeled]

    # map labels -1/1 -> 0/1
    unique_vals = set(labels.tolist())
    print("Unique label values (after filtering 0):", unique_vals)

    if unique_vals.issubset({0.0, 1.0, 0, 1}):
        y = labels.astype(int)
    elif unique_vals.issubset({-1.0, 1.0, -1, 1}):
        y = (labels == 1).astype(int)
    else:
        y = (labels > 0).astype(int)

    # only feature columns (everything except Label)
    feature_cols = [c for c in df_labeled.columns if c != "Label"]
    X = df_labeled[feature_cols].to_numpy(dtype=np.float32)

    return X, y
