"""
train_pe_rf_model.py

Train a Random Forest malware detector on EMBER features, inspired by the
MDAML project (Random Forest + feature selection on PE-based features).

Differences vs your LightGBM script:
- We use RandomForestClassifier instead of LightGBM.
- We do a feature-selection step based on feature_importances_.
- We save both the model and the selected feature indices.

This still uses your EMBER parquet + prepare_ember_xy() pipeline.
"""

from pathlib import Path
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split

from joblib import dump

from ember_dataset import load_ember_parquet, prepare_ember_xy


# How many top features to keep after feature selection.
# Inspired by their "select important features" idea.
TOP_K_FEATURES = 400


def interpret_ml_probability(p: float) -> str:
    """
    Map malware probability to a 3-level verdict.

    We will reuse this logic later inside SafeFile when showing ML verdicts.

      p < 0.3     -> 'benign'
      0.3-0.7     -> 'suspicious'
      p >= 0.7    -> 'malicious'
    """
    if p < 0.3:
        return "benign"
    elif p < 0.7:
        return "suspicious"
    else:
        return "malicious"


def main():
    # -------------------------
    # 1) Paths & dataset loading
    # -------------------------
    this_file = Path(__file__).resolve()
    project_root = this_file.parents[1]
    data_dir = project_root / "ML-dataset" / "ember_2018"

    print("Project root:", project_root)
    print("Using data dir:", data_dir)

    print("\n[1/7] Loading EMBER training data...")
    df = load_ember_parquet(data_dir, split="train", n_rows=None)
    print("Raw shape:", df.shape)

    # ------------------------------------------------
    # 2) Sample subset to avoid RAM explosion
    # ------------------------------------------------
    # Same idea as your LightGBM script: EMBER is large.
    # 120k rows is a decent compromise between performance and memory.
    df = df.sample(n=120000, random_state=42)
    print("After sampling:", df.shape)

    # ------------------------------------------------
    # 3) Build X and y with your existing helper
    # ------------------------------------------------
    print("\n[2/7] Preparing X and y...")
    X, y = prepare_ember_xy(df)

    print("X shape:", X.shape)
    print("y shape:", y.shape)
    print("Malware ratio (y==1):", y.mean())

    # ------------------------------------------------
    # 4) Train/validation split
    # ------------------------------------------------
    print("\n[3/7] Splitting into train and validation sets...")
    X_train, X_val, y_train, y_val = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )

    print("Train shape:", X_train.shape, "Val shape:", X_val.shape)

    # ------------------------------------------------
    # 5) Base Random Forest (for feature importance)
    # ------------------------------------------------
    # Idea inspired by MDAML: train a RF, use feature_importances_
    # to select the most useful features.
    print("\n[4/7] Training base Random Forest (for feature importance)...")

    base_rf = RandomForestClassifier(
        n_estimators=300,       # number of trees
        # let trees expand fully (we'll rely on many trees + randomness)
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        n_jobs=-1,             # use all CPU cores
        random_state=42,
        # Slightly favour benign class (0) to reduce false positives
        class_weight={0: 2.0, 1: 1.0},

    )

    base_rf.fit(X_train, y_train)

    # ------------------------------------------------
    # 6) Feature selection using importances
    # ------------------------------------------------
    print("\n[5/7] Selecting top features by importance...")

    importances = base_rf.feature_importances_
    # Indices of features sorted by importance (most important first)
    sorted_idx = np.argsort(importances)[::-1]

    # Take the top K
    top_k_idx = sorted_idx[:TOP_K_FEATURES]
    print(
        f"Keeping top {TOP_K_FEATURES} features out of {X_train.shape[1]} total.")

    # Slice the training and validation matrices
    X_train_sel = X_train[:, top_k_idx]
    X_val_sel = X_val[:, top_k_idx]

    print("Selected-train shape:", X_train_sel.shape,
          "Selected-val shape:", X_val_sel.shape)

    # ------------------------------------------------
    # 7) Train final Random Forest on selected features
    # ------------------------------------------------
    print("\n[6/7] Training final Random Forest on selected features...")

    # We can reuse similar hyperparameters, maybe bump n_estimators a bit
    final_rf = RandomForestClassifier(
        n_estimators=400,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        n_jobs=-1,
        random_state=42,
        class_weight={0: 2.0, 1: 1.0},
    )

    final_rf.fit(X_train_sel, y_train)

    # ------------------------------------------------
    # 8) Evaluate on validation set
    # ------------------------------------------------
    print("\n[7/7] Evaluating model on validation set...")

    # Predict malware probability (class 1)
    y_proba = final_rf.predict_proba(X_val_sel)[:, 1]

    # Start with a standard threshold 0.5 for evaluation.
    threshold = 0.5
    y_pred = (y_proba >= threshold).astype(int)

    acc = accuracy_score(y_val, y_pred)
    prec = precision_score(y_val, y_pred)
    rec = recall_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred)
    roc = roc_auc_score(y_val, y_proba)
    cm = confusion_matrix(y_val, y_pred)

    print("\n--- METRICS ON VALIDATION SET (Random Forest, selected features) ---")
    print(f"Threshold  : {threshold}")
    print(f"Accuracy   : {acc:.4f}")
    print(f"Precision  : {prec:.4f}")
    print(f"Recall     : {rec:.4f}")
    print(f"F1-score   : {f1:.4f}")
    print(f"ROC-AUC    : {roc:.4f}")

    print("\nConfusion Matrix (rows=true, cols=pred):")
    print(cm)

    print("\nClassification report:")
    print(
        classification_report(
            y_val,
            y_pred,
            target_names=["benign", "malware"],
        )
    )

    # see how many samples fall into benign/suspicious/malicious bands
    bands = {"benign": 0, "suspicious": 0, "malicious": 0}
    for p in y_proba:
        bands[interpret_ml_probability(float(p))] += 1

    print("\nML probability bands (for interpret_ml_probability):")
    for k, v in bands.items():
        print(f"  {k}: {v}")

    # ------------------------------------------------
    # 9) Save model + selected feature indices
    # ------------------------------------------------
    # model_dir = project_root / "models"
    # model_dir.mkdir(parents=True, exist_ok=True)

    # model_path = model_dir / "pe_rf_model.pkl"
    # idx_path = model_dir / "pe_rf_selected_indices.npy"

    # dump(final_rf, model_path)
    # np.save(idx_path, top_k_idx)

    # print(f"\nSaved Random Forest model to: {model_path}")
    # print(f"Saved selected feature indices to: {idx_path}")
    # print("\nYou will need BOTH files at prediction time.")


if __name__ == "__main__":
    main()
