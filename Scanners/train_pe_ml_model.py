from pathlib import Path
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
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

from ember_dataset import load_ember_parquet, prepare_ember_xy
from joblib import dump


def main():
    # 1) Find project root and dataset folder
    this_file = Path(__file__).resolve()
    project_root = this_file.parents[1]
    data_dir = project_root / "ML-dataset" / "ember_2018"

    print("Project root:", project_root)
    print("Using data dir:", data_dir)

    # 2) Load the full EMBER training parquet
    print("\n[1/5] Loading EMBER training data...")
    df = load_ember_parquet(data_dir, split="train", n_rows=None)
    print("Raw shape:", df.shape)

    # 3) Randomly sample a subset to avoid running out of RAM
    #    120,000 rows is a good compromise between performance and memory usage.
    df = df.sample(n=120000, random_state=42)
    print("After sampling:", df.shape)

    # 4) Build X and y (filter unlabeled samples and map labels)
    print("\n[2/5] Preparing X and y...")
    X, y = prepare_ember_xy(df)

    print("X shape:", X.shape)
    print("y shape:", y.shape)
    print("Malware ratio (y==1):", y.mean())

    # 5) Split into training and validation sets
    print("\n[3/5] Splitting into train and validation sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )

    print("Train shape:", X_train.shape, "Val shape:", X_test.shape)

    # 6) Define the LightGBM model (DART variant with mild regularisation)
    print("\n[4/5] Training LightGBM model...")
    model = LGBMClassifier(
        objective="binary",

        # Dropout-style boosting to reduce overfitting
        boosting_type="dart",

        # More trees + smaller learning rate = more careful learning
        n_estimators=1000,
        learning_rate=0.03,

        # Larger trees for more expressive power
        num_leaves=128,
        max_depth=-1,
        min_child_samples=40,

        # Row and feature subsampling (regularisation)
        subsample=0.9,
        colsample_bytree=0.9,

        # Mild L1/L2 regularisation
        reg_alpha=0.1,
        reg_lambda=0.1,

        # Slightly favour benign class (0) to reduce false positives
        class_weight={0: 2.0, 1: 1.0},

        n_jobs=-1,
        random_state=42,
    )

    model.fit(X_train, y_train)

    # 7) Evaluate on the validation set using a custom threshold
    print("\n[5/5] Evaluating on validation set...")
    # Probability of class 1 (malware)
    y_proba = model.predict_proba(X_test)[:, 1]

    # Decision threshold for classifying a file as malware
    threshold = 0.4
    y_pred = (y_proba >= threshold).astype(int)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print("\n--- METRICS ON VALIDATION SET ---")
    print(f"Threshold  : {threshold}")
    print(f"Accuracy   : {acc:.4f}")
    print(f"Precision  : {prec:.4f}")
    print(f"Recall     : {rec:.4f}")
    print(f"F1-score   : {f1:.4f}")
    print(f"ROC-AUC    : {roc:.4f}")

    print("\nConfusion Matrix (rows=true, cols=pred):")
    print(cm)

    print("\nClassification report:")
    print(classification_report(y_test, y_pred,
                                target_names=["benign", "malware"]))

    # 8) Save trained model to disk so SafeFile can use it later
    model_path = project_root / "models" / "pe_malware_model.pkl"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    dump(model, model_path)
    print(f"\n[6/5] Saved model to: {model_path}")


if __name__ == "__main__":
    main()
