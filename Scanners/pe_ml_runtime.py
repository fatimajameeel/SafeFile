from pathlib import Path
import numpy as np
from joblib import load
import lief
import ember  # EMBER feature extractor


_MODEL = None
_EXTRACTOR = None
ML_THRESHOLD = 0.4


def get_project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_pe_model():
    """Loads the trained LightGBM model once and reuses it."""
    global _MODEL
    if _MODEL is None:
        model_path = get_project_root() / "models" / "pe_malware_model.pkl"
        _MODEL = load(model_path)
    return _MODEL


def get_feature_extractor():
    """Loads the EMBER feature extractor once."""
    global _EXTRACTOR
    if _EXTRACTOR is None:
        _EXTRACTOR = ember.PEFeatureExtractor()
    return _EXTRACTOR


def extract_features_from_pe(file_path: Path) -> np.ndarray:
    """Reads a PE file and converts it into a numeric feature vector."""
    extractor = get_feature_extractor()
    file_path = Path(file_path)

    with open(file_path, "rb") as f:
        pe_bytes = f.read()

    features = extractor.feature_vector(pe_bytes)
    return np.array(features, dtype=np.float32).reshape(1, -1)
# Take a PE file and turn it into the correct numeric input for the ML model.


def score_pe_file(file_path: Path) -> dict:
    """Uses the ML model to score a PE file."""
    model = load_pe_model()
    X = extract_features_from_pe(file_path)

    probability = model.predict_proba(X)[0, 1]
    verdict = "malware" if probability >= ML_THRESHOLD else "benign"

    return {
        "ml_score": float(probability),
        "ml_verdict": verdict,
        "ml_threshold": ML_THRESHOLD,
    }
# If probability ≥ 0.4 → “malware”
# Else → “benign”
