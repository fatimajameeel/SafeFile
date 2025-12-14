from pathlib import Path
import numpy as np
from joblib import load
import lief
import ember  # EMBER feature extractor

_MODEL = None
_EXTRACTOR = None

# Threshold bands for 3-level ML verdict
BENIGN_THRESHOLD = 0.3
MALICIOUS_THRESHOLD = 0.7


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


def interpret_ml_probability(prob: float) -> str:
    """
    Converts probability into a clean 3-level verdict:
      <0.3     → benign
      0.3-0.7  → suspicious
      ≥0.7     → malicious
    """
    if prob < BENIGN_THRESHOLD:
        return "benign"
    elif prob < MALICIOUS_THRESHOLD:
        return "suspicious"
    else:
        return "malicious"


def score_pe_file(file_path: Path) -> dict:
    """
    Uses the ML model to score a PE file.
    Returns probability + 3-level verdict.
    """
    model = load_pe_model()
    X = extract_features_from_pe(file_path)

    probability = float(model.predict_proba(X)[0, 1])
    verdict = interpret_ml_probability(probability)

    return {
        "ml_score": probability,
        "ml_verdict": verdict,  # 'benign' / 'suspicious' / 'malicious'
        "ml_threshold": None,
        "benign_threshold": BENIGN_THRESHOLD,
        "malicious_threshold": MALICIOUS_THRESHOLD,
    }
