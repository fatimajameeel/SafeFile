from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


# Weights for each engine when computing the global risk score.
WEIGHTS: Dict[str, float] = {
    "file_type": 0.05,
    "entropy": 0.10,
    "yara": 0.35,
    "virustotal": 0.35,
    "ml": 0.15,
}

# Thresholds for mapping the numeric score (0–100) to a verdict label.
VERDICT_THRESHOLDS = {
    "benign_max": 29,      # 0–29  → benign / safe
    "suspicious_max": 59,  # 30–59 → suspicious
    # >= 60 → malicious
}


def _clamp_score(value: float, minimum: int = 0, maximum: int = 100) -> int:
    """Clamp a floating-point score into an integer 0-100."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        v = 0.0
    v = max(minimum, min(maximum, v))
    return int(round(v))


def _safe_int(value: Any, default: int = 0) -> int:
    """Convert to int, falling back to a default on error."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Per-component scoring helpers (score + flags only, no reasons)
# ---------------------------------------------------------------------------

def score_file_type(file_type_info: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """
    Turn the raw file-type detection result into a 0–100 risk score.
    file_type_info is expected to be the dict returned by detect_file_type().
    """
    if not file_type_info:
        return 0, ["FILETYPE_NOT_AVAILABLE"]

    flags: List[str] = []
    mismatch = bool(file_type_info.get("mismatch"))
    declared_ext = (file_type_info.get("declared_extension") or "") or None
    final_type = (file_type_info.get("final_type") or "") or None

    score = 0

    if mismatch:
        score += 30
        flags.append("EXTENSION_MISMATCH")

    # Executable masquerading as a document / image is more suspicious.
    doc_like_exts = {"txt", "pdf", "doc", "docx",
                     "rtf", "xls", "xlsx", "ppt", "pptx"}
    image_like_exts = {"png", "jpg", "jpeg", "gif", "bmp"}

    if final_type == "exe" and declared_ext:
        if declared_ext.lower() in (doc_like_exts | image_like_exts):
            score += 40
            flags.append("HIDDEN_EXECUTABLE")

    score = _clamp_score(score)
    return score, list(set(flags))


def score_entropy(entropy_info: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """
    Use overall entropy & PE entropy interpretation to compute a risk score.
    """
    if not entropy_info:
        return 0, ["ENTROPY_NOT_AVAILABLE"]

    flags: List[str] = []

    overall_entropy = entropy_info.get("overall_entropy")
    pe_interp = entropy_info.get("pe_interpretation") or {}

    base_risk = pe_interp.get("risk_score", 0)
    base_score = _clamp_score(base_risk)
    pe_flags = list(pe_interp.get("flags") or [])

    flags.extend(pe_flags)
    score = base_score

    # Nudge score based on overall entropy of the whole file.
    if isinstance(overall_entropy, (int, float)):
        if overall_entropy > 7.8 and score < 70:
            score = max(score, 60)
            flags.append("OVERALL_ENTROPY_VERY_HIGH")
        elif overall_entropy > 7.2 and score < 50:
            score = max(score, 40)
            flags.append("OVERALL_ENTROPY_HIGH")

    return _clamp_score(score), list(set(flags))


def score_yara(yara_info: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """
    Turn YARA matches into a 0-100 risk score.
    yara_info is the dict returned by scan_file_with_yara().
    """
    if not yara_info:
        return 0, ["YARA_NOT_AVAILABLE"]

    if yara_info.get("enabled") is False:
        return 0, ["YARA_DISABLED"]

    error = yara_info.get("error")
    if error:
        return 0, ["YARA_ERROR"]

    matches = yara_info.get("matches") or []
    if not matches:
        return 0, []

    severity_map = {
        "low": 20,
        "medium": 40,
        "high": 70,
        "critical": 90,
    }

    max_score = 0
    flags: List[str] = ["YARA_MATCH"]
    critical_hit = False

    for m in matches:
        meta = m.get("meta") or {}
        raw_sev = meta.get("severity", "medium")
        sev = str(raw_sev).lower()
        sev_score = severity_map.get(sev, severity_map["medium"])

        if sev_score > max_score:
            max_score = sev_score

        if sev == "critical":
            critical_hit = True

    if critical_hit:
        flags.append("YARA_CRITICAL")

    return _clamp_score(max_score), list(set(flags))


def score_virustotal(vt_info: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """
    Turn VirusTotal report into a 0-100 risk score.
    vt_info is expected to be the dict returned by get_virustotal_report().
    """
    if not vt_info:
        return 0, ["VT_NOT_AVAILABLE"]

    flags: List[str] = []

    if vt_info.get("enabled") is False:
        return 0, ["VT_DISABLED"]

    error = vt_info.get("error")
    if error:
        return 0, ["VT_ERROR"]

    if not vt_info.get("found"):
        return 0, []

    malicious = _safe_int(vt_info.get("malicious"))
    suspicious = _safe_int(vt_info.get("suspicious"))
    total = _safe_int(vt_info.get("total_engines"))
    detections = malicious + suspicious

    if total > 0:
        ratio = detections / float(total)
    else:
        ratio = 0.0

    score = 0

    if detections == 0:
        score = 0
    elif detections <= 3:
        score = 60
    else:
        score = 90

    # Slight adjustments based on ratio of engines.
    if ratio >= 0.25 and score < 95:
        score = max(score, 90)
    elif ratio >= 0.10 and score < 80:
        score = max(score, 70)

    flags.append("VT_DETECTED" if detections > 0 else "VT_CLEAN")
    return _clamp_score(score), list(set(flags))


def score_ml(ml_info: Optional[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """
    Turn ML model output into a 0-100 risk score.
    ml_info is expected to be the dict returned by score_pe_file().
    """
    if not ml_info:
        return 0, ["ML_NOT_AVAILABLE"]

    flags: List[str] = []

    prob = ml_info.get("ml_score", 0.0)
    verdict = ml_info.get("ml_verdict", "benign")

    score = _clamp_score(float(prob) * 100.0)

    if verdict == "malicious":
        flags.append("ML_MALICIOUS")

    return score, list(set(flags))


# ---------------------------------------------------------------------------
# Final fusion logic
# ---------------------------------------------------------------------------

def compute_final_verdict(
    file_type_info: Optional[Dict[str, Any]],
    entropy_info: Optional[Dict[str, Any]],
    yara_info: Optional[Dict[str, Any]],
    vt_info: Optional[Dict[str, Any]],
    ml_info: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Combine all engines (file type, entropy, YARA, VirusTotal, ML)
    into a single numeric score and verdict label.
    """

    ft_score, ft_flags = score_file_type(file_type_info)
    ent_score, ent_flags = score_entropy(entropy_info)
    yara_score, yara_flags = score_yara(yara_info)
    vt_score, vt_flags = score_virustotal(vt_info)
    ml_score, ml_flags = score_ml(ml_info)

    component_scores = {
        "file_type": ft_score,
        "entropy": ent_score,
        "yara": yara_score,
        "virustotal": vt_score,
        "ml": ml_score,
    }

    # -----------------------------
    # Weighted sum of all component scores
    # If ML is not available (non-PE files), we drop its weight
    # and renormalize the remaining weights so they still sum to 1.
    # -----------------------------
    weights = WEIGHTS.copy()

    # score_ml() returns the flag "ML_NOT_AVAILABLE" when ml_info is None
    if "ML_NOT_AVAILABLE" in ml_flags:
        weights["ml"] = 0.0

    total_w = sum(weights.values()) or 1.0

    final_score_float = (
        weights["file_type"] * ft_score
        + weights["entropy"] * ent_score
        + weights["yara"] * yara_score
        + weights["virustotal"] * vt_score
        + weights["ml"] * ml_score
    ) / total_w

    final_score = _clamp_score(final_score_float)

    # Base verdict from the numeric score.
    if final_score <= VERDICT_THRESHOLDS["benign_max"]:
        verdict = "benign"
    elif final_score <= VERDICT_THRESHOLDS["suspicious_max"]:
        verdict = "suspicious"
    else:
        verdict = "malicious"

    all_flags: List[str] = ft_flags + ent_flags + \
        yara_flags + vt_flags + ml_flags

    # ------------------------------------------------------------------
    # Override rules (logic on top of the numeric score)
    # ------------------------------------------------------------------

    # 1) Strong VirusTotal detection → force malicious.
    if vt_info and vt_info.get("enabled") and vt_info.get("found") and not vt_info.get("error"):
        malicious = _safe_int(vt_info.get("malicious"))
        suspicious = _safe_int(vt_info.get("suspicious"))
        total = _safe_int(vt_info.get("total_engines"))
        detections = malicious + suspicious
        ratio = detections / float(total) if total > 0 else 0.0

        if detections >= 3 or ratio >= 0.10:
            verdict = "malicious"
            all_flags.append("OVERRIDE_VT_MALICIOUS")

    # 2) Critical YARA rule → force malicious.
    if "YARA_CRITICAL" in yara_flags:
        verdict = "malicious"
        all_flags.append("OVERRIDE_YARA_CRITICAL")

    # 3) All signals clean → force benign / lower score.
    vt_clean = False
    if vt_info and vt_info.get("enabled") and vt_info.get("found") and not vt_info.get("error"):
        malicious = _safe_int(vt_info.get("malicious"))
        suspicious = _safe_int(vt_info.get("suspicious"))
        vt_clean = (malicious == 0 and suspicious == 0)

    all_clean = (
        vt_clean
        and yara_score == 0
        and ml_score < 30
        and ent_score < 50
    )

    if all_clean:
        if final_score > VERDICT_THRESHOLDS["benign_max"]:
            final_score = VERDICT_THRESHOLDS["benign_max"]
        verdict = "benign"
        all_flags.append("OVERRIDE_ALL_CLEAN")

    # 4) Only entropy is high, others are quiet → keep at most 'suspicious'.
    if (
        ent_score >= 60
        and yara_score == 0
        and vt_score == 0
        and ml_score < 50
        and verdict == "malicious"
    ):
        verdict = "suspicious"
        all_flags.append("OVERRIDE_ENTROPY_ONLY")

    # ------------------------------------------------------------------
    # Confidence estimation
    # ------------------------------------------------------------------
    strong_signals = 0
    if vt_score >= 70:
        strong_signals += 1
    if yara_score >= 70:
        strong_signals += 1
    if ml_score >= 70:
        strong_signals += 1
    if ent_score >= 70:
        strong_signals += 1

    if strong_signals >= 2:
        confidence = "high"
    elif strong_signals == 1:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "final_score": final_score,
        "verdict": verdict,
        "confidence": confidence,
        "component_scores": component_scores,
        "flags": list(set(all_flags)),
        # no "reasons" key anymore
    }
