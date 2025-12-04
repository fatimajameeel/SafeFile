from .file_type import detect_file_type
from .entropy_analyzer import file_entropy
from .pe_entropy import analyze_pe_entropy
from .entropy_rules import interpret_pe_entropy
from .yara_scanner import scan_file_with_yara
from .virustotal_client import get_virustotal_report
from .pe_ml_runtime import score_pe_file
from .malware_type import infer_malware_type
from .final_verdict import compute_final_verdict


def analyze_file(file_path: str, vt_api_key: str | None = None) -> dict:
    # 1) File type
    file_type_info = detect_file_type(file_path)

    # 2) Overall entropy for the whole file (any file type)
    overall = file_entropy(file_path)

    # 3) Run PE-specific entropy and ML result
    pe_report = None
    pe_interpretation = None
    ml_result = None

    # decide if it is likely a PE based on detector output
    final_type = (file_type_info.get("final_type") or "").lower()
    magic_type = (file_type_info.get("magic_type") or "").lower()

    is_probably_pe = final_type in [
        "exe", "dll"] or magic_type in ["exe", "dll"]

    if is_probably_pe:
        pe_report = analyze_pe_entropy(file_path)

        if pe_report.get("is_pe", False):
            pe_interpretation = interpret_pe_entropy(pe_report)

        # Run the ML model for PE files
        try:
            ml_result = score_pe_file(file_path)
        except Exception as e:
            # If something goes wrong, don't break the whole scan
            ml_result = {
                "error": str(e),
                "ml_score": None,
                "ml_verdict": None,
                "ml_threshold": 0.4,
            }

    # 4) YARA Scan
    yara_report = scan_file_with_yara(file_path)

    # 5) VirusTotal
    if vt_api_key:
        vt_report = get_virustotal_report(file_path, vt_api_key)
    else:
        vt_report = {
            "enabled": False,
            "found": False,
            "error": "No API key configured",
        }

    # 6) Malware type (VT + YARA)
    malware_type = infer_malware_type(vt_report, yara_report)

    # 7) Final verdict from all engines

    final_verdict = compute_final_verdict(
        file_type_info=file_type_info,
        entropy_info={
            "overall_entropy": overall,
            "pe_report": pe_report,
            "pe_interpretation": pe_interpretation,
        },
        yara_info=yara_report,
        vt_info=vt_report,
        ml_info=ml_result,
    )

    #  Build final combined result
    return {
        "file_type": file_type_info,
        "entropy": {
            "overall_entropy": overall,
            "pe_report": pe_report,
            "pe_interpretation": pe_interpretation,
        },
        "yara": yara_report,
        "virustotal": vt_report,
        "ml": ml_result,
        "malware_type": malware_type,
        "final_verdict": final_verdict,
    }
