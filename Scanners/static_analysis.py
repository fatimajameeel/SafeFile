from .file_type import detect_file_type
from .entropy_analyzer import file_entropy
from .pe_entropy import analyze_pe_entropy
from .entropy_rules import interpret_pe_entropy
from .yara_scanner import scan_file_with_yara


def analyze_file(file_path: str) -> dict:
    # 1) File type
    file_type_info = detect_file_type(file_path)

    # 2) Overall entropy for the whole file (any file type)
    overall = file_entropy(file_path)

    # 3) Run PE-specific entropy
    pe_report = None
    pe_interpretation = None

    # decide if it is likely a PE based on detector output
    final_type = (file_type_info.get("final_type") or "").lower()
    magic_type = (file_type_info.get("magic_type") or "").lower()

    is_probably_pe = final_type in [
        "exe", "dll"] or magic_type in ["exe", "dll"]

    if is_probably_pe:
        pe_report = analyze_pe_entropy(file_path)

        if pe_report.get("is_pe", False):
            pe_interpretation = interpret_pe_entropy(pe_report)

    # 4) YARA Scan
    yara_report = scan_file_with_yara(file_path)

    #  Build final combined result
    return {
        "file_type": file_type_info,
        "entropy": {
            "overall_entropy": overall,
            "pe_report": pe_report,
            "pe_interpretation": pe_interpretation,
        },
        "yara": yara_report
    }
