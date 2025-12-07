from db import get_db
import json
import os


def create_scan(user_id: int, scan_type: str) -> int:
    """
    Create a new scan entry in the databse and return its scan_id.
    """
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        INSERT INTO scan (user_id, scan_type)
        VALUES (?, ?)
        """,
        (user_id, scan_type)
    )

    db.commit()
    return cursor.lastrowid


def save_file_result(
    scan_id: int,
    file_name: str,
    analysis_result: dict
) -> int:
    """
    Save one analyzed file's result into the file table.

    - scan_id: which scan this file belongs to
    - file_name: original name of the uploaded file
    - analysis_result: dict returned by analyze_file()
    """
    db = get_db()
    cursor = db.cursor()

    # -------- 1) FILE TYPE --------
    file_type_block = analysis_result.get("file_type") or {}

    # This is the correct field according to your detect_file_type() output
    file_type_label = file_type_block.get("final_type")

    # If final_type is None, fallback to declared extension
    if not file_type_label:
        file_type_label = file_type_block.get("declared_extension")

    # If still nothing, derive from file name
    if not file_type_label and file_name:
        _, ext = os.path.splitext(file_name)
        if ext:
            file_type_label = ext.lstrip(".").lower()

    # -------- 2) ENTROPY --------
    entropy_value = None
    entropy_block = analysis_result.get("entropy")
    if isinstance(entropy_block, dict):
        entropy_value = entropy_block.get("overall_entropy")

    # -------- 3) YARA HITS (rule names only) --------
    yara_hits_json = None
    yara_block = analysis_result.get("yara")

    if yara_block is not None:
        rule_names: list[str] = []

        # YARA result is a dict with "matches" list
        if isinstance(yara_block, dict):
            matches = yara_block.get("matches")
            if isinstance(matches, list):
                for m in matches:
                    # m is a dict from yara_scanner
                    if isinstance(m, dict) and "rule" in m:
                        rule_names.append(m["rule"])
                    elif isinstance(m, str):
                        rule_names.append(m)

        elif isinstance(yara_block, list):
            for m in yara_block:
                if isinstance(m, dict) and "rule" in m:
                    rule_names.append(m["rule"])
                elif isinstance(m, str):
                    rule_names.append(m)

        if rule_names:
            yara_hits_json = json.dumps(rule_names)  # ["Rule1", "Rule2"]

    # -------- 4) FILE HASH --------
    vt_report = analysis_result.get("virustotal") or {}
    file_hash = analysis_result.get("sha256") or vt_report.get("sha256")

    # -------- 5) VIRUSTOTAL: full JSON + counts --------
    vt_report_json = json.dumps(vt_report) if vt_report else None

    vt_malicious_count = None
    vt_total_engines = None

    if isinstance(vt_report, dict) and vt_report:
        vt_malicious_count = vt_report.get("malicious")
        vt_total_engines = vt_report.get("total_engines")

    # -------- 6) ML VERDICT --------
    ml_block = analysis_result.get("ml") or {}
    ml_verdict = ml_block.get("ml_verdict") or ml_block.get(
        "verdict") or ml_block.get("label")

    # -------- 7) FINAL VERDICT & RISK SCORE --------
    final_block = analysis_result.get("final_verdict") or {}
    risk_score = final_block.get("final_score")      # 0–100
    # "benign" / "suspicious" / "malicious"
    final_verdict = final_block.get("verdict")

    # -------- 8) MALWARE TYPE --------
    malware_raw = analysis_result.get("malware_type")
    malware_type = None

    if isinstance(malware_raw, dict):
        malware_type = malware_raw.get("label") or malware_raw.get("type")
    elif isinstance(malware_raw, str):
        malware_type = malware_raw
    elif malware_raw is not None:
        malware_type = str(malware_raw)

    # -------- 9) IS_PE FLAG --------
    is_pe = None
    if "is_pe" in file_type_block:
        is_pe = 1 if file_type_block.get("is_pe") else 0

    # -------- 10) INSERT INTO DATABASE --------
    cursor.execute(
        """
        INSERT INTO file (
            scan_id,
            file_name,
            file_type_detected,
            entropy_value,
            yara_hits,
            file_hash,
            vt_report_json,
            ml_verdict,
            final_verdict,
            risk_score,
            malware_type,
            is_pe,
            vt_malicious_count,
            vt_total_engines
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            file_name,
            file_type_label,
            entropy_value,
            yara_hits_json,
            file_hash,
            vt_report_json,
            ml_verdict,
            final_verdict,
            risk_score,
            malware_type,
            is_pe,
            vt_malicious_count,
            vt_total_engines,
        )
    )

    db.commit()
    return cursor.lastrowid
