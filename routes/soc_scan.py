# routes/soc_scan.py

from flask import render_template, request, current_app, session
import os
from werkzeug.utils import secure_filename
from Scanners.static_analysis import analyze_file
from Scanners.file_type import is_corrupted

from DB_helpers.scans import create_scan, save_file_result
from DB_helpers.logs import log_event
from .soc_routes import soc_bp


@soc_bp.route("/soc/scan", methods=["GET", "POST"])
def soc_scan():
    """
    SOC Scan page.
    Two-step flow:
      1) Upload files/folder -> show message + list of files + Scan button
      2) Press Scan button   -> run analysis and show results table
    """
    error_message = None
    file_message = None
    folder_message = None
    folder_file_list = []
    analysis_results = []
    uploaded_files = []  # files waiting to be scanned
    scan_type = None

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    vt_api_key = current_app.config.get("VT_API_KEY")

    if request.method == "POST":
        action = request.form.get("action")

        # =========================
        # STEP 2: SCAN REQUEST
        # =========================
        if action == "scan":
            # 1) Get list of filenames selected to scan
            filenames = request.form.getlist("files_to_scan")

            # 2) Get current user ID from session
            user_id = session.get("user_id")
            if user_id is None:
                user_id = 0  # or handle anonymous

            # 3)
            scan_type = "file"

            # 4) Create a scan entry in the database
            scan_id = create_scan(user_id=user_id, scan_type=scan_type)

            # 5) Log: Scan Started
            log_event(
                user_id=user_id,
                scan_id=scan_id,
                file_id=None,
                event_type="SCAN_STARTED",
                detail=f"Scan started for {len(filenames)} file(s).",
                severity="INFO",
            )

            # 6) Loop through each file and analyze
            for name in filenames:
                save_path = os.path.join(upload_folder, name)

                # Run analysis for each file
                analysis = analyze_file(save_path, vt_api_key=vt_api_key)
                file_type_info = analysis["file_type"]
                entropy_info = analysis["entropy"]
                yara_info = analysis["yara"]
                vt_info = analysis.get("virustotal")
                ml_info = analysis.get("ml")
                malware_type = analysis.get("malware_type")
                final_verdict = analysis.get("final_verdict")

                # Save this file's result into the database
                file_id = save_file_result(
                    scan_id=scan_id,
                    file_name=name,
                    analysis_result=analysis
                )

                # Log: file scanned
                verdict_str = None
                if isinstance(final_verdict, dict):
                    verdict_str = final_verdict.get("verdict")
                if not verdict_str:
                    verdict_str = "unknown"

                log_event(
                    user_id=user_id,
                    scan_id=scan_id,
                    file_id=file_id,
                    event_type="FILE_SCANNED",
                    detail=f"Scanned {name} — verdict: {verdict_str}",
                    severity="INFO",
                )

                # log: YARA_MATCH if any rules hit
                if isinstance(yara_info, dict):
                    matches = yara_info.get("matches") or []
                    rule_names = [
                        m["rule"] for m in matches
                        if isinstance(m, dict) and "rule" in m
                    ]
                    if rule_names:
                        log_event(
                            user_id=user_id,
                            scan_id=scan_id,
                            file_id=file_id,
                            event_type="YARA_MATCH",
                            detail=f"YARA matched: {', '.join(rule_names)}",
                            severity="WARNING",
                        )

                # log: VT_ALERT if VT says malicious
                if isinstance(vt_info, dict):
                    vt_mal = vt_info.get("malicious")
                    vt_total = vt_info.get("total_engines")
                    if vt_mal and vt_total:
                        log_event(
                            user_id=user_id,
                            scan_id=scan_id,
                            file_id=file_id,
                            event_type="VT_ALERT",
                            detail=f"VirusTotal: {vt_mal}/{vt_total} engines flagged this file",
                            severity="WARNING",
                        )

                # Store data for displaying in the UI
                analysis_results.append({
                    "file_id": file_id,
                    "display_name": name,
                    **file_type_info,
                    "entropy": entropy_info,
                    "yara": yara_info,
                    "virustotal": vt_info,
                    "ml": ml_info,
                    "malware_type": malware_type,
                    "final_verdict": final_verdict,
                })

            # 7) Log: scan completed
            log_event(
                user_id=user_id,
                scan_id=scan_id,
                file_id=None,
                event_type="SCAN_COMPLETED",
                detail=f"Scan completed for {len(filenames)} file(s).",
                severity="INFO",
            )

            # --- FINAL VERDICT WARNING (suspicious / malicious) ---
            verdict_label = None
            verdict_score = None
            if isinstance(final_verdict, dict):
                verdict_label = final_verdict.get("verdict")
                verdict_score = final_verdict.get("final_score")

            if verdict_label in ("suspicious", "malicious"):
                log_event(
                    user_id=user_id,
                    scan_id=scan_id,
                    file_id=file_id,
                    event_type="FINAL_VERDICT_WARNING",
                    detail=f"Final verdict for {name}: {verdict_label} (score {verdict_score}).",
                    severity="WARNING",
                )
                # --- HIGH ENTROPY / PACKED PE WARNING ---
            overall_entropy = None
            pe_flags = []
            pe_risk = None

            if isinstance(entropy_info, dict):
                overall_entropy = entropy_info.get("overall_entropy")
                pe_interp = entropy_info.get("pe_interpretation") or {}
                pe_flags = pe_interp.get("flags") or []
                pe_risk = pe_interp.get("risk_score")

            # Example simple rules – you can tweak thresholds if you want
            if overall_entropy is not None and overall_entropy >= 7.3:
                log_event(
                    user_id=user_id,
                    scan_id=scan_id,
                    file_id=file_id,
                    event_type="HIGH_ENTROPY",
                    detail=f"High entropy detected ({overall_entropy:.2f}) in {name}.",
                    severity="WARNING",
                )

            if pe_risk is not None and pe_risk >= 40:
                flag_str = ", ".join(
                    pe_flags) if pe_flags else "entropy anomalies"
                log_event(
                    user_id=user_id,
                    scan_id=scan_id,
                    file_id=file_id,
                    event_type="PE_ENTROPY_SUSPICIOUS",
                    detail=f"PE entropy suspicious for {name}: {flag_str} (risk {pe_risk}).",
                    severity="WARNING",
                )

                # --- FILE TYPE MISMATCH WARNING ---
            mismatch = file_type_info.get("mismatch")
            if mismatch:
                declared_ext = file_type_info.get("declared_extension")
                detected_type = file_type_info.get("final_type")

                log_event(
                    user_id=user_id,
                    scan_id=scan_id,
                    file_id=file_id,
                    event_type="FILETYPE_MISMATCH",
                    detail=(
                        f"Type mismatch for {name}: declared .{declared_ext or '?'} "
                        f"but detected .{detected_type or '?'}."
                    ),
                    severity="WARNING",
                )

                # --- ML SUSPICIOUS / MALWARE WARNING ---
            ml_score = None
            ml_verdict_label = None
            if isinstance(ml_info, dict):
                ml_score = ml_info.get("ml_score") or ml_info.get("score")
                ml_verdict_label = (
                    ml_info.get("ml_verdict")
                    or ml_info.get("verdict")
                    or ml_info.get("label")
                )

            if ml_verdict_label == "malware" or (ml_score is not None and ml_score >= 0.8):
                log_event(
                    user_id=user_id,
                    scan_id=scan_id,
                    file_id=file_id,
                    event_type="ML_SUSPICIOUS",
                    detail=(
                        f"ML model flagged {name} as {ml_verdict_label or 'suspicious'} "
                        f"(score {ml_score:.2f})." if ml_score is not None
                        else f"ML model flagged {name} as {ml_verdict_label}."
                    ),
                    severity="WARNING",
                )

            file_message = f"Scanned {len(filenames)} file(s)."

        # =========================
        # STEP 1: UPLOAD REQUEST
        # =========================
        else:
            # ---------- SINGLE FILE UPLOAD ----------
            single_files = request.files.getlist("single_files")

            if single_files and any(f.filename for f in single_files):
                scan_type = "file"
                saved_names = []

                for f in single_files:
                    if not f.filename:
                        continue

                    # 1) SIZE CHECK
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(0)

                    if size > 100 * 1024 * 1024:
                        # --- ERROR LOG: FILE_TOO_LARGE ---
                        log_event(
                            user_id=session.get("user_id") or 0,
                            scan_id=None,
                            file_id=None,
                            event_type="FILE_TOO_LARGE",
                            detail=f"Upload rejected: '{f.filename}' is {size/1024/1024:.1f} MB (limit 100 MB).",
                            severity="ERROR"
                        )

                        error_message = (
                            f"'{f.filename}' is larger than 100 MB. "
                            "Please upload a file smaller than 100 MB."
                        )
                        return render_template(
                            "soc_scan.html",
                            error_message=error_message,
                            file_message=None,
                            folder_message=None,
                            folder_file_list=[],
                            analysis_results=[],
                            uploaded_files=[],
                        )

                    # 2) SAVE FILE
                    clean_name = secure_filename(f.filename)
                    save_path = os.path.join(upload_folder, clean_name)
                    f.save(save_path)

                    # 3) CORRUPTION CHECK
                    if is_corrupted(save_path):
                        # --- ERROR LOG: FILE_CORRUPTED (folder file) ---
                        log_event(
                            user_id=session.get("user_id") or 0,
                            scan_id=None,
                            file_id=None,
                            event_type="FILE_CORRUPTED",
                            detail=f"Corrupted file rejected: '{display_name}' could not be read.",
                            severity="ERROR"
                        )

                        error_message = f"'{display_name}' appears corrupted or unreadable."
                        os.remove(save_path)
                        return render_template(
                            "soc_scan.html",
                            error_message=error_message,
                            file_message=None,
                            folder_message=None,
                            folder_file_list=[],
                            analysis_results=[],
                            uploaded_files=[],
                        )

                    saved_names.append(clean_name)

                    # add to "ready to scan" list
                    uploaded_files.append({
                        "display_name": clean_name,
                        "saved_name": clean_name,
                    })

                if len(saved_names) == 1:
                    file_message = f"File '{saved_names[0]}' uploaded."
                elif len(saved_names) > 1:
                    file_message = f"{len(saved_names)} files uploaded."

            # ---------- FOLDER UPLOAD ----------
            folder_files = request.files.getlist("folder_files")

            if folder_files and any(f.filename for f in folder_files):
                scan_type = "folder"
                total_size = 0

                # 1) CALCULATE TOTAL SIZE
                for f in folder_files:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(0)
                    total_size += size

                # 2) SIZE CHECK (500 MB)
                if total_size > 500 * 1024 * 1024:
                    mb = total_size / (1024 * 1024)

                    # --- ERROR LOG: FILE_TOO_LARGE (folder) ---
                    log_event(
                        user_id=session.get("user_id") or 0,
                        scan_id=None,
                        file_id=None,
                        event_type="FILE_TOO_LARGE",
                        detail=f"Folder upload rejected: total size {mb:.1f} MB (limit 500 MB).",
                        severity="ERROR"
                    )

                    error_message = (
                        f"Folder size is {mb:.1f} MB. "
                        "Maximum allowed size is 500 MB."
                    )
                    return render_template(
                        "soc_scan.html",
                        error_message=error_message,
                        file_message=None,
                        folder_message=None,
                        folder_file_list=[],
                        analysis_results=[],
                        uploaded_files=[],
                    )

                # 3) SAVE + CHECK CORRUPTION
                for f in folder_files:
                    if not f.filename:
                        continue

                    display_name = f.filename
                    base_name = os.path.basename(f.filename)
                    clean_name = secure_filename(base_name)

                    save_path = os.path.join(upload_folder, clean_name)
                    f.save(save_path)

                    # corruption check
                    if is_corrupted(save_path):
                        # --- ERROR LOG: FILE_CORRUPTED ---
                        log_event(
                            user_id=session.get("user_id") or 0,
                            scan_id=None,
                            file_id=None,
                            event_type="FILE_CORRUPTED",
                            detail=f"Corrupted file rejected: '{clean_name}' could not be read.",
                            severity="ERROR"
                        )

                        error_message = f"'{clean_name}' appears to be corrupted or unreadable."
                        os.remove(save_path)
                        return render_template(
                            "soc_scan.html",
                            error_message=error_message,
                            file_message=None,
                            folder_message=None,
                            folder_file_list=[],
                            analysis_results=[],
                            uploaded_files=[],
                        )

                    folder_file_list.append(display_name)

                    uploaded_files.append({
                        "display_name": display_name,
                        "saved_name": clean_name,
                    })

                folder_message = "Folder uploaded."

    # RETURN PAGE
    return render_template(
        "soc_scan.html",
        error_message=error_message,
        file_message=file_message,
        folder_message=folder_message,
        folder_file_list=folder_file_list,
        analysis_results=analysis_results,
        uploaded_files=uploaded_files,
    )
