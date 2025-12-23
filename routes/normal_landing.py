# routes/user/landing.py

from datetime import datetime, timedelta
from flask import render_template, request, current_app, session
import os
import uuid
from werkzeug.utils import secure_filename

from Scanners.static_analysis import analyze_file
from Scanners.file_type import is_corrupted
from Scanners.easy_results import format_verdict
from DB_helpers.scans import create_scan, save_file_result
from db import get_db
from datetime import datetime, timezone
from .normal_routes import normal_bp


def _save_with_unique_name(upload_folder: str, original_name: str) -> tuple[str, str]:
    """
    Returns (save_path, saved_name)
    - saved_name is the clean filename we store on disk
    - we add a short uuid prefix to avoid collisions
    """
    clean = secure_filename(original_name)
    unique = f"{uuid.uuid4().hex[:8]}_{clean}"
    save_path = os.path.join(upload_folder, unique)
    return save_path, unique


def _simplify_result(display_name: str, analysis: dict) -> dict:
    ft = analysis.get("file_type") or {}
    fv = analysis.get("final_verdict") or {}

    raw_verdict = None
    if isinstance(fv, dict):
        raw_verdict = fv.get("verdict")

    detected = ft.get("final_type")
    declared = ft.get("declared_extension")

    return {
        "file_name": display_name,
        "declared_type": human_file_type(declared),
        "detected_type": human_file_type(detected),
        "mismatch": bool(ft.get("mismatch")),
        "raw_verdict": (raw_verdict or "unknown").lower(),
        "verdict": format_verdict(raw_verdict),
    }


def human_file_type(detected: str) -> str:
    detected = (detected or "").lower()

    mapping = {
        "pdf": "PDF Document",
        "exe": "Windows Application",
        "dll": "Windows Library",
        "zip": "ZIP Archive",
        "rar": "RAR Archive",
        "doc": "Word Document",
        "docx": "Word Document",
        "xls": "Excel Spreadsheet",
        "xlsx": "Excel Spreadsheet",
        "png": "PNG Image",
        "jpg": "JPEG Image",
        "jpeg": "JPEG Image",
        "txt": "Text File",
        "bin": "Binary File",
        "unknown": "Unknown File Type",
    }

    return mapping.get(detected, detected.upper() if detected else "Unknown File Type")


def time_ago(ts: str) -> str:
    if not ts:
        return "Scanned just now"

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ]

    dt = None
    for fmt in formats:
        try:
            dt = datetime.strptime(ts, fmt)
            break
        except ValueError:
            continue

    if not dt:
        return f"Scanned {ts}"

    # ------------------ IMPORTANT PART ------------------
    # DB timestamp is UTC → convert to Bahrain time
    dt_bh = dt + timedelta(hours=3)
    now_bh = datetime.utcnow() + timedelta(hours=3)
    # ----------------------------------------------------

    diff = now_bh - dt_bh
    seconds = int(diff.total_seconds())

    if seconds < 10:
        return "Scanned just now"
    if seconds < 60:
        return f"Scanned {seconds} seconds ago"

    minutes = seconds // 60
    if minutes < 60:
        return f"Scanned {minutes} minute{'s' if minutes != 1 else ''} ago"

    hours = minutes // 60
    if hours < 24:
        return f"Scanned {hours} hour{'s' if hours != 1 else ''} ago"

    days = hours // 24
    return f"Scanned {days} day{'s' if days != 1 else ''} ago"


@normal_bp.route("/landing", methods=["GET", "POST"])
def normal_landing():
    # --------------- USER / DEFAULT STATE ----------------
    user_id = session.get("user_id")

    error_message = None

    scan_mode = None              # "file" or "folder"
    single_result = None
    folder_results = []
    folder_summary = None

    last_scan = None

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    vt_api_key = current_app.config.get("VT_API_KEY")

    # --------------- HANDLE UPLOAD + SCAN (POST) ----------------
    if request.method == "POST":

        # --------------- SINGLE FILE(S) ----------------
        single_files = request.files.getlist("single_files")
        if single_files and any(f.filename for f in single_files):
            scan_mode = "file"
            results = []

            for f in single_files:
                if not f.filename:
                    continue

                # Size check (100 MB)
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)

                if size > 100 * 1024 * 1024:
                    error_message = f"'{f.filename}' is larger than 100 MB. Please upload a smaller file."
                    return render_template(
                        "normal_landing.html",
                        error_message=error_message,
                        scan_mode=None,
                        single_result=None,
                        folder_results=[],
                        folder_summary=None,
                        last_scan=last_scan,
                    )

                # Save file with unique name
                save_path, saved_name = _save_with_unique_name(
                    upload_folder, f.filename)
                f.save(save_path)

                # Corruption check
                if is_corrupted(save_path):
                    os.remove(save_path)
                    error_message = f"'{f.filename}' appears corrupted or unreadable."
                    return render_template(
                        "normal_landing.html",
                        error_message=error_message,
                        scan_mode=None,
                        single_result=None,
                        folder_results=[],
                        folder_summary=None,
                        last_scan=last_scan,
                    )

                # Analyze
                analysis = analyze_file(save_path, vt_api_key=vt_api_key)

                # Save to DB (each file gets its own scan_id)
                scan_id = create_scan(user_id=user_id, scan_type="file")
                save_file_result(
                    scan_id=scan_id, file_name=f.filename, analysis_result=analysis)

                # Simplify for UI
                results.append(_simplify_result(
                    display_name=f.filename, analysis=analysis))

            # Show the first file as the main result
            if results:
                single_result = results[0]

        # --------------- FOLDER (SAVE EACH FILE AS ITS OWN SCAN) ----------------
        folder_files = request.files.getlist("folder_files")
        if folder_files and any(f.filename for f in folder_files):
            scan_mode = "folder"

            # Total folder size check (500 MB)
            total_size = 0
            for f in folder_files:
                f.seek(0, os.SEEK_END)
                total_size += f.tell()
                f.seek(0)

            if total_size > 500 * 1024 * 1024:
                mb = total_size / (1024 * 1024)
                error_message = f"Folder size is {mb:.1f} MB. Maximum allowed size is 500 MB."
                return render_template(
                    "normal_landing.html",
                    error_message=error_message,
                    scan_mode=None,
                    single_result=None,
                    folder_results=[],
                    folder_summary=None,
                    last_scan=last_scan,
                )

            counts = {"safe": 0, "suspicious": 0,
                      "malicious": 0, "unknown": 0, "total": 0}

            for f in folder_files:
                if not f.filename:
                    continue

                # Keep folder path for display, but save only base filename on disk
                display_name = f.filename
                base_name = os.path.basename(f.filename)

                save_path, saved_name = _save_with_unique_name(
                    upload_folder, base_name)
                f.save(save_path)

                if is_corrupted(save_path):
                    os.remove(save_path)
                    error_message = f"'{base_name}' appears corrupted or unreadable."
                    return render_template(
                        "normal_landing.html",
                        error_message=error_message,
                        scan_mode=None,
                        single_result=None,
                        folder_results=[],
                        folder_summary=None,
                        last_scan=last_scan,
                    )

                analysis = analyze_file(save_path, vt_api_key=vt_api_key)

                # Save to DB (each file = its own scan_id)
                scan_id = create_scan(user_id=user_id, scan_type="file")
                save_file_result(
                    scan_id=scan_id, file_name=display_name, analysis_result=analysis)

                row = _simplify_result(
                    display_name=display_name, analysis=analysis)
                folder_results.append(row)

                # Count verdicts for summary cards
                v = (row.get("raw_verdict") or "unknown").lower()
                if v == "benign":
                    v = "safe"

                counts["total"] += 1
                if v in counts:
                    counts[v] += 1
                else:
                    counts["unknown"] += 1

            folder_summary = counts

    # --------------- LAST SCAN CARD (GET + POST) ----------------
    if user_id:
        db = get_db()
        row = db.execute(
            """
            SELECT f.file_name, f.timestamp, f.final_verdict
            FROM file AS f
            JOIN scan AS s ON f.scan_id = s.scan_id
            WHERE s.user_id = ?
            ORDER BY f.timestamp DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

        if row:
            verdict_raw = (row["final_verdict"] or "unknown")
            last_scan = {
                "file_name": row["file_name"],
                "time_ago": time_ago(row["timestamp"]),
                "verdict": format_verdict(verdict_raw),
            }

    # --------------- RENDER PAGE ----------------
    return render_template(
        "normal_landing.html",
        error_message=error_message,
        scan_mode=scan_mode,
        single_result=single_result,
        folder_results=folder_results,
        folder_summary=folder_summary,
        last_scan=last_scan,
    )
