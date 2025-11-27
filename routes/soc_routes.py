# routes/soc_routes.py

from flask import Blueprint, render_template, request, current_app
import os
from werkzeug.utils import secure_filename
from Scanners.static_analysis import analyze_file
from Scanners.file_type import is_corrupted

soc_bp = Blueprint("soc", __name__)


@soc_bp.route("/normal/normal")
def normal_scan():
    return render_template("normal_scan.html")


@soc_bp.route("/soc/home")
def soc_home():
    return render_template("soc_home.html")


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

    upload_folder = current_app.config["UPLOAD_FOLDER"]

    if request.method == "POST":
        action = request.form.get("action")

        # =========================
        # STEP 2: SCAN REQUEST
        # =========================
        if action == "scan":
            filenames = request.form.getlist("files_to_scan")

            for name in filenames:
                save_path = os.path.join(upload_folder, name)

                # Run analysis for each file
                analysis = analyze_file(save_path)
                file_type_info = analysis["file_type"]
                entropy_info = analysis["entropy"]
                yara_info = analysis["yara"]

                analysis_results.append({
                    "display_name": name,
                    **file_type_info,
                    "entropy": entropy_info,
                    "yara": yara_info
                })

            file_message = f"Scanned {len(filenames)} file(s)."

        # =========================
        # STEP 1: UPLOAD REQUEST
        # =========================
        else:
            # ---------- SINGLE FILE UPLOAD ----------
            single_files = request.files.getlist("single_files")

            if single_files and any(f.filename for f in single_files):
                saved_names = []

                for f in single_files:
                    if not f.filename:
                        continue

                    # 1) SIZE CHECK
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(0)

                    if size > 100 * 1024 * 1024:
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


@soc_bp.route("/soc/history")
def soc_history():
    return render_template("soc_history.html")


@soc_bp.route("/soc/logs")
def soc_logs():
    return render_template("soc_logs.html")
