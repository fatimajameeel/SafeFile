# routes/soc_history.py
from flask import render_template, request, make_response, abort
import json
from flask import render_template, request, make_response, abort
from werkzeug.utils import secure_filename
import json
from .soc_routes import soc_bp
from db import get_db


@soc_bp.route("/soc/history")
def soc_history():
    db = get_db()

    # 1) Read filters from the URL (search + verdict)
    # If URL is /soc/history?q=report → q = "report".
    # If URL is /soc/history → q = "".

    q = request.args.get("q", "").strip()
    verdict_filter = request.args.get("verdict", "all").lower()

    # 2) Base SQL: get file + user info
    sql = """
        SELECT
            f.file_id,
            f.file_name,
            f.timestamp,
            f.final_verdict,
            u.email AS uploaded_by
        FROM file AS f
        JOIN scan AS s ON f.scan_id = s.scan_id
        JOIN user AS u ON s.user_id = u.user_id
    """

    params = []  # will hold the values that go into ? placeholders in SQL.
    where_clauses = []  # will hold parts of the WHERE condition

    # 3) Text search (by file name OR uploader email)
    # If q = "malware", this becomes (internally):
    # WHERE (f.file_name LIKE '%malware%' OR u.email LIKE '%malware%')

    if q:
        where_clauses.append("(f.file_name LIKE ? OR u.email LIKE ?)")
        pattern = f"%{q}%"
        params.extend([pattern, pattern])

    # 4) Verdict filter (safe / suspicious / malicious)
    # So if verdict = “suspicious”, you get a condition like:
    # WHERE f.final_verdict = 'Suspicious'

    if verdict_filter != "all":
        allowed = {"benign", "suspicious", "malicious"}
        if verdict_filter in allowed:
            where_clauses.append("f.final_verdict = ?")
            params.append(verdict_filter)

    # 5) Add WHERE if we have any filters
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)

    # 6) Newest first
    sql += " ORDER BY f.timestamp DESC"

    # 7) Run the query
    rows = db.execute(sql, params).fetchall()

    # For "Showing X of Y" text (optional)
    total_count = db.execute("SELECT COUNT(*) FROM file").fetchone()[0]
    showing_count = len(rows)

    # 8) Send everything to the template
    return render_template(
        "soc_history.html",
        rows=rows,
        q=q,
        verdict_filter=verdict_filter,
        total_count=total_count,
        showing_count=showing_count,
    )
# routes/soc_history.py


@soc_bp.route("/soc/history/file/<int:file_id>/download", methods=["GET"])
def download_file_analysis_json(file_id: int):
    """
    Download a PRETTY JSON file for one scanned file.

    URL example:
      /soc/history/file/12/download

    What this does:
      - Reads analysis_json from DB for this file_id
      - Pretty-prints it with indentation
      - Returns it as a downloadable .json attachment
    """
    db = get_db()

    # 1) Get the file name + analysis_json from the DB
    row = db.execute("""
        SELECT file_name, analysis_json
        FROM file
        WHERE file_id = ?
    """, (file_id,)).fetchone()

    # 2) If file_id doesn't exist (or there's no saved analysis), return 404
    if not row:
        abort(404, description="File not found")

    raw_json = row["analysis_json"]
    if not raw_json:
        abort(404, description="No analysis JSON stored for this file")

    # 3) Convert to pretty JSON (with new lines + indentation)
    #    If parsing fails for any reason fallback to raw text
    try:
        parsed = json.loads(raw_json)
        pretty_json = json.dumps(parsed, indent=2, ensure_ascii=False)
    except Exception:
        pretty_json = raw_json

    # 4) Create a safe download filename
    base_name = row["file_name"] or f"file_{file_id}"
    safe_base = secure_filename(base_name) or f"file_{file_id}"
    download_name = f"{safe_base}_analysis.json"

    # 5) Return as a downloadable file (attachment)
    resp = make_response(pretty_json)
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
    return resp
