# routes/soc_history.py
from flask import render_template, request
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
