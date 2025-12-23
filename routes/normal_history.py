# routes/user/history.py

# Flask imports
from flask import render_template, request, session

# Blueprint for normal (non-SOC) users
from .normal_routes import normal_bp

# Database connection helper
from db import get_db


@normal_bp.route("/normal/history")
def normal_history():
    """
    Normal user scan history page.

    Shows a simple list of scans performed by the logged-in user:
    - File name
    - Scan date
    - Final verdict
    """

    # Get database connection
    db = get_db()

    # Get the currently logged-in user ID from the session
    # (this is set during login)
    user_id = session.get("user_id")

    # Read optional filters from the URL query string
    # Example: /normal/history?q=invoice&verdict=malicious
    q = request.args.get("q", "").strip()
    verdict_filter = request.args.get("verdict", "all").lower()

    # Base SQL query:
    # - Get file scan results
    # - Join file table with scan table
    # - Only show scans created by THIS user
    sql = """
        SELECT
            f.file_name,
            f.timestamp,
            f.final_verdict
        FROM file AS f
        JOIN scan AS s ON f.scan_id = s.scan_id
        WHERE s.user_id = ?
    """

    # Parameters list for safe SQL execution
    params = [user_id]

    # If the user typed something in the search box,
    # filter by file name
    if q:
        sql += " AND f.file_name LIKE ?"
        params.append(f"%{q}%")

    # If a verdict filter is selected (Safe / Suspicious / Malicious),
    # apply it to the query
    if verdict_filter != "all":
        allowed = {"benign", "suspicious", "malicious"}
        if verdict_filter in allowed:
            sql += " AND f.final_verdict = ?"
            params.append(verdict_filter)

    # Show newest scans first
    sql += " ORDER BY f.timestamp DESC"

    # Execute the query and fetch all results
    rows = db.execute(sql, params).fetchall()

    # Render the history page template
    return render_template(
        "normal_history.html",
        rows=rows,                 # scan results
        q=q,                       # search box value
        verdict_filter=verdict_filter,
        showing_count=len(rows),   # used for "Showing X results"
    )
