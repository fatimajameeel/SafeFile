from flask import render_template
from db import get_db
from .soc_routes import soc_bp


"""
    Show recent system log events from the system_log table.
"""


@soc_bp.route("/soc/logs")
def soc_logs():

    # Open a connection and create a cyrsor to run SQL
    db = get_db()
    cursor = db.cursor()

    # Get the latest 200 events
    cursor.execute(
        """
        SELECT
            log_id,
            timestamp,
            severity,
            event_type,
            event_detail
            FROM system_log
            ORDER BY timestamp DESC
            LIMIT 200
            """
    )

    rows = cursor.fetchall()

    # Convert rows (tuples) into a list of dictionaries for the template
    logs = [
        {
            "id": row[0],
            "timestamp": row[1],
            "severity": row[2],
            "event_type": row[3],
            "detail": row[4],
        }
        for row in rows
    ]
    return render_template("soc_logs.html", logs=logs)
