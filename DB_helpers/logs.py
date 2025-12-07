# DB_helpers/logs.py

from db import get_db

"""
    Insert a single log entry into system_log table.

    Parameters:
        user_id (int or None)
        scan_id (int or None)
        file_id (int or None)
        event_type (str)  -> e.g. "SCAN_STARTED", "FILE_SCANNED"
        detail (str)      -> description
        severity (str)    -> "INFO", "WARNING", "ERROR"
"""


def log_event(
    user_id=None,
    scan_id=None,
    file_id=None,
    event_type="INFO",
    detail=None,
    severity="INFO"
):

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        INSERT INTO system_log (
            user_id,
            scan_id,
            file_id,
            event_type,
            event_detail,
            severity
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, scan_id, file_id, event_type, detail, severity)
    )

    db.commit()
