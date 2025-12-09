import datetime
from db import get_db


def get_activity_last7_days():
    """
    Returns a list of 7 dicts for the last 7 days (including today):

    {
        "date": "2025-12-08",
        "label": "Dec 08",
        "total": 15,
        "alerts": 2
    }

    If a day has no data, total and alerts = 0.
    """

    db = get_db()
    cursor = db.cursor()

    # 1) Range: last 7 days including today
    today = datetime.date.today()
    start_date = today - datetime.timedelta(days=6)

    start_dt = datetime.datetime.combine(start_date, datetime.time.min)
    end_dt = datetime.datetime.combine(today + datetime.timedelta(days=1),
                                       datetime.time.min)

    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    # 2) SQL Query using timestamp instead of created_at
    cursor.execute(
        """
        SELECT
            DATE(timestamp) AS day,
            COUNT(*) AS total_count,
            SUM(
                CASE
                    WHEN LOWER(final_verdict) IN ('suspicious', 'malicious')
                    THEN 1
                    ELSE 0
                END
            ) AS alert_count
        FROM file
        WHERE timestamp >= ? AND timestamp < ?
        GROUP BY DATE(timestamp)
        ORDER BY DATE(timestamp)
        """,
        (start_str, end_str),
    )

    rows = cursor.fetchall()

    # 3) Put results into a dictionary keyed by date
    daily_map = {}
    for day_str, total_count, alert_count in rows:
        daily_map[day_str] = {
            "total": total_count or 0,
            "alerts": alert_count or 0,
        }

    # 4) Build exactly 7 days, filling zeros if missing
    chart_points = []
    for i in range(7):
        day = start_date + datetime.timedelta(days=i)
        iso_date = day.isoformat()

        counts = daily_map.get(iso_date, {"total": 0, "alerts": 0})

        label = day.strftime("%b %d")  # e.g. "Dec 08"

        chart_points.append(
            {
                "date": iso_date,
                "label": label,
                "total": counts["total"],
                "alerts": counts["alerts"],
            }
        )

    return chart_points
