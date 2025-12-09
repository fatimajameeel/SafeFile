import datetime
from db import get_db


def get_daily_upload():
    """
    Return how many files were scanned each day in the last 7 days.

    The result is shaped for Chart.js:

    {
        "labels": ["Dec 03", "Dec 04", ..., "Dec 09"],
        "counts": [10, 5, ..., 7],
    }

    - We count rows in the `file` table, grouped by DATE(timestamp).
    - We return 7 days (today and the previous 6 days),
      even if some days have 0 scans.
    """

    db = get_db()
    cursor = db.cursor()

    # 1) get the date range from today and the previous 6 days
    today = datetime.datetime.today()
    start_date = today - datetime.timedelta(days=6)

    # convert to string that the SQLite will understands
    # compare only the date part
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = today.strftime("%Y-%m-%d")

    # 2) Query the database : count how many files per day

    cursor.execute(
        """
        SELECT
            DATE(timestamp) AS day,
            COUNT(*) AS total_files
        FROM file
        WHERE DATE(timestamp) BETWEEN ? AND ?
        GROUP BY day
        ORDER BY day
        """,
        (start_str, end_str),
    )

    rows = cursor.fetchall()

    # 3) Build a mapping  { "2025-12-03": 10, "2025-12-04": 5, ... }

    counts_by_day = {}
    for row in rows:
        day_str = row[0]
        total = row[1] or 0
        counts_by_day[day_str] = total

    # 4) Prepare the final labels + counts arrays.
    #    We loop from start_date to today so we always get 7 entries,
    #    even if there were no scans on some days (we put 0).
    labels: list[str] = []
    counts: list[int] = []

    current = start_date
    while current <= today:
        iso_str = current.strftime("%Y-%m-%d")

        # Human-friendly label for the chart, e.g. "Dec 03"
        pretty_label = current.strftime("%b %d")

        labels.append(pretty_label)
        counts.append(counts_by_day.get(iso_str, 0))

        current += datetime.timedelta(days=1)

    # 5) Return structure ready for Chart.js
    return {
        "labels": labels,
        "counts": counts,
    }
