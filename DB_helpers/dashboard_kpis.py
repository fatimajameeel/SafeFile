import datetime
from db import get_db


"""
    Compute the date ranges for:
    - the current 7-day window
    - the previous 7-day window

    Returns a dict with 4 datetime objects:
    {
        "current_start": ...,
        "current_end": ...,
        "previous_start": ...,
        "previous_end": ...,
    }
"""


def _get_week_ranges():
    # Get the current date & time (server time)
    now = datetime.datetime.now()

    # Current week: last 7 days up to now
    current_end = now
    current_start = now - datetime.timedelta(days=7)

    # Previous week : the 7 days before the current week
    previous_end = current_start
    previous_start = current_start - datetime.timedelta(days=7)

    # Returns a dictionary with 4 key
    return {
        "current_start": current_start,
        "current_end": current_end,
        "previous_start": previous_start,
        "previous_end": previous_end,
    }


"""
    Query the database and count how many files fall in this time window,
    grouped by final_verdict.

    We return a dict like:
    {
        "total": 123,
        "safe": 100,
        "suspicious": 15,
        "malicious": 8,
    }
"""


def _query_verdict_counts(start_dt, end_dt):

    db = get_db()
    cursor = db.cursor()

    # Convert datetimes to strings that SQLite can compare
    # Format: 'YYYY-MM-DD HH:MM:SS'
    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str = end_dt.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN final_verdict = 'benign' THEN 1 ELSE 0 END) AS safe_count,
            SUM(CASE WHEN final_verdict = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN final_verdict = 'malicious' THEN 1 ELSE 0 END) AS malicious_count
        FROM file
        WHERE timestamp >= ? AND timestamp < ?
        """,
        (start_str, end_str),
    )

    # Gets the single row returned by the query.
    row = cursor.fetchone()

    # if row[0] is None it uses 0 instead
    total = row[0] or 0
    safe = row[1] or 0
    suspicious = row[2] or 0
    malicious = row[3] or 0

    # Returns a dictionary with the four values.
    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "malicious": malicious,
    }


"""
    Compute the percentage change between current and previous values.

    Formula:
      (current - previous) / previous * 100

    If previous is 0 (or None), we return None because we cannot
    compute a meaningful percentage.
"""


def _compute_change_percent(current_value, previous_value):

    # if there is no previous value or it's 0 we return None (no meaningful trend)
    if previous_value is None or previous_value == 0:
        return None

    # Calculates the percentage change and returns the changes
    change = (current_value - previous_value) / previous_value * 100.0
    return change


"""
    Main function that prepares all KPI data for the dashboard.

    It returns a dict shaped like:

    {
      "period_label": "This week (last 7 days)",
      "comparison_label": "Compared to previous 7 days",
      "cards": [
        {
          "id": "total",
          "title": "Total Files Scanned",
          "current_value": 120,
          "previous_value": 100,
          "change_percent": 20.0,
        },
        ...
      ]
    }

"""


def get_dashboard_kpi_stats():

    # 1) Get the time ranges for current and previous week
    ranges = _get_week_ranges()

    current_start = ranges["current_start"]
    current_end = ranges["current_end"]
    previous_start = ranges["previous_start"]
    previous_end = ranges["previous_end"]

    # 2) Query verdict counts for each week
    current_counts = _query_verdict_counts(current_start, current_end)
    previous_counts = _query_verdict_counts(previous_start, previous_end)

    # 3) Compute detection rates (percentage)
    # current
    current_total = current_counts["total"]
    current_alerts = current_counts["suspicious"] + current_counts["malicious"]

    # if ther were any scans get the detetction rate if
    #  not set it to 0 to avoid divsion by 0

    if current_total > 0:
        current_detection_rate = (current_alerts / current_total) * 100.0
    else:
        current_detection_rate = 0.0

    # previous
    previous_total = previous_counts["total"]
    previous_alerts = previous_counts["suspicious"] + \
        previous_counts["malicious"]

    # Same as above: compute detection rate or default to 0 if no data
    if previous_total > 0:
        previous_detection_rate = (previous_alerts / previous_total) * 100.0
    else:
        previous_detection_rate = 0.0

    # 4) Compute change percentages for each metric
    total_change = _compute_change_percent(
        current_counts["total"], previous_counts["total"])
    safe_change = _compute_change_percent(
        current_counts["safe"], previous_counts["safe"])
    suspicious_change = _compute_change_percent(
        current_counts["suspicious"], previous_counts["suspicious"]
    )
    malicious_change = _compute_change_percent(
        current_counts["malicious"], previous_counts["malicious"]
    )
    detection_rate_change = _compute_change_percent(
        current_detection_rate, previous_detection_rate
    )

    # 4.5) Build verdict distribution for the current week (for the pie chart)
    vd_total = current_counts["total"]
    vd_safe = current_counts["safe"]
    vd_suspicious = current_counts["suspicious"]
    vd_malicious = current_counts["malicious"]

    if vd_total > 0:
        verdict_distribution = [
            {
                "label": "Safe",
                "count": vd_safe,
                "percent": round((vd_safe / vd_total) * 100.0, 1),
            },
            {
                "label": "Suspicious",
                "count": vd_suspicious,
                "percent": round((vd_suspicious / vd_total) * 100.0, 1),
            },
            {
                "label": "Malicious",
                "count": vd_malicious,
                "percent": round((vd_malicious / vd_total) * 100.0, 1),
            },
        ]
    else:
        # No scans this week → empty chart
        verdict_distribution = []

    # 5) Prepare the structure that the template will use
    kpi_stats = {
        "period_label": "This week (last 7 days)",
        "comparison_label": "Compared to previous 7 days",
        "cards": [
            {
                "id": "total",
                "title": "Total Files Scanned",
                "current_value": current_counts["total"],
                "previous_value": previous_counts["total"],
                "change_percent": total_change,
            },
            {
                "id": "safe",
                "title": "Safe",
                "current_value": current_counts["safe"],
                "previous_value": previous_counts["safe"],
                "change_percent": safe_change,
            },
            {
                "id": "suspicious",
                "title": "Suspicious",
                "current_value": current_counts["suspicious"],
                "previous_value": previous_counts["suspicious"],
                "change_percent": suspicious_change,
            },
            {
                "id": "malicious",
                "title": "Malicious",
                "current_value": current_counts["malicious"],
                "previous_value": previous_counts["malicious"],
                "change_percent": malicious_change,
            },
            {
                "id": "detection_rate",
                "title": "Detection Rate",
                "current_value": round(current_detection_rate, 1),
                "previous_value": round(previous_detection_rate, 1),
                "change_percent": detection_rate_change,
            },
        ],
        "verdict_distribution": verdict_distribution,
    }

    return kpi_stats
