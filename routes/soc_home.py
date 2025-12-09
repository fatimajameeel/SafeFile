# routes/soc_home.py

from flask import render_template
from .soc_routes import soc_bp
from DB_helpers.dashboard_kpis import get_dashboard_kpi_stats
from DB_helpers.week_chart import get_activity_last7_days
from DB_helpers.malware_types import get_malware_type_breakdown
from DB_helpers.top_yara_rules import get_top_yara_rules
from DB_helpers.daily_upload import get_daily_upload


@soc_bp.route("/soc/home")
def soc_home():
    """
    Render the SOC dashboard home page.

    This route gathers:
    - KPI stats for the top cards (kpi_stats)
    - Weekly threat activity for the line chart (week_chart)
    - Malware types distribution for the pie chart (malware_type_data)
    - Top YARA rules hit counts for the bar chart (top_yara)
    """

    # 1) KPI cards
    kpi_stats = get_dashboard_kpi_stats()

    # 2) Get chart data: for each of the last 7 days number of total scans and alerts
    week_chart = get_activity_last7_days()

    # 3) Malware type (pie chart)
    malware_type_data = get_malware_type_breakdown()

    # 4) Top YARA rules (all time, top 5 by default)
    top_yara = get_top_yara_rules(limit=5)

    # 5) Dily upload volume
    daily_volume = get_daily_upload()

    # Render the HTML template so we pass data
    return render_template("soc_home.html",
                           kpi_stats=kpi_stats,
                           week_chart=week_chart,
                           malware_type_data=malware_type_data,
                           top_yara=top_yara,
                           daily_volume=daily_volume,
                           )
