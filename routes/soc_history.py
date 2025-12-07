# routes/soc_history.py

from flask import render_template
from .soc_routes import soc_bp


@soc_bp.route("/soc/history")
def soc_history():
    return render_template("soc_history.html")
