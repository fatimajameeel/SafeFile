# routes/normal_scan.py

from flask import render_template
from .soc_routes import soc_bp


@soc_bp.route("/normal/normal")
def normal_scan():
    return render_template("normal_scan.html")
