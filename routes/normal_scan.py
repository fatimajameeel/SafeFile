# routes/user/scan.py

from flask import render_template
from .normal_routes import normal_bp


@normal_bp.route("/normal/scan")
def normal_scan():

    return render_template("normal_scan.html")
