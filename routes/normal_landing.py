# routes/user/landing.py

from flask import render_template
from .normal_routes import normal_bp


@normal_bp.route("/normal/landing")
def normal_landing():

    return render_template("normal_landing.html")
