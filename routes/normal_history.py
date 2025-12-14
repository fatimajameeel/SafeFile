# routes/user/history.py

from flask import render_template
from .normal_routes import normal_bp


@normal_bp.route("/normal/history")
def normal_history():

    return render_template("normal_history.html")
