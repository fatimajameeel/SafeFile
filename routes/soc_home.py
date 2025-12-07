# routes/soc_home.py

from flask import render_template
from .soc_routes import soc_bp


@soc_bp.route("/soc/home")
def soc_home():
    return render_template("soc_home.html")
