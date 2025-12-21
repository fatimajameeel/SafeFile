# routes/auth_routes.py

from flask import Blueprint, render_template, request, redirect, session, url_for
from werkzeug.security import check_password_hash
from db import get_db

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    # renders landing page
    return render_template("login.html")


@auth_bp.route("/login", methods=["POST"])
def login():
    db = get_db()

    # Read data sent from the login form
    username = request.form.get("username")
    password = request.form.get("password")

    # Look up the user by the entered username
    user = db.execute(
        "SELECT * FROM user WHERE username = ?", (username,)
    ).fetchone()

    if user is None:
        return render_template("login.html",
                               username_error="User not found")

    # check password using hash
    if not check_password_hash(user["password_hash"], password):
        return render_template("login.html",
                               password_error="Incorrect password",
                               entered_username=username)

    # Save info into session
    session["user_id"] = user["user_id"]
    session["role_id"] = user["role_id"]
    session["username"] = user["username"]

    # Redirect based on role
    if user["role_id"] == 1:
        # blueprint "soc", function "normal_scan"
        return redirect(url_for("normal.normal_landing"))
    elif user["role_id"] == 2:
        # blueprint "soc", function "soc_home"
        return redirect(url_for("soc.soc_home"))
    else:
        return redirect(url_for("auth.index"))


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.index"))
