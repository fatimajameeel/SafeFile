# app.py

from flask import Flask
import os
from db import close_db
from routes.auth_routes import auth_bp
from routes.soc_routes import soc_bp


def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Secret key for sessions
    app.secret_key = "homa"

    # Upload folder configuration (used by SOC routes)
    upload_folder = os.path.join(os.path.dirname(__file__), "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = upload_folder

    # DB teardown
    app.teardown_appcontext(close_db)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(soc_bp)

    # VirusTotal API
    app.config["VT_API_KEY"] = os.getenv("VT_API_KEY")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
