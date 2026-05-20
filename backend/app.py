"""
backend/app.py
--------------
Flask application factory for BehaviorShield.
"""

import pathlib
from flask import Flask, send_from_directory, request, abort, jsonify
from flask_cors import CORS
import logging
import time
from agent.config import API_TOKEN_PATH

from backend.routes.events    import events_bp
from backend.routes.alerts    import alerts_bp
from backend.routes.quarantine import quarantine_bp
from backend.routes.whitelist import whitelist_bp
from backend.routes.reports   import reports_bp
from backend.routes.status    import status_bp
from backend.routes.pause     import pause_bp
from backend.routes.hash_results import hash_results_bp
from backend.routes.settings import settings_bp
from backend.routes.control  import control_bp


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)

    # ── API Authentication ──────────────────────────────────────────
    # Cache the token from disk on startup
    try:
        _expected_token = API_TOKEN_PATH.read_text(encoding="utf-8").strip()
    except Exception as e:
        logging.error("Failed to read API token from %s: %s", API_TOKEN_PATH, e)
        _expected_token = None

    @app.before_request
    def check_auth():
        # Exempt authentication endpoint and static file serving (React)
        if request.path == "/api/auth/token" or not request.path.startswith("/api/"):
            return

        token = request.headers.get("X-API-Token")
        if not _expected_token or token != _expected_token:
            logging.warning("API Authentication failure from %s: %s (Token: %s)", 
                            request.remote_addr, request.path, "present" if token else "missing")
            abort(403, description="Invalid or missing API token")

    @app.route("/api/auth/token", methods=["GET"])
    def get_token():
        """Allow local dashboard to fetch the token."""
        # Only allow from localhost
        if request.remote_addr not in ("127.0.0.1", "::1"):
            logging.warning("Token request rejected: Invalid remote addr %s", request.remote_addr)
            abort(403)
        
        # Check Referer to ensure it's from our dashboard/dev server
        referer = request.headers.get("Referer", "")
        # Allow both localhost and 127.0.0.1
        if not (referer.startswith("http://localhost") or referer.startswith("http://127.0.0.1")):
            logging.warning("Token request rejected: Invalid Referer %s", referer)
            abort(403)

        logging.info("Token successfully requested by %s (Referer: %s)", request.remote_addr, referer)
        return jsonify({"token": _expected_token})

    # Allow React dev server (port 5173) during development
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Pass the DB path via app config so blueprints can share it
    app.config["DB_PATH"] = db_path or "C:/BehaviorShield/data/behaviorshield.db"

    from database.db import init_db
    init_db(app.config["DB_PATH"])

    # Register all blueprints
    app.register_blueprint(events_bp,    url_prefix="/api")
    app.register_blueprint(alerts_bp,    url_prefix="/api")
    app.register_blueprint(quarantine_bp, url_prefix="/api")
    app.register_blueprint(whitelist_bp,  url_prefix="/api")
    app.register_blueprint(reports_bp,    url_prefix="/api")
    app.register_blueprint(status_bp,     url_prefix="/api")
    app.register_blueprint(pause_bp,      url_prefix="/api")
    app.register_blueprint(hash_results_bp, url_prefix="/api")
    app.register_blueprint(settings_bp,   url_prefix="/api")
    app.register_blueprint(control_bp,    url_prefix="/api")

    # -- Serve React build in production --------------------------
    react_build = pathlib.Path(__file__).parent.parent / "frontend" / "dist"

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_react(path):
        if path and (react_build / path).exists():
            return send_from_directory(str(react_build), path)
        return send_from_directory(str(react_build), "index.html")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
