"""
backend/routes/control.py
--------------------------
POST /api/reload  -- Signal the running agent to restart itself.
POST /api/stop    -- Alias for an indefinite pause (1 year).

The agent's control-check thread watches the 'reload_requested' DB flag
and calls _restart_requested.set() + _shutdown.set() when it sees it.
"""

import time
from flask import Blueprint, jsonify, current_app
from database.db import get_connection

control_bp = Blueprint("control", __name__)

_STOP_DURATION = 365 * 24 * 3600  # 1 year in seconds


@control_bp.route("/reload", methods=["POST"])
def reload_agent():
    """
    Set the 'reload_requested' flag in system_meta.
    The agent's control-check loop detects this and performs a clean restart.
    """
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_meta (key, value) VALUES ('reload_requested', '1')"
            )
        return jsonify({"status": "reload_requested"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@control_bp.route("/stop", methods=["POST"])
def stop_agent():
    """
    Pause protection indefinitely (1 year) — functionally a 'Stop'.
    The tray shows the Resume button when paused_until > now.
    """
    db = current_app.config["DB_PATH"]
    paused_until = time.time() + _STOP_DURATION
    conn = get_connection(db)
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_meta (key, value) VALUES ('paused_until', ?)",
                (str(paused_until),)
            )
        return jsonify({"status": "stopped", "paused_until": paused_until})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
