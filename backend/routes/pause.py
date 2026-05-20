"""backend/routes/pause.py - POST /api/pause, POST /api/resume, GET /api/pause"""
import time
from flask import Blueprint, request, jsonify, current_app
from database.db import get_connection

pause_bp = Blueprint("pause", __name__)


@pause_bp.route("/pause", methods=["GET"])
def pause_status():
    """Return current pause state."""
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        row = conn.execute("SELECT value FROM system_meta WHERE key='paused_until'").fetchone()
        paused_until = float(row["value"]) if row else 0.0
        
        now    = time.time()
        paused = paused_until > now
        return jsonify({
            "paused":        paused,
            "paused_until":  paused_until if paused else None,
            "seconds_left":  max(0, int(paused_until - now)) if paused else 0,
        })
    finally:
        conn.close()


@pause_bp.route("/pause", methods=["POST"])
def pause_protection():
    """Pause protection for N seconds (default 1800)."""
    db = current_app.config["DB_PATH"]
    data     = request.get_json(silent=True) or {}
    duration = int(data.get("duration", 1800))
    duration = max(1, min(7200, duration))   # clamp 1s-2h
    
    paused_until = time.time() + duration
    
    conn = get_connection(db)
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_meta (key, value) VALUES ('paused_until', ?)",
                (str(paused_until),)
            )
    finally:
        conn.close()
        
    return jsonify({"status": "paused", "duration": duration, "paused_until": paused_until})


@pause_bp.route("/resume", methods=["POST"])
def resume_protection():
    """Resume protection immediately."""
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        with conn:
            conn.execute("DELETE FROM system_meta WHERE key='paused_until'")
    finally:
        conn.close()
    return jsonify({"status": "resumed"})
