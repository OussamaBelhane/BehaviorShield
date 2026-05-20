"""backend/routes/alerts.py - GET /api/alerts, POST /api/alerts/<id>/dismiss"""

from flask import Blueprint, jsonify, current_app
from database.db import get_connection
from datetime import datetime, timezone

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/alerts")
def list_alerts():
    from flask import request
    db = current_app.config["DB_PATH"]
    include_dismissed = request.args.get("include_dismissed", "false").lower() == "true"
    
    where_clause = "WHERE a.pid >= 0"
    if not include_dismissed:
        where_clause += " AND a.dismissed = 0"

    conn = get_connection(db)
    try:
        rows = conn.execute(
            f"""
            SELECT a.id, a.pid, a.image_path, a.alert_type, a.score, a.message, a.dismissed, a.timestamp
            FROM alerts a
            LEFT JOIN processes p ON p.pid = a.pid
            LEFT JOIN whitelist w ON (
                (p.image_path IS NOT NULL AND LOWER(p.image_path) = LOWER(w.exe_path)) OR 
                (p.image_sha256 IS NOT NULL AND LOWER(p.image_sha256) = LOWER(w.exe_sha256)) OR
                (p.cmd_line IS NOT NULL AND w.cmd_line_pattern IS NOT NULL AND p.cmd_line LIKE w.cmd_line_pattern)
            )
            {where_clause} AND w.id IS NULL
            ORDER BY a.timestamp DESC
            LIMIT 200
            """
        ).fetchall()
    finally:
        conn.close()

    alerts = []
    for r in rows:
        d = dict(r)
        # Normalise field names so the React frontend can use them directly
        # Frontend expects: process_name, sha256 - not image_path
        d["process_name"] = _basename(d.get("image_path", ""))
        alerts.append(d)

    return jsonify({"alerts": alerts})


@alerts_bp.route("/alerts/<int:alert_id>/dismiss", methods=["POST"])
def dismiss_alert(alert_id: int):
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        with conn:
            conn.execute(
                "UPDATE alerts SET dismissed=1 WHERE id=?", (alert_id,)
            )
    finally:
        conn.close()
    return jsonify({"status": "ok", "id": alert_id})


def _basename(path: str) -> str:
    """Extract just the filename from a full image path."""
    if not path:
        return "unknown"
    import pathlib as _pl
    return _pl.Path(path).name or path
