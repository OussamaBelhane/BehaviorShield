"""backend/routes/status.py - GET /api/status"""

from flask import Blueprint, jsonify, current_app, request
from database.db import get_connection, is_learning_mode
from agent.config import LEARNING_MODE_DAYS
from datetime import datetime, timezone
import time
import os
import psutil

status_bp = Blueprint("status", __name__)


@status_bp.route("/status")
def get_status():
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        active_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE dismissed=0"
        ).fetchone()[0]
        killed_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE alert_type IN ('KILL', 'INSTANT_KILL')"
        ).fetchone()[0]
        quarantine_count = conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE status='QUARANTINED'"
        ).fetchone()[0]
        processes_count = conn.execute(
            """
            SELECT COUNT(DISTINCT p.pid) 
            FROM processes p
            LEFT JOIN whitelist w ON (
                (p.image_path IS NOT NULL AND LOWER(p.image_path) = LOWER(w.exe_path)) OR 
                (p.image_sha256 IS NOT NULL AND LOWER(p.image_sha256) = LOWER(w.exe_sha256))
            )
            WHERE w.id IS NULL
            """
        ).fetchone()[0]

        install_row = conn.execute(
            "SELECT value FROM system_meta WHERE key='install_time'"
        ).fetchone()
        install_time = install_row["value"] if install_row else None

        try:
            cfg = conn.execute("SELECT value FROM system_meta WHERE key='learning_days'").fetchone()
            active_days = int(cfg["value"]) if cfg else LEARNING_MODE_DAYS
        except Exception:
            active_days = LEARNING_MODE_DAYS

        learning = is_learning_mode(db, active_days)
        days_remaining = 0
        if learning and install_time and active_days > 0:
            try:
                elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(install_time)).days
                days_remaining = max(0, active_days - elapsed)
            except Exception:
                days_remaining = active_days

        uptime_seconds = int(time.time() - psutil.Process(os.getpid()).create_time())

        # Check whitelist setting
        wl_row = conn.execute("SELECT value FROM system_meta WHERE key='whitelist_enabled'").fetchone()
        whitelist_enabled = wl_row["value"].lower() == "true" if wl_row else True

        # Check pause setting
        pause_row = conn.execute("SELECT value FROM system_meta WHERE key='paused_until'").fetchone()
        paused_until = float(pause_row["value"]) if pause_row else 0.0
        is_paused = paused_until > time.time()

        # Get max current process score for the Gauge (ignore whitelisted)
        max_score = conn.execute("SELECT MAX(score) FROM processes WHERE status != 'WHITELISTED'").fetchone()[0] or 0

        # Get latest un-dismissed kill alert for the banner
        latest_kill_row = conn.execute(
            """
            SELECT id, pid, image_path as process_name, score, message, timestamp
            FROM alerts
            WHERE dismissed = 0 AND pid >= 0 AND alert_type IN ('KILL', 'INSTANT_KILL')
            ORDER BY timestamp DESC
            LIMIT 1
            """
        ).fetchone()
        latest_kill = dict(latest_kill_row) if latest_kill_row else None
        if latest_kill:
            # Clean up process name
            import pathlib as _pl
            p = latest_kill["process_name"]
            latest_kill["process_name"] = _pl.Path(p).name if p else "Unknown Process"

        return jsonify({
            "learning_mode":    learning,
            "max_score":        max_score,
            "days_remaining":   days_remaining,
            "total_events":     total_events,
            "active_alerts":    active_alerts,
            "killed_processes": killed_count,
            "quarantine_count": quarantine_count,
            "processes_count":  processes_count,
            "protected_since":  install_time,
            "uptime":           uptime_seconds,
            "active_days":      active_days,
            "whitelist_enabled": whitelist_enabled,
            "is_paused":        is_paused,
            "paused_until":     paused_until if is_paused else 0,
            "latest_kill":      latest_kill
        })
    finally:
        conn.close()


@status_bp.route("/scan/progress")
def get_scan_progress():
    """[IMPROVEMENT 7] Return current startup scan progress from DB."""
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        import json
        row = conn.execute("SELECT value FROM system_meta WHERE key='scan_progress'").fetchone()
        if row:
            return jsonify(json.loads(row["value"]))
        return jsonify({"scanned": 0, "total": 0, "finished": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@status_bp.route("/processes")
def list_processes():
    """Return a list of tracked processes, optionally filtered by whitelist."""
    db = current_app.config["DB_PATH"]
    include_whitelisted = request.args.get("include_whitelisted", "false").lower() == "true"
    
    conn = get_connection(db)
    try:
        whitelist_clause = ""
        if not include_whitelisted:
            whitelist_clause = "WHERE w.id IS NULL"
            
        rows = conn.execute(
            f"""
            SELECT p.id, p.pid, p.image_path, p.image_sha256, p.cmd_line,
                   p.parent_pid, p.parent_image, p.signature_status, 
                   p.hash_verdict, p.score, p.status, p.first_seen, p.last_updated
            FROM processes p
            LEFT JOIN whitelist w ON (
                (p.image_path IS NOT NULL AND LOWER(p.image_path) = LOWER(w.exe_path)) OR 
                (p.image_sha256 IS NOT NULL AND LOWER(p.image_sha256) = LOWER(w.exe_sha256)) OR
                (p.cmd_line IS NOT NULL AND w.cmd_line_pattern IS NOT NULL AND p.cmd_line LIKE w.cmd_line_pattern)
            )
            {whitelist_clause}
            ORDER BY p.last_updated DESC
            """
        ).fetchall()
        
        processes = [dict(r) for r in rows]
        return jsonify({"processes": processes})
    finally:
        conn.close()
