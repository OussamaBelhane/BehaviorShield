"""backend/routes/settings.py - GET/POST/DELETE /api/settings/folders"""

from flask import Blueprint, request, jsonify, current_app
from database.db import get_connection
from datetime import datetime, timezone
import pathlib
import sys
import subprocess

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/settings/folders", methods=["GET"])
def list_protected_folders():
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        rows = conn.execute("SELECT id, path, added_at FROM protected_folders ORDER BY id DESC").fetchall()
        folders = [dict(r) for r in rows]
        return jsonify({"folders": folders})
    finally:
        conn.close()

@settings_bp.route("/settings/folders", methods=["POST"])
def add_protected_folder():
    db = current_app.config["DB_PATH"]
    data = request.get_json(silent=True) or {}
    path = data.get("path", "").strip()
    
    if not path:
        return jsonify({"error": "Path is required"}), 400
    
    conn = get_connection(db)
    try:
        with conn:
            conn.execute(
                "INSERT INTO protected_folders (path, added_at) VALUES (?, ?)",
                (path, datetime.now(timezone.utc).isoformat())
            )
        return jsonify({"status": "added"})
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return jsonify({"error": "Folder is already protected"}), 409
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@settings_bp.route("/settings/folders/<int:fid>", methods=["DELETE"])
def remove_protected_folder(fid: int):
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        with conn:
            conn.execute("DELETE FROM protected_folders WHERE id = ?", (fid,))
        return jsonify({"status": "removed"})
    finally:
        conn.close()

@settings_bp.route("/browse-folder", methods=["GET"])
def browse_folder():
    """Open a native folder dialog on the host."""
    try:
        # Use tkinter to open a native directory picker
        cmd = [
            sys.executable,
            "-c",
            "import tkinter.filedialog; import tkinter; root=tkinter.Tk(); root.withdraw(); root.wm_attributes('-topmost', 1); print(tkinter.filedialog.askdirectory(title='Select Folder to Protect'))"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        path = res.stdout.strip()
        return jsonify({"path": path}) # path is empty string if user cancels
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@settings_bp.route("/settings/whitelist-toggle", methods=["GET"])
def get_whitelist_toggle():
    from database.db import is_whitelist_enabled
    db = current_app.config["DB_PATH"]
    return jsonify({"enabled": is_whitelist_enabled(db)})

@settings_bp.route("/settings/whitelist-toggle", methods=["POST"])
def set_whitelist_toggle():
    db = current_app.config["DB_PATH"]
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", True)
    
    conn = get_connection(db)
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_meta (key, value) VALUES ('whitelist_enabled', ?)",
                (str(enabled).lower(),)
            )
        return jsonify({"status": "ok", "enabled": enabled})
    finally:
        conn.close()

@settings_bp.route("/settings/learning", methods=["POST"])
def update_learning_mode():
    db_path = current_app.config["DB_PATH"]
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", False)
    days = int(data.get("days", 7)) if enabled else 0

    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_meta (key, value) VALUES ('learning_days', ?)",
                (str(days),)
            )
            if enabled:
                # Reset install time so countdown starts afresh
                conn.execute(
                    "INSERT OR REPLACE INTO system_meta (key, value) VALUES ('install_time', ?)",
                    (datetime.now(timezone.utc).isoformat(),)
                )
        return jsonify({"status": "ok", "learning_mode": enabled, "days": days})
    finally:
        conn.close()
