"""backend/routes/quarantine.py - GET/POST /api/quarantine"""

from flask import Blueprint, request, jsonify, current_app
from database.db import get_connection
from agent.quarantine import restore_file, delete_permanently, get_quarantine_list
from agent.whitelist import add_to_whitelist

quarantine_bp = Blueprint("quarantine", __name__)


@quarantine_bp.route("/quarantine")
def list_quarantine():
    db = current_app.config["DB_PATH"]
    return jsonify({"quarantine": get_quarantine_list(db)})


@quarantine_bp.route("/quarantine/<int:qid>/restore", methods=["POST"])
def restore(qid: int):
    db       = current_app.config["DB_PATH"]
    data     = request.get_json(silent=True) or {}
    whitelist = data.get("whitelist", False)

    conn = get_connection(db)
    try:
        row = conn.execute(
            "SELECT original_path FROM quarantine WHERE id=?", (qid,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "Not found"}), 404

    ok = restore_file(qid, db)
    if not ok:
        return jsonify({"error": "Restore failed"}), 500

    if whitelist and row["original_path"]:
        conn = get_connection(db)
        try:
            # Also find the hash from the quarantine entry to whitelist it
            q_row = conn.execute("SELECT file_sha256 FROM quarantine WHERE id=?", (qid,)).fetchone()
            if q_row and q_row["file_sha256"]:
                add_to_whitelist(
                    row["original_path"], 
                    sha256=q_row["file_sha256"],
                    reason="User restored and whitelisted from quarantine", 
                    db_path=db
                )
        finally:
            conn.close()

    return jsonify({"status": "restored", "whitelisted": whitelist})


@quarantine_bp.route("/quarantine/<int:qid>/delete", methods=["POST"])
def delete(qid: int):
    db = current_app.config["DB_PATH"]
    ok = delete_permanently(qid, db)
    if not ok:
        return jsonify({"error": "Delete failed"}), 500
    return jsonify({"status": "deleted"})


@quarantine_bp.route("/quarantine/<int:qid>/inspect")
def inspect(qid: int):
    """Return detailed metadata for a quarantined file."""
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        # 1. Get the quarantine entry
        q_row = conn.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
        if not q_row:
            return jsonify({"error": "Not found"}), 404
        
        entry = dict(q_row)
        sha = entry["file_sha256"]
        pid = entry["process_pid"]

        # 2. Get hash scan result from cache
        h_row = conn.execute(
            "SELECT result, source, vt_score FROM hash_cache WHERE sha256=?", (sha,)
        ).fetchone()
        entry["hash_info"] = dict(h_row) if h_row else None

        # 3. Get behavior rules triggered by this PID/process
        # We look for all events that contributed to the score
        events = conn.execute(
            """
            SELECT event_type, source_path, dest_path, timestamp
            FROM events
            WHERE pid = ? AND (dest_path = ? OR source_path = ?)
            ORDER BY timestamp DESC
            """,
            (pid, entry["original_path"], entry["original_path"])
        ).fetchall()
        entry["triggered_events"] = [dict(e) for e in events]

        return jsonify(entry)
    finally:
        conn.close()
