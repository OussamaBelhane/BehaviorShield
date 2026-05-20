"""backend/routes/events.py — GET /api/events, GET /api/events/<id>"""

from flask import Blueprint, request, jsonify, current_app
from database.db import get_connection
import pathlib
import psutil
import logging
from agent.process_killer import kill_process

events_bp = Blueprint("events", __name__)
logger = logging.getLogger(__name__)

# ── Backend-side psutil fallback for process names ────────────────
# When the agent wrote a PID but didn't resolve the name, we try here.
_psutil_cache: dict[int, str] = {}   # pid → name  (in-memory cache)

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


def _resolve_name_backend(pid: int) -> str:
    """
    Live psutil lookup for a PID → process name.
    Used as a safety net when the agent didn't store process_name.
    """
    if pid == 0:
        return "[System Watchdog]"
    if not _PSUTIL or not pid or pid < 0:
        return ""
    if pid in _psutil_cache:
        return _psutil_cache[pid]
    try:
        name = psutil.Process(pid).name()
        _psutil_cache[pid] = name
        return name
    except Exception:
        _psutil_cache[pid] = ""
        return ""


def _basename(path: str) -> str:
    if not path:
        return ""
    return pathlib.Path(path).name or path


@events_bp.route("/events")
def list_events():
    db   = current_app.config["DB_PATH"]
    page = max(1, int(request.args.get("page", 1)))
    per  = min(200, int(request.args.get("per_page", 50)))
    pid      = request.args.get("pid")
    sev      = request.args.get("severity")
    since_id = request.args.get("since_id")
    include_whitelisted = request.args.get("include_whitelisted", "false").lower() == "true"

    where  = []
    params = []
    if pid:
        where.append("e.pid = ?"); params.append(int(pid))
    if sev:
        where.append("e.severity = ?"); params.append(sev.upper())
    if since_id:
        where.append("e.id > ?"); params.append(int(since_id))

    # Whitelist filtering (Skip if include_whitelisted=true)
    # Special case: PID 0 (Watchdog) is never whitelisted/filtered
    whitelist_clause = ""
    if not include_whitelisted:
        whitelist_clause = "AND (w.id IS NULL OR e.pid = 0)"

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    offset    = (page - 1) * per

    conn = get_connection(db)
    try:
        # Get total count BEFORE whitelist filtering for logging
        total_unfiltered = conn.execute(
            f"SELECT COUNT(*) FROM events e {where_sql}", params
        ).fetchone()[0]

        # Use ORDER BY e.id DESC for much faster primary key-based ordering
        # We join whitelist on path OR sha256 to ensure we catch whitelisted processes
        rows = conn.execute(
            f"""
            SELECT e.id, e.pid, e.event_type, e.source_path, e.dest_path,
                   e.extension, e.score_delta, e.severity, e.timestamp,
                   e.process_name as stored_process_name,
                   e.source,
                   p.image_path, p.score as process_score, p.status as process_status
            FROM events e
            LEFT JOIN processes p ON p.pid = e.pid
            LEFT JOIN whitelist w ON (
                (p.image_path IS NOT NULL AND LOWER(p.image_path) = LOWER(w.exe_path)) OR 
                (p.image_sha256 IS NOT NULL AND LOWER(p.image_sha256) = LOWER(w.exe_sha256)) OR
                (p.cmd_line IS NOT NULL AND w.cmd_line_pattern IS NOT NULL AND p.cmd_line LIKE w.cmd_line_pattern)
            )
            {where_sql} {"AND" if where_sql else "WHERE"} 1=1 {whitelist_clause}
            ORDER BY e.id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, per, offset],
        ).fetchall()

        # Get total count AFTER whitelist filtering for pagination
        total = conn.execute(
            f"""
            SELECT COUNT(*) FROM events e 
            LEFT JOIN processes p ON p.pid = e.pid
            LEFT JOIN whitelist w ON (
                (p.image_path IS NOT NULL AND LOWER(p.image_path) = LOWER(w.exe_path)) OR 
                (p.image_sha256 IS NOT NULL AND LOWER(p.image_sha256) = LOWER(w.exe_sha256)) OR
                (p.cmd_line IS NOT NULL AND w.cmd_line_pattern IS NOT NULL AND p.cmd_line LIKE w.cmd_line_pattern)
            )
            {where_sql} {"AND" if where_sql else "WHERE"} 1=1 {whitelist_clause}
            """, 
            params
        ).fetchone()[0]

        hidden_count = total_unfiltered - total
        if hidden_count > 0:
            logger.debug("Filtered %d whitelisted events from response", hidden_count)
    finally:
        conn.close()

    events = []
    for r in rows:
        d = dict(r)
        # Resolution priority:
        #   1. process_name stored at write-time by agent (most accurate)
        #   2. image_path from processes table JOIN (Sysmon PROCESS_CREATE)
        #   3. Live psutil lookup by PID (backend safety net)
        stored   = d.pop("stored_process_name", "") or ""
        img_path = d.get("image_path", "") or ""
        joined   = _basename(img_path)
        live     = _resolve_name_backend(d.get("pid", 0)) if not stored and not joined else ""
        
        d["process_name"] = stored or joined or live or "Unknown Process"
        d["process_image"] = img_path or (stored if stored and ".exe" in stored.lower() else "") or ""
        d["process_status"] = d.get("process_status") or "ACTIVE"
        events.append(d)

    return jsonify({
        "events": events,
        "page":  page, "per_page": per, "total": total,
    })


@events_bp.route("/events/<int:event_id>")
def get_event(event_id: int):
    db = current_app.config["DB_PATH"]
    conn = get_connection(db)
    try:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(row))


@events_bp.route("/processes/kill", methods=["POST"])
def manual_kill_process():
    """
    Manually kill a process by PID.
    Checks if process exists first and handles NoSuchProcess gracefully.
    """
    db = current_app.config["DB_PATH"]
    data = request.get_json(silent=True) or {}
    pid = data.get("pid")

    if not pid:
        return jsonify({"error": "PID required"}), 400

    try:
        pid = int(pid)
    except ValueError:
        return jsonify({"error": "Invalid PID format"}), 400

    # 1. Check if PID exists
    if not psutil.pid_exists(pid):
        return jsonify({"status": "already_dead", "message": f"PID {pid} no longer exists."})

    # 2. Attempt kill
    try:
        # We don't have all the metadata here, but kill_process handles minimal info
        # It will also quarantine files written by this process if it finds them in the DB.
        success = kill_process(pid=pid, db_path=db, reason="Manual termination via dashboard")
        
        if success:
            return jsonify({"status": "killed", "pid": pid})
        else:
            return jsonify({"error": "Kill failed (insufficient permissions or process already exiting)"}), 500

    except psutil.NoSuchProcess:
        return jsonify({"status": "already_dead", "message": f"PID {pid} disappeared during kill attempt."})
    except psutil.AccessDenied:
        return jsonify({"error": "Access denied. Backend may need higher privileges."}), 403
    except Exception as e:
        return jsonify({"error": f"Internal error during kill: {str(e)}"}), 500
