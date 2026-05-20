"""backend/routes/whitelist.py - GET/POST/DELETE /api/whitelist"""

from flask import Blueprint, request, jsonify, current_app
from agent.whitelist import (
    get_all_whitelist_entries, add_to_whitelist, remove_from_whitelist
)
import pathlib

whitelist_bp = Blueprint("whitelist", __name__)


def _basename(path: str) -> str:
    if not path:
        return ""
    return pathlib.Path(path).name or path


@whitelist_bp.route("/whitelist")
def list_whitelist():
    db = current_app.config["DB_PATH"]
    raw = get_all_whitelist_entries(db)

    # Normalise field names to match React frontend expectations
    entries = []
    for r in raw:
        entries.append({
            "id":           r["id"],
            "process_name": _basename(r.get("exe_path", "")),
            "sha256":       r.get("exe_sha256", ""),
            "added_by":     r.get("vendor", "") or "AGENT",
            "added_date":   r.get("added_at", ""),
            "exe_path":     r.get("exe_path", ""),
            "is_system":    bool(r.get("is_system", 0)),
        })
    return jsonify({"whitelist": entries})


@whitelist_bp.route("/whitelist", methods=["POST"])
def add_entry():
    db   = current_app.config["DB_PATH"]
    data = request.get_json(silent=True) or {}
    path = data.get("exe_path", "")
    if not path:
        return jsonify({"error": "exe_path required"}), 400

    from agent.config import NEVER_WHITELIST
    basename = pathlib.Path(path).name.lower()
    if basename in NEVER_WHITELIST:
        return jsonify({"error": f"Cannot whitelist {basename} because it is an interpreter that can run arbitrary code (e.g. ransomware scripts)."}), 403

    from agent.hash_scanner import get_sha256, scan
    from agent.signature_check import get_signature_status
    from database.db import get_connection

    # 1. Resolve to absolute path if possible
    if not pathlib.Path(path).is_absolute() or not pathlib.Path(path).exists():
        conn = get_connection(db)
        try:
            # Try to find the full path in the processes table by basename
            row = conn.execute(
                "SELECT image_path FROM processes WHERE image_path LIKE ? ORDER BY id DESC LIMIT 1",
                (f"%\\{path}",)
            ).fetchone()
            if row:
                path = row["image_path"]
            else:
                # Fallback: check if it's just the filename
                row = conn.execute(
                    "SELECT image_path FROM processes WHERE LOWER(image_path) LIKE ? ORDER BY id DESC LIMIT 1",
                    (f"%{path.lower()}",)
                ).fetchone()
                if row:
                    path = row["image_path"]
        finally:
            conn.close()

    # 2. Compute SHA256
    sha = get_sha256(path)
    if not sha:
        return jsonify({"error": f"File unreadable or does not exist: {path}"}), 400

    # 2. Check duplicate
    conn = get_connection(db)
    try:
        row = conn.execute("SELECT id FROM whitelist WHERE exe_sha256 = ?", (sha,)).fetchone()
        if row:
            return jsonify({"error": "File is already whitelisted (duplicate hash)"}), 409
    finally:
        conn.close()

    # 3. Hash scan
    sig = get_signature_status(path)
    result = scan(path, pid=0, mode="protection", signature=sig, parent_image="", db_path=db)

    # 4. Reject malware
    if result == "malware":
        return jsonify({"error": "This file is flagged as malware"}), 403

    # 5. Add to whitelist (clean/unknown)
    ok = add_to_whitelist(
        path,
        vendor="manual",
        reason="Manually added (User)",
        is_system=False,
        sha256=sha,
        db_path=db,
    )
    
    # Reset process scores and dismiss alerts for this executable
    conn = get_connection(db)
    try:
        with conn:
            # Update processes table
            conn.execute(
                "UPDATE processes SET score=0, status='WHITELISTED' WHERE image_path=? OR image_sha256=?",
                (path, sha)
            )
            # Dismiss alerts associated with this path
            conn.execute(
                "UPDATE alerts SET dismissed=1 WHERE image_path=?",
                (path,)
            )
            # Also reset vendor/system status if scan() auto-added it
            conn.execute(
                "UPDATE whitelist SET vendor='manual', reason='Manually added (User)', is_system=0 WHERE exe_sha256=?", 
                (sha,)
            )
    except Exception:
        pass
    finally:
        conn.close()

    if not ok:
        return jsonify({"error": "Failed to add to database"}), 500
        
    return jsonify({"status": "added"})

@whitelist_bp.route("/browse", methods=["GET"])
def browse_file():
    """Open a native file dialog on the host to get the absolute path securely."""
    import sys
    import subprocess
    try:
        cmd = [
            sys.executable,
            "-c",
            "import tkinter.filedialog; import tkinter; root=tkinter.Tk(); root.withdraw(); root.wm_attributes('-topmost', 1); print(tkinter.filedialog.askopenfilename(title='Select Program to Whitelist', filetypes=[('Executables', '*.exe')]))"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        path = res.stdout.strip()
        return jsonify({"path": path}) # path is empty string if user cancels
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@whitelist_bp.route("/whitelist/<int:wid>", methods=["DELETE"])
def remove_entry(wid: int):
    db = current_app.config["DB_PATH"]
    
    # Safety Check: Do not allow deleting system entries
    from database.db import get_connection
    conn = get_connection(db)
    try:
        row = conn.execute("SELECT is_system FROM whitelist WHERE id = ?", (wid,)).fetchone()
        if row and row["is_system"]:
            return jsonify({"error": "Cannot delete system-protected whitelist entries"}), 403
    finally:
        conn.close()

    remove_from_whitelist(wid, db)
    return jsonify({"status": "removed"})
