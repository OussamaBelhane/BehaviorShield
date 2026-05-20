r"""
agent/quarantine.py
-------------------
Quarantine manager for BehaviorShield.
Moves suspicious files to C:\BehaviorShield\Quarantine\ with metadata
stored in the SQLite database.
"""

import logging
import pathlib
import shutil
import uuid
import os
from datetime import datetime, timezone

from agent.signature_check import get_file_sha256, get_signature_status
from agent.config import QUARANTINE_DIR, DB_PATH, CRITICAL_PROCESSES
from database.db import get_connection

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def quarantine_file(
    src_path: str | pathlib.Path,
    process_pid: int = 0,
    process_image: str = "",
    reason: str = "",
    db_path=None,
) -> int | None:
    """
    Move a file to the quarantine directory.
    
    Safety Rules:
    - Refuses to quarantine if the file is a CRITICAL_PROCESS name AND is located
      within the Windows directory AND has a valid 'TRUSTED' digital signature.
    - Allows quarantine if a critical name is found outside Windows folders
      (e.g. C:\Temp\svchost.exe) or if it is unsigned/maliciously replaced.

    Returns the quarantine DB row ID on success, None on failure.
    """
    src = pathlib.Path(src_path)
    if not src.exists():
        logger.warning("Quarantine: file not found: %s", src)
        return None

    # Safety check: Never quarantine critical system files if they are in the
    # correct Windows directory AND have a valid digital signature.
    # We allow quarantining them if they appear elsewhere or are unsigned.
    src_str = str(src).lower()
    if src.name.lower() in CRITICAL_PROCESSES:
        win_dir = os.environ.get('SystemRoot', 'C:\\Windows').lower()
        if src_str.startswith(win_dir):
            if get_signature_status(src) == "TRUSTED":
                logger.critical(
                    "REFUSING TO QUARANTINE CRITICAL SYSTEM FILE (Signed & in Windows folder): %s",
                    src
                )
                return None
            else:
                logger.warning(
                    "Allowing quarantine of critical name %s in Windows folder because it is UNSIGNED",
                    src.name
                )
        else:
            logger.warning(
                "Allowing quarantine of critical name %s because it is OUTSIDE Windows folder: %s",
                src.name, src.parent
            )

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    # Each quarantined file lives in its own UUID folder to avoid name clashes
    entry_id = str(uuid.uuid4())
    dest_dir  = QUARANTINE_DIR / entry_id
    dest_dir.mkdir(parents=True)
    dest = dest_dir / src.name

    sha = get_file_sha256(str(src))

    try:
        shutil.move(str(src), str(dest))
        logger.info("Quarantined: %s -> %s", src, dest)
    except OSError as exc:
        logger.error("Failed to quarantine %s: %s", src, exc)
        return None

    conn = get_connection(db_path or DB_PATH)
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO quarantine
                    (original_path, quarantine_path, process_pid, process_image,
                     file_sha256, status, reason, quarantined_at)
                VALUES (?, ?, ?, ?, ?, 'QUARANTINED', ?, ?)
                """,
                (str(src), str(dest), process_pid, process_image, sha, reason, _now_iso()),
            )
            row_id = cursor.lastrowid
        return row_id
    finally:
        conn.close()


def restore_file(quarantine_id: int, db_path=None) -> bool:
    """
    Restore a quarantined file to its original path.
    The caller is responsible for also whitelisting the file if desired.
    """
    conn = get_connection(db_path or DB_PATH)
    try:
        row = conn.execute(
            "SELECT * FROM quarantine WHERE id = ?", (quarantine_id,)
        ).fetchone()
        if not row:
            logger.warning("Quarantine: ID %d not found", quarantine_id)
            return False

        if row["status"] != "QUARANTINED":
            logger.warning("Quarantine: ID %d already %s", quarantine_id, row["status"])
            return False

        src  = pathlib.Path(row["quarantine_path"])
        dest = pathlib.Path(row["original_path"])

        if not src.exists():
            logger.error("Quarantine: file missing at %s", src)
            return False

        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))

        with conn:
            conn.execute(
                "UPDATE quarantine SET status='RESTORED', resolved_at=? WHERE id=?",
                (_now_iso(), quarantine_id),
            )

        logger.info("Restored quarantine ID %d: %s -> %s", quarantine_id, src, dest)
        return True
    except OSError as exc:
        logger.error("Restore failed for ID %d: %s", quarantine_id, exc)
        return False
    finally:
        conn.close()


def delete_permanently(quarantine_id: int, db_path=None) -> bool:
    """Permanently delete a quarantined file and remove its DB record."""
    conn = get_connection(db_path or DB_PATH)
    try:
        row = conn.execute(
            "SELECT * FROM quarantine WHERE id = ?", (quarantine_id,)
        ).fetchone()
        if not row:
            return False

        q_path = pathlib.Path(row["quarantine_path"])
        try:
            if q_path.exists():
                q_path.unlink()
            # Also remove the UUID directory if empty
            if q_path.parent.exists():
                shutil.rmtree(str(q_path.parent), ignore_errors=True)
        except OSError as exc:
            logger.warning("Could not delete file %s: %s", q_path, exc)

        with conn:
            conn.execute(
                "UPDATE quarantine SET status='DELETED', resolved_at=? WHERE id=?",
                (_now_iso(), quarantine_id),
            )
        logger.info("Permanently deleted quarantine ID %d", quarantine_id)
        return True
    finally:
        conn.close()


def get_quarantine_list(db_path=None) -> list[dict]:
    """Return all quarantine entries sorted by newest first."""
    conn = get_connection(db_path or DB_PATH)
    try:
        rows = conn.execute(
            """
            SELECT id, original_path, quarantine_path, process_pid,
                   process_image, file_sha256, status, quarantined_at, resolved_at
            FROM quarantine
            ORDER BY quarantined_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
