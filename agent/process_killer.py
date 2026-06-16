"""
agent/process_killer.py
-----------------------
Kill a suspicious process and quarantine all files it wrote.

Design:
  - Primary kill: psutil.Process.kill()
  - Fallback kill: taskkill /F /PID (only if psutil raises)
  - After kill: quarantine every file the process wrote (tracked via Sysmon)
  - Respects learning mode -- NEVER kills during first 7 days
"""

import logging
import subprocess
import pathlib
from datetime import datetime, timezone

import psutil

from agent.config import DB_PATH, CRITICAL_PROCESSES
from agent.quarantine import quarantine_file
from database.db import get_connection, is_learning_mode

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def kill_process(
    pid: int,
    image: str = "",
    score: int = 0,
    reason: str = "",
    written_files: list[str] | None = None,
    db_path=None,
) -> bool:
    """
    Kill a process and quarantine its written files.
    If PID is -1 (unknown), we try to resolve it via image name or highest-scoring process.
    """
    effective_db = db_path or DB_PATH

    # -- Learning mode guard --------------------------------------
    if is_learning_mode(effective_db):
        logger.warning(
            "[LEARNING MODE] Would kill PID %d (%s) score=%d -- skipping (learning mode active)",
            pid, image, score,
        )
        _log_alert(pid, image, score, reason, "LEARNING_MODE_BLOCKED", effective_db)
        return False

    # -- Resolve Unknown PID (-1) ----------------------------------
    if pid <= 0:
        if not image:
            # Look for the highest scoring process in the engine
            try:
                from agent.main import engine
                states = engine.get_all_states()
                active = [s for s in states if s["pid"] > 0 and s["score"] >= 30]
                if active:
                    best = max(active, key=lambda x: x["score"])
                    pid = best["pid"]
                    image = best["image"]
                    logger.info("kill_process: Resolved PID -1 to PID %d [%s] (highest score: %d)", pid, image, best["score"])
            except Exception as e:
                logger.error("kill_process: Resolution failed: %s", e)

    # -- Kill the process -----------------------------------------
    killed = _do_kill(pid, image)

    # -- Log the kill event ---------------------------------------
    _log_kill(pid, image, score, reason, killed, effective_db)

    # -- Quarantine written files ---------------------------------
    if killed:
        to_quarantine = list(written_files or [])
        
        # ALWAYS auto-discover files from events table to ensure we don't miss sysmon events
        # We append anything not already in the list
        conn = get_connection(effective_db)
        try:
            # Get all paths (source or dest) written/modified/created by this PID
            rows = conn.execute(
                "SELECT DISTINCT dest_path FROM events WHERE pid = ? AND dest_path != ''",
                (pid,)
            ).fetchall()
            for r in rows:
                if r["dest_path"] not in to_quarantine:
                    to_quarantine.append(r["dest_path"])
        except Exception as e:
            logger.error("Auto-discovery of files failed for PID %d: %s", pid, e)
        finally:
            conn.close()

        # Also quarantine the executable itself (if it's not a critical system process or python interpreter)
        if image:
            import os
            basename = pathlib.Path(image).name.lower()
            if (
                basename not in CRITICAL_PROCESSES 
                and basename not in ("python.exe", "pythonw.exe")
                and "c:\\windows\\" not in image.lower()
                and os.path.exists(image)
            ):
                if image not in to_quarantine:
                    logger.info("Adding threat binary itself to quarantine: %s", image)
                    to_quarantine.append(image)

        for file_path in to_quarantine:
            try:
                quarantine_file(
                    file_path, 
                    process_pid=pid, 
                    process_image=image, 
                    reason=reason,
                    db_path=effective_db
                )
            except Exception as exc:
                logger.error("Failed to quarantine %s: %s", file_path, exc)

    return killed


def _do_kill(pid: int, image: str = "") -> bool:
    """Attempt to kill a process -- psutil primary, taskkill /PID fallback, then /IM fallback."""
    
    # Special case: Kill by image name if PID is still unknown
    if pid <= 0 and image:
        logger.warning("PID unknown, trying kill-by-image fallback for: %s", image)
        return _kill_by_image(image)
    
    if pid <= 0:
        logger.error("_do_kill: Cannot kill, PID is unknown and no image name provided.")
        return False

    # Prevent self-kill
    import os
    if pid == os.getpid():
        logger.warning("_do_kill: Refusing to kill self.")
        return False

    # Prevent killing critical system processes
    if image:
        basename = pathlib.Path(image).name.lower()
        if basename in CRITICAL_PROCESSES:
            # ONLY protect if running from a legitimate system path
            img_lower = image.lower()
            is_system_path = "c:\\windows\\" in img_lower or "c:\\windows\\system32\\" in img_lower
            
            if is_system_path:
                # ALSO check signature -- if a system file is tampered with, it's not protected
                from agent.signature_check import get_signature_status
                sig_status = get_signature_status(image)
                if sig_status == "TRUSTED":
                    logger.critical("REFUSING TO KILL LEGITIMATE CRITICAL SYSTEM PROCESS: %s (PID %d)", basename, pid)
                    return False
                else:
                    logger.warning("Critical process name %s detected but signature is %s -- Proceeding with kill.", basename, sig_status)
            else:
                logger.warning("Critical process name %s detected in NON-SYSTEM path (%s) -- Proceeding with kill.", basename, image)

    # Primary: psutil
    try:
        proc = psutil.Process(pid)
        proc.kill()
        logger.critical("KILLED PID %d via psutil", pid)
        return True
    except psutil.NoSuchProcess:
        logger.info("PID %d already gone", pid)
        return True
    except psutil.AccessDenied:
        logger.warning("psutil AccessDenied for PID %d -- trying taskkill fallback", pid)
    except Exception as exc:
        logger.error("psutil kill failed for PID %d: %s", pid, exc)

    # Fallback: taskkill /PID
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            logger.critical("KILLED PID %d via taskkill fallback", pid)
            return True
        else:
            logger.error("taskkill /PID failed for PID %d: %s", pid, result.stderr)
    except Exception as exc:
        logger.error("taskkill /PID fallback failed for PID %d: %s", pid, exc)

    # Final fallback: kill by image name
    if image:
        return _kill_by_image(image)

    return False


def _kill_by_image(image: str) -> bool:
    """Kill all processes matching the given image name using taskkill /IM."""
    basename = pathlib.Path(image).name
    if not basename:
        return False
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/IM", basename],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            logger.critical("KILLED by image name: %s", basename)
            return True
        else:
            # returncode 128 = no matching process (already gone)
            if "not found" in result.stderr.lower() or result.returncode == 128:
                logger.info("No running process named %s (already gone?)", basename)
                return True
            logger.error("taskkill /IM %s failed: %s", basename, result.stderr.strip())
            return False
    except Exception as exc:
        logger.error("taskkill /IM fallback failed for %s: %s", basename, exc)
        return False


def _log_kill(
    pid: int, image: str, score: int, reason: str, killed: bool, db_path
) -> None:
    conn = get_connection(db_path)
    message = f"Process {'killed' if killed else 'KILL FAILED'}: {reason}"
    now_ts = _now_iso()

    try:
        # Check for duplicates within 2 seconds
        dup_q = "SELECT id FROM alerts WHERE pid = ? AND message = ? AND ABS(strftime('%s', timestamp) - strftime('%s', ?)) <= 2 LIMIT 1"
        row = conn.execute(dup_q, (pid, message, now_ts)).fetchone()
        if row:
            logger.debug("Skipping duplicate kill alert for PID %d: %s", pid, message)
            return

        with conn:
            conn.execute(
                """
                INSERT INTO alerts
                    (pid, image_path, alert_type, score, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    pid, image,
                    "INSTANT_KILL" if score >= 60 else "KILL",
                    score,
                    message,
                    now_ts,
                ),
            )
            conn.execute(
                "UPDATE processes SET status='KILLED', last_updated=? WHERE pid=?",
                (now_ts, pid),
            )
    finally:
        conn.close()


def _log_alert(pid: int, image: str, score: int, reason: str, alert_type: str, db_path) -> None:
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO alerts (pid, image_path, alert_type, score, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (pid, image, alert_type, score, reason, _now_iso()),
            )
    finally:
        conn.close()
