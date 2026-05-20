"""
agent/event_writer.py
---------------------
Shared event persistence layer for BehaviorShield.

Both the Sysmon path (main.py) and the Watchdog path (monitor.py) call
`persist_file_event()` to write to the DB.  A thread-safe deduplication
dict prevents double-writes when both sources fire for the same file.

Deduplication rule:
  When Sysmon writes a FILE_CREATE for path X, it records X in
  `sysmon_seen` with the current timestamp.  The Watchdog handler
  checks this dict; if path X was seen within DEDUP_WINDOW_SEC seconds
  it skips the DB write entirely (Sysmon already captured it -- with the
  correct PID and process name -- so there is nothing to add).
"""

import logging
import threading
import time
import pathlib
from datetime import datetime, timezone

from agent.config import DB_PATH, EXCLUDED_EXTENSIONS, EXCLUDED_PATH_PATTERNS, WATCHDOG_EXCLUDED_DIRS
from database.db import get_connection

logger = logging.getLogger(__name__)

# ── Noise filter ──────────────────────────────────────────────────────────────

def should_ignore(path: str) -> bool:
    """
    Return True if this file event is noise that should never reach the DB.
    Checks:
      1. File extension / suffix  (e.g. .log, .tmp, .pf, -journal)
      2. Path substrings          (e.g. \\Prefetch\\, \\Cache_Data\\)
    """
    p = path.lower().replace("/", "\\")

    # Extension / suffix check (handles both .ext and suffix like -journal)
    for excl in EXCLUDED_EXTENSIONS:
        if p.endswith(excl.lower()):
            return True

    # Path pattern check
    for pattern in EXCLUDED_PATH_PATTERNS:
        if pattern.lower() in p:
            logger.debug("Ignoring path due to pattern '%s': %s", pattern, path)
            return True

    # Directory segment check (fast, case-insensitive)
    # Using set lookup for O(1) performance per segment
    path_parts = p.split("\\")
    for part in path_parts:
        if part in WATCHDOG_EXCLUDED_DIRS:
            logger.debug("Ignoring path due to excluded directory segment '%s': %s", part, path)
            return True

    return False

# ── Deduplication window ──────────────────────────────────────────────────────
DEDUP_WINDOW_SEC = 3.0   # seconds -- Watchdog fires within ~1s of Sysmon

# Shared dedup dict: {file_path_lower: unix_timestamp}
# Written by Sysmon path, read by Watchdog path.
sysmon_seen: dict[str, float] = {}
_seen_lock  = threading.Lock()


def record_sysmon_path(path: str) -> None:
    """Mark a path as just handled by Sysmon (suppresses Watchdog write)."""
    with _seen_lock:
        sysmon_seen[path.lower()] = time.monotonic()


def was_handled_by_sysmon(path: str) -> bool:
    """Return True if Sysmon wrote this path within DEDUP_WINDOW_SEC."""
    with _seen_lock:
        ts = sysmon_seen.get(path.lower())
    if ts is None:
        return False
    return (time.monotonic() - ts) < DEDUP_WINDOW_SEC


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity(total_delta: int) -> str:
    if total_delta >= 20:
        return "CRITICAL"
    if total_delta >= 10:
        return "WARNING"
    return "INFO"


def persist_file_event(
    event_type:   str,
    path:         str,
    dest:         str,
    pid:          int,
    process_name: str,
    rules:        list,
    db_path=None,
    source:       str = "watchdog",   # "sysmon" | "watchdog"
) -> None:
    """
    Write a file event to the database.

    Called by:
      - main._on_sysmon_event  (source="sysmon",   has real PID + name)
      - BehaviorShieldHandler  (source="watchdog",  best-effort PID + name)

    Parameters
    ----------
    event_type   : "CREATE" | "MODIFY" | "RENAME" | "DELETE"
    path         : source / primary file path
    dest         : destination path (renames only)
    pid          : process PID (0 if unknown)
    process_name : exe basename e.g. "python.exe" (empty if unknown)
    rules        : list of triggered rule dicts from BehaviorEngine
    db_path      : override default DB path
    source       : originating data source
    """
    # Never log our own DB writes (infinite feedback loop prevention)
    p = path.lower()
    if "behaviorshield\\data" in p or "behaviorshield/data" in p:
        return

    total_delta = sum(r.get("delta", 0) for r in rules)
    sev = _severity(total_delta)

    conn = get_connection(db_path or DB_PATH)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO events
                    (pid, process_name, event_type, source_path, dest_path,
                     score_delta, severity, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pid or None,
                    process_name or None,
                    event_type,
                    path,
                    dest or None,
                    total_delta,
                    sev,
                    source,
                    _now_iso(),
                ),
            )
    except Exception as exc:
        logger.error("persist_file_event failed: %s", exc)
    finally:
        conn.close()
