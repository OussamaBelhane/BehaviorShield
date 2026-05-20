"""
agent/whitelist.py
------------------
Signature-based whitelist for BehaviorShield.
Whitelist entries are keyed by SHA-256 of the executable binary.
Renaming an exe to 'explorer.exe' does NOT bypass the whitelist.
"""

import logging
import pathlib
import threading
from datetime import datetime, timezone

from agent.signature_check import get_file_sha256
from agent.config import DB_PATH
from database.db import get_connection

logger = logging.getLogger(__name__)

# -- In-memory cache for O(1) lookups without DB overhead --------------
_whitelist_hashes: set[str] = set()
_whitelist_paths:  set[str] = set()
_whitelist_cmds:   list[str] = [] # list of SQL LIKE patterns
_cache_lock = threading.Lock()

def is_whitelisted_by_path(exe_path: str | pathlib.Path, db_path=None) -> bool:
    """Fast check if the exact path is in the whitelist (uses cache)."""
    path_str = str(exe_path).lower()
    if not path_str: return False
    
    from agent.config import NEVER_WHITELIST
    basename = pathlib.Path(path_str).name.lower()
    if basename in NEVER_WHITELIST:
        return False

    with _cache_lock:
        if path_str in _whitelist_paths:
            return True

    # Fallback to DB if cache is empty or for some reason missed (e.g. startup)
    conn = get_connection(db_path or DB_PATH)
    try:
        row = conn.execute(
            "SELECT id FROM whitelist WHERE LOWER(exe_path) = ? AND exe_path != ''", 
            (path_str,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()

def is_whitelisted_by_name(process_name: str, db_path=None) -> bool:
    """Fast check if the process name matches any whitelisted paths."""
    if not process_name: return False
    
    from agent.config import NEVER_WHITELIST
    if process_name.lower() in NEVER_WHITELIST:
        return False
        
    conn = get_connection(db_path or DB_PATH)
    try:
        row = conn.execute(
            "SELECT id FROM whitelist WHERE LOWER(exe_path) LIKE ?", 
            (f"%\\{process_name.lower()}",)
        ).fetchone()
        
        # Also check without backslash in case paths were stored with forward slashes
        if not row:
            row = conn.execute(
                "SELECT id FROM whitelist WHERE LOWER(exe_path) LIKE ?", 
                (f"%/{process_name.lower()}",)
            ).fetchone()
            
        return row is not None
    finally:
        conn.close()


def is_whitelisted_by_cmd(cmd_line: str, db_path=None) -> bool:
    """[IMPROVEMENT 4] Check if the full command line matches any whitelisted pattern."""
    if not cmd_line: return False
    
    conn = get_connection(db_path or DB_PATH)
    try:
        # Check using SQL LIKE patterns
        row = conn.execute(
            "SELECT id FROM whitelist WHERE ? LIKE cmd_line_pattern AND cmd_line_pattern IS NOT NULL", 
            (cmd_line,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def is_whitelisted(exe_path: str | pathlib.Path, db_path=None, sha256: str | None = None, cmd_line: str | None = None) -> bool:
    """
    Return True if the executable is in the whitelist table (by path OR sha256 OR cmd_line).
    Ensures that Group 1 (System) and Group 2 (User) entries are skipped by monitoring.
    """
    path_str = str(exe_path)
    
    from agent.config import NEVER_WHITELIST
    basename = pathlib.Path(path_str).name.lower()
    if basename in NEVER_WHITELIST:
        return False
        
    if is_whitelisted_by_path(path_str, db_path):
        return True

    if cmd_line and is_whitelisted_by_cmd(cmd_line, db_path):
        return True

    sha = sha256 or get_file_sha256(path_str)
    if not sha:
        return False

    conn = get_connection(db_path or DB_PATH)
    try:
        row = conn.execute(
            "SELECT id FROM whitelist WHERE exe_sha256 = ?", (sha,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def add_to_whitelist(
    exe_path: str | pathlib.Path,
    vendor: str = "",
    reason: str = "",
    is_system: bool = False,
    db_path=None,
    sha256: str | None = None, # Support passing sha256 directly to avoid re-hashing
) -> bool:
    """
    Add an executable to the whitelist by its SHA-256.
    Returns True on success, False if file is unreadable.
    """
    from agent.config import NEVER_WHITELIST
    basename = pathlib.Path(exe_path).name.lower()
    if basename in NEVER_WHITELIST:
        return False

    sha = sha256 or get_file_sha256(str(exe_path))
    if not sha:
        logger.warning("Cannot whitelist %s -- file unreadable", exe_path)
        return False

    conn = get_connection(db_path or DB_PATH)
    try:
        with conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO whitelist (exe_sha256, exe_path, vendor, reason, is_system, added_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (sha, str(exe_path), vendor, reason, 1 if is_system else 0, datetime.now(timezone.utc).isoformat()),
            )
        logger.info("Whitelisted %s (sha256=%s...)", exe_path, sha[:12])
        return True
    finally:
        conn.close()


def remove_from_whitelist(whitelist_id: int, db_path=None) -> bool:
    """Remove an entry by its DB row ID."""
    conn = get_connection(db_path or DB_PATH)
    try:
        with conn:
            conn.execute("DELETE FROM whitelist WHERE id = ?", (whitelist_id,))
        return True
    finally:
        conn.close()


def get_all_whitelist_entries(db_path=None) -> list[dict]:
    """Return all whitelist entries as a list of dicts."""
    conn = get_connection(db_path or DB_PATH)
    try:
        rows = conn.execute(
            "SELECT id, exe_sha256, exe_path, vendor, reason, is_system, added_at FROM whitelist"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_whitelisted_hashes(db_path=None) -> set[str]:
    """Retrieve all whitelisted SHA-256 hashes as a set for O(1) lookups."""
    conn = get_connection(db_path or DB_PATH)
    try:
        rows = conn.execute("SELECT exe_sha256 FROM whitelist").fetchall()
        return {r["exe_sha256"].lower() for r in rows if r["exe_sha256"]}
    finally:
        conn.close()


def sync_whitelist_cache(db_path=None) -> None:
    """Refresh the in-memory sets from the database."""
    global _whitelist_hashes, _whitelist_paths, _whitelist_cmds
    
    conn = get_connection(db_path or DB_PATH)
    try:
        rows = conn.execute("SELECT exe_sha256, exe_path, cmd_line_pattern FROM whitelist").fetchall()
        
        new_hashes = {r["exe_sha256"].lower() for r in rows if r["exe_sha256"]}
        new_paths  = {r["exe_path"].lower() for r in rows if r["exe_path"]}
        new_cmds   = [r["cmd_line_pattern"] for r in rows if r["cmd_line_pattern"]]
        
        with _cache_lock:
            _whitelist_hashes = new_hashes
            _whitelist_paths  = new_paths
            _whitelist_cmds   = new_cmds
            
        logger.debug("Whitelist cache synced: %d hashes, %d paths, %d cmd patterns", len(_whitelist_hashes), len(_whitelist_paths), len(_whitelist_cmds))
    except Exception as e:
        logger.error("Failed to sync whitelist cache: %s", e)
    finally:
        conn.close()
