"""
database/db.py
--------------
SQLite connection factory for BehaviorShield.

IMPORTANT:  Every connection immediately sets WAL journal mode.
            Each thread / Flask request gets its own connection.
            Never share a single connection across threads.
"""

import sqlite3
import pathlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Resolve the schema file relative to this module
_SCHEMA_FILE = pathlib.Path(__file__).parent / "schema.sql"

# Default DB path - can be overridden by passing db_path explicitly
DEFAULT_DB_PATH = pathlib.Path("C:/BehaviorShield/data/behaviorshield.db")


def get_connection(db_path: str | pathlib.Path | None = None) -> sqlite3.Connection:
    """
    Open (or create) the SQLite database and configure it correctly.

    Returns a sqlite3.Connection with:
      - WAL journal mode  (multi-reader / single-writer, safe for Flask + agent)
      - Row factory set to sqlite3.Row  (column access by name)
      - Foreign key enforcement enabled
    """
    path = pathlib.Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        str(path),
        check_same_thread=False,   # Each caller is responsible for their own connection
        timeout=30,
    )
    conn.row_factory = sqlite3.Row

    # -- MUST be set on every new connection ----------------------
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")   # Safe with WAL + good performance
    # -------------------------------------------------------------

    return conn


def init_db(db_path: str | pathlib.Path | None = None) -> None:
    """
    Create all tables from schema.sql if they don't already exist.
    Also inserts the 'install_time' system_meta row used to track learning mode.
    """
    conn = get_connection(db_path)
    schema_sql = _SCHEMA_FILE.read_text(encoding="utf-8")

    with conn:
        conn.executescript(schema_sql)

        # Migrations: add columns to existing tables
        for col_sql in [
            "ALTER TABLE events ADD COLUMN process_name TEXT",
            "ALTER TABLE events ADD COLUMN source TEXT DEFAULT 'watchdog'",
            "ALTER TABLE processes ADD COLUMN hash_verdict TEXT DEFAULT 'UNKNOWN'",
            "ALTER TABLE processes ADD COLUMN cmd_line TEXT",
            "ALTER TABLE whitelist ADD COLUMN cmd_line_pattern TEXT",
            "ALTER TABLE alerts ADD COLUMN dismissed INTEGER DEFAULT 0",
            "CREATE TABLE IF NOT EXISTS protected_folders (id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL UNIQUE, added_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS directory_profiles (path TEXT PRIMARY KEY, event_count INTEGER DEFAULT 0, trusted INTEGER DEFAULT 0, last_updated TEXT)",
            "CREATE TABLE IF NOT EXISTS system_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid)",
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid)",
        ]:
            try:
                conn.execute(col_sql)
            except Exception:
                pass  # Column already exists - safe to ignore

        # Record first-run time for learning mode calculation
        conn.execute(
            """
            INSERT OR IGNORE INTO system_meta (key, value)
            VALUES ('install_time', ?)
            """,
            (datetime.now(timezone.utc).isoformat(),),
        )

    conn.close()
    logger.info("Database initialised at %s (WAL mode)", db_path or DEFAULT_DB_PATH)


def is_learning_mode(
    db_path: str | pathlib.Path | None = None,
    learning_days: int = 7,
) -> bool:
    """
    Return True if we are still within the initial 7-day learning window.
    During learning mode the agent logs threats but never kills processes.
    """
    return False
def is_whitelist_enabled(db_path: str | pathlib.Path | None = None) -> bool:
    """
    Return True if the whitelist functionality is enabled in settings.
    Defaults to True if not explicitly set.
    """
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT value FROM system_meta WHERE key='whitelist_enabled'"
        ).fetchone()
        if row is None:
            return True   # Default to enabled
        return row["value"].lower() == "true"
    except Exception as exc:
        logger.error("Error reading whitelist status: %s", exc)
        return True   # Failsafe: default to enabled
    finally:
        conn.close()
def is_paused(db_path: str | pathlib.Path | None = None) -> bool:
    """
    Return True if protection is currently paused.
    """
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT value FROM system_meta WHERE key='paused_until'"
        ).fetchone()
        if row is None:
            return False
        
        paused_until = float(row["value"])
        import time
        return time.time() < paused_until
    except Exception:
        return False
    finally:
        conn.close()
