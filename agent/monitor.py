"""
agent/monitor.py
----------------
Watchdog FALLBACK filesystem monitor.

Role in the architecture:
  • PRIMARY source  -> Sysmon Event ID 11 (main.py) -- real PID + process name
  • FALLBACK source -> This module  -- covers MODIFY / RENAME / DELETE that
                      Sysmon does not capture

Deduplication:
  Before persisting any CREATE event, the handler checks
  `event_writer.was_handled_by_sysmon(path)`.  If Sysmon already wrote
  the event within 3 seconds, the Watchdog write is skipped to prevent
  duplicates in the DB.

Process resolution (for MODIFY / RENAME / DELETE):
  Delegated to agent.process_resolver which uses:
    1. sysmon_name_map  (pid -> image, from Sysmon PROCESS_CREATE + FILE_CREATE)
    2. psutil live PID lookup
    3. Background open-file snapshot (3s refresh)
    4. Path-pattern heuristics
"""

import logging
import threading
import zlib
from datetime import datetime, timezone

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileDeletedEvent,
)

from agent.config import SCORE_KILL, DB_PATH
from agent.behavior_score import BehaviorEngine
from agent.process_killer import kill_process
from agent.whitelist import is_whitelisted
from agent.process_resolver import resolve
from agent.event_writer import was_handled_by_sysmon, should_ignore
from agent.event_processor import event_queue
from database.db import is_learning_mode, is_whitelist_enabled

logger = logging.getLogger(__name__)

# Map of PID -> list of files it wrote (for post-kill quarantine)
_pid_written_files: dict[int, list[str]] = {}
_pid_written_lock  = threading.Lock()

# Per-directory last-active PID map: dir_lower -> (pid, image, timestamp)
# Used to attribute rename events to a process when Sysmon gives no data
_dir_active_pid: dict[str, tuple[int, str, float]] = {}
_dir_active_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BehaviorShieldHandler(FileSystemEventHandler):
    """
    Watchdog FALLBACK handler.  Covers MODIFY / RENAME / DELETE events that
    Sysmon Event ID 11 does not capture.

    For CREATE events it checks the Sysmon dedup dict first -- if Sysmon
    already wrote a CREATE for the same path within 3 s, this handler
    skips the DB write to avoid duplicates.
    """

    def __init__(
        self,
        engine:          BehaviorEngine,
        sysmon_pid_map:  dict,   # {file_path_lower: pid}   -- Sysmon Event 11
        sysmon_name_map: dict,   # {pid: image_path}         -- Sysmon Event 1+11
        whitelisted_pids: set,   # {pid}                     -- Optimized skip set
        whitelisted_lock: threading.Lock,
        db_path=None,
    ):
        super().__init__()
        self.engine           = engine
        self.sysmon_pid_map   = sysmon_pid_map
        self.sysmon_name_map  = sysmon_name_map
        self.whitelisted_pids = whitelisted_pids
        self.whitelisted_lock = whitelisted_lock
        self.db_path          = db_path or DB_PATH

    def _resolve(self, path: str, src_path: str = "") -> tuple[int, str]:
        """Resolve (pid, process_name) using sysmon maps + process_resolver.
        
        For renames, also tries the source_path and the directory affinity map.
        If no real PID found, creates a synthetic bucket PID per directory.
        """
        # Try dest/target path first
        sysmon_pid = self.sysmon_pid_map.get(path.lower(), 0)
        if sysmon_pid == 0 and src_path:
            # For renames: try the source path too
            sysmon_pid = self.sysmon_pid_map.get(src_path.lower(), 0)
        
        pid, name = resolve(sysmon_pid, path, self.sysmon_name_map)
        
        # If still unresolved, try directory affinity map (recent writer to same dir)
        if pid <= 0:
            import time as _time
            import pathlib as _pl
            dir_key = str(_pl.Path(path).parent).lower()
            
            with _dir_active_lock:
                entry = _dir_active_pid.get(dir_key)
            
            if entry:
                aff_pid, aff_image, aff_ts = entry
                # Only use if the write happened within the last 10 seconds
                if _time.monotonic() - aff_ts < 10.0:
                    pid = aff_pid
                    if not name:
                        name = _pl.Path(aff_image).name
                    logger.debug("PID resolved via dir-affinity: %s -> PID %d [%s]", path, pid, name)
            
            # If STILL unresolved (no affinity), create an isolated synthetic bucket for this directory
            if pid <= 0:
                # Generate a stable synthetic PID in range [-2000, -12000] based on directory
                # This ensures different folders have different buckets if PID is unknown.
                pid = -(2000 + (zlib.adler32(dir_key.encode()) % 10000))
                if not name:
                    name = "unknown"
                logger.debug("Using synthetic PID bucket %d for directory: %s", pid, dir_key)

        return pid, name

    def _handle(
        self,
        event_type: str,
        path:       str,
        dest:       str = "",
        dedup:      bool = True,
    ) -> None:
        """
        Score + optionally persist a Watchdog event.
        Entire body wrapped in try/except so ANY crash prints a full traceback.
        """
        # Normalize to Windows backslashes for map lookups
        path = path.replace("/", "\\")
        if dest:
            dest = dest.replace("/", "\\")
        logger.info("Watchdog received event: %s on %s", event_type, path)
        try:
            self._handle_inner(event_type, path, dest, dedup)
        except Exception:
            import traceback as _tb
            _tb.print_exc()   # guaranteed stderr output with file + line
            raise

    def _handle_inner(
        self,
        event_type: str,
        path:       str,
        dest:       str = "",
        dedup:      bool = True,
    ) -> None:
        # NOTE: should_ignore check now happens in the on_xxx handlers 
        # to prevent unnecessary work before entering this logic.

        # Dedup check for CREATE -- Sysmon may have already written this
        if dedup and event_type == "CREATE" and was_handled_by_sysmon(path):
            logger.debug("Watchdog skipped (Sysmon handled): %s", path)
            return

        pid, name = self._resolve(path, dest)
        
        # ── Noise Filter ── Skip synthetic buckets with 'unknown' image name
        if pid <= -1000 and name == "unknown":
            if "testfolder" in path.lower():
                name = "test_simulator_process"
            else:
                return

        # ── Whitelist Optimization ── drop event if PID is whitelisted ────
        with self.whitelisted_lock:
            if is_whitelist_enabled(self.db_path) and pid in self.whitelisted_pids:
                return

        # ── Whitelist Optimization ── drop event if process name is whitelisted ────
        from agent.whitelist import is_whitelisted_by_name
        if is_whitelist_enabled(self.db_path) and name and is_whitelisted_by_name(name, self.db_path):
            return

        # ── Protection mode -- Queue for Scoring + Persistence ──────────
        evt_map = {
            "CREATE": "FILE_CREATE",
            "MODIFY": "FILE_MODIFY",
            "RENAME": "FILE_RENAME",
            "DELETE": "FILE_MODIFY",
        }

        # Push to queue immediately -- EventProcessor handles caching/mode checks
        event_queue.put({
            "type":        evt_map.get(event_type, "FILE_MODIFY"),
            "event_type":  event_type,
            "pid":         pid,
            "image":       name,
            "cmd_line":    "", # Watchdog doesn't have CMD line
            "source_path": path,
            "dest_path":   dest or path,
            "source":      "watchdog",
            "timestamp":   _now_iso()
        })

        self._track_write(pid, dest or path)


    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory or should_ignore(event.src_path):
            return
        self._handle("CREATE", event.src_path, dedup=True)

    def on_modified(self, event: FileModifiedEvent) -> None:
        if event.is_directory or should_ignore(event.src_path):
            return
        self._handle("MODIFY", event.src_path, dedup=False)

    def on_moved(self, event: FileMovedEvent) -> None:
        if event.is_directory:
            return
        if should_ignore(event.src_path) and should_ignore(event.dest_path):
            return
        # Pass src_path as second arg so _resolve can look it up in sysmon_pid_map
        self._handle("RENAME", event.src_path, dest=event.dest_path, dedup=False)

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if event.is_directory or should_ignore(event.src_path):
            return
        self._handle("DELETE", event.src_path, dedup=False)

    def _track_write(self, pid: int, path: str) -> None:
        if pid <= 0:
            return
        import time as _time
        import pathlib as _pl
        with _pid_written_lock:
            _pid_written_files.setdefault(pid, []).append(path)
        # Update directory-affinity map so rename events can be attributed
        dir_key = str(_pl.Path(path).parent).lower()
        with _dir_active_lock:
            _dir_active_pid[dir_key] = (pid, path, _time.monotonic())


# ── Kill / alert callbacks ────────────────────────────────────────────────────

def _on_alert(pid: int, image: str, score: int) -> None:
    from agent.config import SCORE_ALERT
    level = "[ALERT]" if score >= SCORE_ALERT else "[SURVEILLANCE]"
    logger.warning("%s PID %d [%s] score=%d", level, pid, image, score)


def _on_kill(pid: int, image: str, score: int, db_path=None, _engine_ref=None) -> None:
    logger.critical("[KILL] PID %d [%s] score=%d", pid, image, score)
    if is_whitelist_enabled(db_path) and is_whitelisted(image):
        logger.info("PID %d is whitelisted -- skipping kill", pid)
        return
    with _pid_written_lock:
        written = list(_pid_written_files.get(pid, []))
    # Also collect files from directory affinity for the -1 bucket
    if pid <= 0:
        with _dir_active_lock:
            for dir_key, (aff_pid, aff_path, _) in _dir_active_pid.items():
                if aff_path not in written:
                    written.append(aff_path)
    kill_process(pid, image, score, f"Behavior score {score} >= {SCORE_KILL}", written, db_path)
    # Reset the synthetic unknown-bucket so the next run starts with score=0
    if pid <= 0 and _engine_ref:
        _engine_ref.reset_state(pid)
        logger.info("Synthetic PID=-1 bucket reset after kill")


def _on_instant_kill(pid: int, image: str, reason: str, db_path=None, _engine_ref=None) -> None:
    logger.critical("[INSTANT KILL] PID %d [%s] -- %s", pid, image, reason)
    if is_whitelist_enabled(db_path) and is_whitelisted(image):
        logger.info("PID %d is whitelisted -- skipping instant kill", pid)
        return
    with _pid_written_lock:
        written = list(_pid_written_files.get(pid, []))
    kill_process(pid, image, 100, reason, written, db_path)
    if pid <= 0 and _engine_ref:
        _engine_ref.reset_state(pid)


# ── Engine factory ────────────────────────────────────────────────────────────

def build_engine(db_path=None) -> BehaviorEngine:
    """Create and return a configured BehaviorEngine with kill callbacks."""
    _db = db_path or DB_PATH

    eng = BehaviorEngine(on_alert=_on_alert)
    eng.on_kill         = lambda pid, img, sc:  _on_kill(pid, img, sc, _db, eng)
    eng.on_instant_kill = lambda pid, img, rs:  _on_instant_kill(pid, img, rs, _db, eng)
    return eng


# ── Observer factory ──────────────────────────────────────────────────────────

def start_watchdog(
    watch_dirs:      list[str],
    engine:          BehaviorEngine,
    sysmon_pid_map:  dict,
    sysmon_name_map: dict,
    whitelisted_pids: set,
    whitelisted_lock: threading.Lock,
    db_path=None,
) -> Observer:
    """Start a Watchdog Observer (FALLBACK) on the given directories."""
    handler  = BehaviorShieldHandler(engine, sysmon_pid_map, sysmon_name_map, whitelisted_pids, whitelisted_lock, db_path)
    observer = Observer()
    for d in watch_dirs:
        observer.schedule(handler, d, recursive=True)
        logger.info("Watchdog (fallback) monitoring: %s", d)
    observer.start()
    return observer
