"""
agent/main.py
-------------
BehaviorShield detection agent entry point.

Usage (Administrator terminal):
    python run_agent.py
            -- OR --
    python -m agent.main

Starts:
  1. ProcessFileCache    -- background psutil process snapshot (pid->name)
  2. Sysmon reader       -- Event IDs 1 (ProcessCreate) + 11 (FileCreate)
                           PRIMARY source: writes to DB with real PID + name
  3. Watchdog observer   -- FALLBACK for MODIFY / RENAME / DELETE
                           Skips any file already written by Sysmon (dedup)
"""

import ctypes
import logging
import pathlib
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone


def _ensure_dirs() -> None:
    """Create required runtime directories.  MUST run before anything else."""
    for d in [
        pathlib.Path("C:/BehaviorShield/data"),
        pathlib.Path("C:/BehaviorShield/logs"),
        pathlib.Path("C:/BehaviorShield/Quarantine"),
        pathlib.Path("C:/BehaviorShield/TestFolder"),
    ]:
        d.mkdir(parents=True, exist_ok=True)

    # ── API Token Generation ──────────────────────────────────────────
    from agent.config import API_TOKEN_PATH
    if not API_TOKEN_PATH.exists():
        import secrets
        import subprocess
        token = secrets.token_hex(32)
        API_TOKEN_PATH.write_text(token, encoding="utf-8")
        
        # Restrict permissions to SYSTEM and Administrators (Windows)
        try:
            # /inheritance:r = remove inherited ACEs
            # /grant:r = grant specific rights
            subprocess.run([
                "icacls", str(API_TOKEN_PATH),
                "/inheritance:r",
                "/grant:r", "SYSTEM:(F)",
                "/grant:r", "Administrators:(F)",
                "/grant:r", "Users:(R)"
            ], capture_output=True, check=False)
            print("[OK] Generated new API token and set NTFS permissions.")
        except Exception as e:
            print(f"[!] Generated API token but failed to set NTFS permissions: {e}")


# ── STEP 1: Create directories FIRST so the log file can be opened ───────────
_ensure_dirs()

# ── STEP 2: Now configure logging safely ────────────────────────────────────
class SQLiteLogHandler(logging.Handler):
    def emit(self, record):
        try:
            from database.db import get_connection
            from agent.config import DB_PATH
            import sqlite3
            from datetime import datetime, timezone
            
            # Formatter handles exception tracebacks automatically if present
            msg = self.format(record)
            
            conn = get_connection(DB_PATH)
            try:
                with conn:
                    # We save all INFO, WARNING, ERROR, CRITICAL to db logs table
                    conn.execute(
                        "INSERT INTO system_logs (timestamp, level, module, message) VALUES (?, ?, ?, ?)",
                        (datetime.now(timezone.utc).isoformat(), record.levelname, record.name, msg)
                    )
            finally:
                conn.close()
        except Exception:
            pass

sqlite_handler = SQLiteLogHandler()
sqlite_handler.setFormatter(logging.Formatter("%(message)s"))

class _SafeStreamHandler(logging.StreamHandler):
    """StreamHandler that never raises — catches any internal error and dumps to stderr."""
    def emit(self, record):
        try:
            super().emit(record)
        except Exception:
            try:
                import traceback as _tb
                sys.stderr.write(f"\n[LOG HANDLER CRASH]\n{_tb.format_exc()}\n")
                sys.stderr.flush()
            except Exception:
                pass

from agent.config import SILENT_MODE

log_handlers = [
    _SafeStreamHandler(sys.stdout),
    sqlite_handler
]

if SILENT_MODE:
    log_handlers.append(logging.NullHandler())
else:
    log_handlers.append(logging.FileHandler("C:/BehaviorShield/logs/agent.log", encoding="utf-8"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=log_handlers,
)
logger = logging.getLogger("BehaviorShield")

# Catch absolutely any unhandled exception (like missing modules, fatal crashes)
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    import traceback
    # Format the full traceback as a string so it's always written to the log file
    tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    tb_text = "".join(tb_lines)
    traceback.print_exception(exc_type, exc_value, exc_traceback)
    logger.critical("Uncaught fatal exception\n%s", tb_text)

sys.excepthook = handle_exception

# Also catch exceptions from daemon threads (Sysmon reader, hash scanner, Watchdog)
import threading as _threading

def _handle_thread_exception(args):
    """Truly bulletproof thread crash handler -- outer try catches everything."""
    try:
        exc_type  = getattr(args, 'exc_type',      None)
        exc_value = getattr(args, 'exc_value',     None)
        exc_tb    = getattr(args, 'exc_traceback', None)
        thread    = getattr(args, 'thread',        None)

        if exc_type is SystemExit:
            return

        thread_name = getattr(thread, 'name', 'unknown') if thread else 'unknown'

        try:
            import traceback as _tb
            tb_text = "".join(_tb.format_exception(exc_type, exc_value, exc_tb))
        except BaseException:
            tb_text = f"{exc_type}: {exc_value}\n(format_exception failed)\n"

        # Write to UTF-8 log file first (most reliable)
        try:
            with open("C:/BehaviorShield/logs/agent.log", "a", encoding="utf-8") as _lf:
                import datetime as _dt
                _lf.write(
                    f"\n{_dt.datetime.now():%Y-%m-%d %H:%M:%S}"
                    f" [CRITICAL] THREAD_CRASH thread='{thread_name}'\n{tb_text}\n"
                )
        except BaseException:
            pass

        # Also write to stderr (may fail on cp1252 consoles)
        try:
            sys.stderr.write(f"\n[THREAD CRASH] thread='{thread_name}':\n{tb_text}\n")
            sys.stderr.flush()
        except BaseException:
            pass

    except BaseException:
        pass   # absolute last resort — never propagate

_threading.excepthook = _handle_thread_exception

# Catch exceptions from __del__ / finalizers — these bypass threading.excepthook
def _handle_unraisable(args):
    """Catch exceptions raised in __del__ or C finalizers."""
    try:
        import traceback as _tb
        tb_text = "".join(_tb.format_exception(
            args.exc_type, args.exc_value,
            getattr(args, 'exc_traceback', None)
        ))
        with open("C:/BehaviorShield/logs/agent.log", "a", encoding="utf-8") as _f:
            import datetime as _dt
            _f.write(f"\n{_dt.datetime.now():%Y-%m-%d %H:%M:%S} [CRITICAL] UNRAISABLE: {getattr(args,'err_msg','')}\n{tb_text}\n")
        sys.stderr.write(f"\n[UNRAISABLE] {getattr(args,'err_msg','')}\n{tb_text}\n")
        sys.stderr.flush()
    except BaseException:
        pass

sys.unraisablehook = _handle_unraisable


from agent.config import DB_PATH, SKIP_SCAN_PATHS
from agent.monitor import build_engine, start_watchdog
from agent.sysmon_reader import SysmonReader
from agent.process_resolver import process_cache
from agent.event_writer import record_sysmon_path, should_ignore
from agent.hash_scanner import scan_async, should_skip_path
from database.db import init_db, is_learning_mode, is_whitelist_enabled, get_connection
from agent.event_processor import EventProcessor, event_queue


# ── Shared state ─────────────────────────────────────────────────────────────

# {file_path.lower(): pid}   -- Sysmon Event ID 11 -> used by Watchdog fallback
_sysmon_pid_map:  dict[str, int] = {}
_sysmon_map_lock = threading.Lock()

# {pid: image_path}          -- Sysmon Event IDs 1 + 11 -> process name lookup
_sysmon_name_map:  dict[int, str] = {}
_sysmon_name_map_lock = threading.Lock()

# {pid}                       -- Active whitelisted pids (skipped by engine)
_whitelisted_pids: set[int] = set()
_whitelisted_lock = threading.Lock()

# Global processor reference
processor = None

# Global cache for the 'whitelist_enabled' setting (synced by worker)
_whitelist_enabled_cache: bool = True


# ── Admin check ───────────────────────────────────────────────────────────────

def _check_admin() -> None:
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        print(
            "\n"
            "+----------------------------------------------------------+\n"
            "|           BehaviorShield -- Permission Error             |\n"
            "+----------------------------------------------------------+\n"
            "|  BehaviorShield must be run as Administrator.            |\n"
            "|                                                          |\n"
            "|  How to fix:                                             |\n"
            "|    1. Close this window                                  |\n"
            "|    2. Right-click your terminal                          |\n"
            "|    3. Select 'Run as administrator'                      |\n"
            "|    4. Run:  python run_agent.py                          |\n"
        )
        # sys.exit(1)
        pass


# ── Sysmon event handler ────────────────────────────────────────────────────────

def _on_sysmon_event(event: dict) -> None:
    """
    Called by SysmonReader for every Sysmon event.

    PROCESS_CREATE (ID 1):
      - Check if exe path should skip scanning (trusted dirs)
      - Fire async hash scan (non-blocking)
      - Register UNKNOWN processes in behavior engine via callback

    FILE_CREATE (ID 11):
      ★ PRIMARY path: writes to DB with real PID + process name
      - Score via BehaviorEngine
      - Persist to DB  (source='sysmon')
      - Record path in dedup dict so Watchdog skips it
    """
    etype = event.get("type")

    if etype == "PROCESS_CREATE":
        image    = event.get("image", "")
        pid      = event.get("pid", 0)
        cmd_line = event.get("cmd_line", "")

        # Store pid -> image in lookup maps (always)
        if pid > 0 and image:
            with _sysmon_name_map_lock:
                _sysmon_name_map[pid] = image

        # ── [IMPROVEMENT 5] Instant Whitelist by Signature ──
        from agent.signature_check import get_signature_status
        sig_status = get_signature_status(image)
        
        is_inst_whitelisted = False
        if sig_status == "TRUSTED":
            # Check if in standard location
            p_lower = image.lower()
            if "windows\\system32" in p_lower or "program files" in p_lower:
                with _whitelisted_lock:
                    _whitelisted_pids.add(pid)
                is_inst_whitelisted = True
                logger.info("INSTANT WHITELIST (Signature): PID %d [%s]", pid, pathlib.Path(image).name)

        if is_inst_whitelisted:
            return

        # ── [IMPROVEMENT 4] Command-line Whitelisting ──
        from agent.whitelist import is_whitelisted_by_cmd
        if cmd_line and is_whitelisted_by_cmd(cmd_line, DB_PATH):
            with _whitelisted_lock:
                _whitelisted_pids.add(pid)
            logger.info("WHITELISTED (Command Line): PID %d matches pattern", pid)
            return

        # ── Skip trusted paths ── no scanning needed ────────────────────
        if image and should_skip_path(image):
            logger.debug("Skipping hash scan (trusted path): %s", image)
            return

        # ── Whitelist Optimization ── skip monitoring if already whitelisted ──
        from agent.whitelist import is_whitelisted_by_path
        from agent.config import NEVER_WHITELIST
        
        process_name = pathlib.Path(image).name.lower() if image else ""
        if process_name in NEVER_WHITELIST:
            logger.warning("Interpreter %s spawned (PID %d) -- bypassing auto-whitelist.", process_name, pid)
        elif image and _whitelist_enabled_cache and is_whitelisted_by_path(image, DB_PATH):
            with _whitelisted_lock:
                _whitelisted_pids.add(pid)
            logger.info("WHITELIST CACHED: PID %d [%s]", pid, pathlib.Path(image).name)
            return

        current_mode = "learning" if is_learning_mode(DB_PATH) else "protection"
        scan_async(
            exe_path=image,
            pid=pid,
            mode=current_mode,
            signature=sig_status, # Reuse signature check
            parent_image=event.get("parent_image", ""),
            db_path=DB_PATH,
            engine=engine # [IMPROVEMENT 8] Pass engine for unified alerts
        )

    elif etype == "FILE_CREATE":
        target       = event.get("target_file", "")
        pid          = event.get("pid", 0)
        image        = event.get("image", "")
        process_name = pathlib.Path(image).name if image else ""

        is_whitelisted = False
        with _whitelisted_lock:
            if _whitelist_enabled_cache and pid in _whitelisted_pids:
                is_whitelisted = True

        if not is_whitelisted:
            from agent.whitelist import is_whitelisted_by_name
            if _whitelist_enabled_cache and process_name and is_whitelisted_by_name(process_name, DB_PATH):
                if pid > 0:
                    with _whitelisted_lock:
                        _whitelisted_pids.add(pid)
                is_whitelisted = True
        
        if is_whitelisted:
            return

        # ── Noise gate ── drop boring creates (prefetch, logs, etc.) ─────────
        if should_ignore(target):
            return

        # Keep lookup maps up to date
        # Record in dedup and PID map
        # Normalize to backslashes
        target_norm = target.replace("/", "\\").lower()
        with _sysmon_map_lock:
            _sysmon_pid_map[target_norm] = pid
            _sysmon_name_map[pid] = image
        if pid > 0 and image:
            with _sysmon_name_map_lock:
                _sysmon_name_map[pid] = image

        # ── Protection mode -- Queue for Scoring + Persistence ──────────
        if target:
            event_queue.put({
                "type":         "FILE_CREATE",
                "event_type":   "CREATE",
                "pid":          pid,
                "image":        image,
                "process_name": process_name,
                "source_path":  target,
                "dest_path":    target,
                "source":       "sysmon",
                "timestamp":    datetime.now(timezone.utc).isoformat(),
                "is_whitelisted": is_whitelisted
            })
            record_sysmon_path(target)

            # Note: Scoring and DB write now happen in EventProcessor threads.
            # Real-time console logs will now be handled by the engine's callbacks 
            # or the processor worker.


# ── Startup process scan ──────────────────────────────────────────────────────

# -- [IMPROVEMENT 7] Global Scan Progress State --------------------------
_scan_progress = {"scanned": 0, "total": 0, "finished": False}

def _scan_running_processes(db_path, mode: str, engine=None) -> None:
    """
    [IMPROVEMENT 1] Prioritized and Parallelized Startup Scan.
    Features: Aggressive pre-filtering, directory prioritization, progress reporting.
    """
    import psutil
    from concurrent.futures import ThreadPoolExecutor, wait
    from agent.config import is_risky_path, SILENT_MODE
    from agent.signature_check import get_signature_status
    from agent.whitelist import is_whitelisted_by_path, get_whitelisted_hashes
    from agent.hash_scanner import is_cached, scan
    
    logger.info("Starting prioritized startup scan...")
    _scan_progress["finished"] = False
    
    # 0. Ensure a "System Watchdog" entry exists
    if not SILENT_MODE:
        conn = get_connection(db_path)
        try:
            conn.execute(
                "INSERT OR IGNORE INTO processes (pid, image_path, status, first_seen, last_updated) VALUES (?, ?, ?, ?, ?)",
                (0, "[System Watchdog]", "ACTIVE", datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
        finally:
            conn.close()

    # 1. Collect and Pre-filter processes
    all_procs = []
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            pid = proc.info['pid']
            exe = proc.info['exe']
            if not pid or not exe: continue
            
            with _sysmon_name_map_lock:
                _sysmon_name_map[pid] = exe
                
            # [IMPROVEMENT 1] Aggressive pre-filter for signed system binaries
            p_lower = exe.lower()
            if ("windows\\system32" in p_lower or "program files" in p_lower):
                if get_signature_status(exe) == "TRUSTED":
                    with _whitelisted_lock:
                        _whitelisted_pids.add(pid)
                    continue
            
            all_procs.append((pid, exe))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    _scan_progress["total"] = len(all_procs)
    _scan_progress["scanned"] = 0
    
    # [IMPROVEMENT 1] Sort by risky paths (Risky directories first)
    all_procs.sort(key=lambda x: is_risky_path(x[1]), reverse=True)

    # 2. Parallel scan with cap of 20 workers
    executor = ThreadPoolExecutor(max_workers=20)
    futures = []
    
    def _worker(p, e):
        global _scan_progress
        try:
            res = scan(e, p, mode, "UNKNOWN", "", db_path, silent=True, engine=engine)
            if res in ("clean", "whitelisted"):
                with _whitelisted_lock:
                    _whitelisted_pids.add(p)
        finally:
            _scan_progress["scanned"] += 1
            # Push progress event
            event_queue.put({
                "type": "SCAN_PROGRESS",
                "scanned": _scan_progress["scanned"],
                "total": _scan_progress["total"]
            })
            
            # [IMPROVEMENT 7] Persist to DB for backend visibility
            if not SILENT_MODE:
                try:
                    conn = get_connection(db_path)
                    with conn:
                        import json
                        conn.execute(
                            "INSERT OR REPLACE INTO system_meta (key, value) VALUES (?, ?)",
                            ("scan_progress", json.dumps(_scan_progress))
                        )
                except: pass
                finally:
                    conn.close()

    for pid, exe in all_procs:
        futures.append(executor.submit(_worker, pid, exe))
        
    wait(futures, timeout=60)
    executor.shutdown(wait=False, cancel_futures=True)
    
    _scan_progress["finished"] = True
    logger.info("Startup scan complete: processed %d processes.", _scan_progress["total"])

# ── Shutdown ──────────────────────────────────────────────────────────────────

_shutdown = threading.Event()
_restart_requested = threading.Event()

def _command_loop():
    """Listen for user input in a background thread."""
    import msvcrt
    import sys
    
    # Print a clear instruction for the user
    if sys.stdout:
        sys.stdout.write("\n" + "="*40 + "\n")
        sys.stdout.write(" [CONSOLE] Press 'q' to quit, 'r' to restart.\n")
        sys.stdout.write("="*40 + "\n\n")
        sys.stdout.flush()

    while not _shutdown.is_set():
        try:
            # Check for immediate key presses on Windows
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                
                # Handle special keys (0 or 0xE0 prefix)
                if ch in (b'\x00', b'\xe0'):
                    msvcrt.getch() # swallow the second byte
                    continue

                try:
                    char = ch.decode('utf-8').lower()
                except UnicodeDecodeError:
                    continue

                if char == 'q':
                    logger.info("Quit command received via keyboard.")
                    _shutdown.set()
                elif char == 'r':
                    logger.info("Restart command received via keyboard.")
                    _restart_requested.set()
                    _shutdown.set()
            
            # Small sleep to avoid CPU pinning
            time.sleep(0.1)
        except Exception as e:
            # Fallback if msvcrt fails for any reason
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                cmd = line.strip().lower()
                if cmd == 'q':
                    _shutdown.set()
                elif cmd == 'r':
                    _restart_requested.set()
                    _shutdown.set()
            except:
                break

def _whitelist_sync_worker() -> None:
    """Periodically sync manual DB whitelist changes into the active running agent memory."""
    from agent.whitelist import get_all_whitelist_entries
    
    global _whitelist_enabled_cache
    
    while not _shutdown.is_set():
        try:
            # 1. Update the global enabled setting cache
            from database.db import is_whitelist_enabled as _db_is_enabled
            _whitelist_enabled_cache = _db_is_enabled(DB_PATH)
            
            # 2. Update the in-memory whitelist cache (paths/hashes)
            from agent.whitelist import sync_whitelist_cache
            sync_whitelist_cache(DB_PATH)

            # 3. Fetch current whitelist to update active PID set
            from agent.whitelist import get_all_whitelist_entries
            entries = get_all_whitelist_entries(DB_PATH)
            db_paths = {e["exe_path"].lower() for e in entries if e["exe_path"]}
            
            with _sysmon_name_map_lock:
                items = list(_sysmon_name_map.items())
                
            new_whitelisted = 0
            for pid, exe in items:
                with _whitelisted_lock:
                    if pid in _whitelisted_pids:
                        continue  # Already whitelisted
                
                # Check path first (instant)
                exe_lower = exe.lower()
                is_whitel = False
                if exe_lower in db_paths:
                    is_whitel = True
                
                # Check NEVER_WHITELIST
                from agent.config import NEVER_WHITELIST
                if pathlib.Path(exe).name.lower() in NEVER_WHITELIST:
                    is_whitel = False
                if is_whitel:
                    with _whitelisted_lock:
                        _whitelisted_pids.add(pid)
                    logger.info("WHITELIST SYNC: PID %d [%s] synced from DB manually", pid, pathlib.Path(exe).name)
                    new_whitelisted += 1

            if new_whitelisted > 0:
                logger.info("Whitelist sync: added %d new active pids to memory cache.", new_whitelisted)

        except Exception as exc:
            logger.error("Whitelist sync error: %s", exc)

        # Sleep in small chunks so shutdown is responsive
        for _ in range(5):
            if _shutdown.is_set():
                return
            time.sleep(1)

def _handle_signal(sig, frame):
    logger.info("Shutdown signal received -- stopping...")
    _shutdown.set()


def _control_check_worker() -> None:
    """Watch the DB for reload_requested and stop_requested flags set by /api/reload."""
    while not _shutdown.is_set():
        try:
            conn = get_connection(DB_PATH)
            try:
                row = conn.execute(
                    "SELECT value FROM system_meta WHERE key='reload_requested'"
                ).fetchone()
                if row and str(row["value"]).strip() == "1":
                    logger.info("[Control] Reload requested via API -- restarting agent...")
                    # Clear the flag immediately so we don't loop
                    with conn:
                        conn.execute("DELETE FROM system_meta WHERE key='reload_requested'")
                    _restart_requested.set()
                    _shutdown.set()
            finally:
                conn.close()
        except Exception as e:
            logger.warning("[Control] control_check_worker error: %s", e)

        # Sleep in small chunks so shutdown is fast
        for _ in range(3):
            if _shutdown.is_set():
                return
            time.sleep(1)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    global engine

    print("\n  BehaviorShield v1.0 -- Starting up...\n")

    # 1. Admin check
    _check_admin()

    # 2. Initialise DB
    init_db(DB_PATH)

    # 3. Learning mode notice
    if is_learning_mode(DB_PATH):
        logger.info(
            "LEARNING MODE ACTIVE -- BehaviorShield will observe for 7 days "
            "before engaging kill protection."
        )
    else:
        logger.info("PROTECTION MODE ACTIVE -- Threats will be killed automatically.")

    # 4. Build the behavior engine
    engine = build_engine(DB_PATH)

    # 4.0. Start Event Processor (Background Worker)
    global processor
    processor = EventProcessor(engine, DB_PATH)
    processor.start()
    logger.info("EventProcessor (Background Scoring + DB) started.")

    # 4.1 Sync whitelist cache immediately
    from agent.whitelist import sync_whitelist_cache
    sync_whitelist_cache(DB_PATH)

    # 4.5. Scan already-running processes
    current_mode = "learning" if is_learning_mode(DB_PATH) else "protection"
    _scan_running_processes(DB_PATH, current_mode, engine=engine)

    # 5. Start ProcessFileCache (background psutil snapshot)
    process_cache.start()
    logger.info("ProcessFileCache started (background process snapshot every 3s)")

    # 6. Start Sysmon reader -- PRIMARY event source
    sysmon_reader = SysmonReader(callback=_on_sysmon_event)
    sysmon_reader.start()
    logger.info("Sysmon reader started -- PRIMARY source (Event IDs 1 + 11)")

    # 6.5. Start Whitelist Sync thread
    threading.Thread(target=_whitelist_sync_worker, daemon=True, name="whitelist-sync").start()
    logger.info("Whitelist sync thread started (checks DB every 15s)")

    # 6.6. Start Control Check thread (reload / stop signals from API)
    threading.Thread(target=_control_check_worker, daemon=True, name="control-check").start()
    logger.info("Control check thread started (reload/stop signals via DB)")


    # 7. Start Watchdog -- FALLBACK for MODIFY / RENAME / DELETE
    # Targeted monitoring: ONLY watch high-value user data folders.
    # This avoids the massive noise of AppData and Program Files.
    home = pathlib.Path.home()
    watch_dirs = [
        str(home / "Desktop"),
        str(home / "Documents"),
        str(home / "Downloads"),
        str(home / "Pictures"),
        str(home / "Videos"),
        str(home / "Music"),
        str(home / "OneDrive"),
        "C:/BehaviorShield/TestFolder"
    ]
    
    # Filter only existing dirs
    watch_dirs = [d for d in watch_dirs if os.path.exists(d)]

    # ── Load custom user-defined protected folders ──
    from database.db import get_connection
    conn = get_connection(DB_PATH)
    try:
        rows = conn.execute("SELECT path FROM protected_folders").fetchall()
        for r in rows:
            p = r["path"]
            if os.path.exists(p) and p not in watch_dirs:
                watch_dirs.append(p)
                logger.info("Watchdog adding user-defined path: %s", p)
    except Exception as e:
        logger.error("Failed to load custom protected folders: %s", e)
    finally:
        conn.close()
    
    observer = start_watchdog(
        watch_dirs=watch_dirs,
        engine=engine,
        sysmon_pid_map=_sysmon_pid_map,
        sysmon_name_map=_sysmon_name_map,
        whitelisted_pids=_whitelisted_pids,
        whitelisted_lock=_whitelisted_lock,
        db_path=DB_PATH
    )
    logger.info("Watchdog (fallback) started for: %s", watch_dirs)

    # 8. Register signals
    try:
        signal.signal(signal.SIGINT,  _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except ValueError:
        # Happens when running in a thread (e.g. via tray_main.py)
        pass

    print("\n  BehaviorShield is running. Press Ctrl+C to stop.\n")
    logger.info("=" * 60)
    logger.info("BehaviorShield v2.0 -- ACTIVE (Hybrid Mode)")
    logger.info("  Primary source : Sysmon Event IDs 1 + 11")
    logger.info("  Fallback source: Watchdog (Deduplicated)")
    logger.info("  DB             : %s", DB_PATH)
    logger.info("  Watching       : %s", watch_dirs)
    logger.info("  Commands       : Type 'q' to quit, 'r' to restart")
    logger.info("=" * 60)

    # 9. Start Command Listener
    cmd_thread = threading.Thread(target=_command_loop, daemon=True, name="CommandListener")
    cmd_thread.start()

    # 10. Main loop
    try:
        while not _shutdown.is_set():
            time.sleep(1)
    finally:
        logger.info("Shutting down...")
        if processor:
            processor.stop()
        process_cache.stop()
        sysmon_reader.stop()
        if observer:
            observer.stop()
            observer.join()
        
        # Reset shutdown for next potential run (in case of restart)
        restart = _restart_requested.is_set()
        _shutdown.clear()
        _restart_requested.clear()
        
        logger.info("BehaviorShield stopped cleanly.")
    
    return restart


if __name__ == "__main__":
    main()
