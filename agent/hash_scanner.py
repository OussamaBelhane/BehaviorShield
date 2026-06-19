"""
agent/hash_scanner.py
---------------------
Hash-based threat intelligence for BehaviorShield.

Pipeline (runs in a background thread -- never blocks the agent):
  1. Compute SHA-256 of the exe
  2. Check hash_cache table (SQLite)  -> HIT -> return cached result
  3. Check local malware hash DB      -> MALWARE -> save + alert
  4. Check WinVerifyTrust signature    -> TRUSTED -> CLEAN
  5. Call VirusTotal API (async)       -> CLEAN / MALWARE / UNKNOWN
  6. Save result to hash_cache permanently  (never expires)

Learning mode actions:
  CLEAN   -> whitelist + ignore
  MALWARE -> CRITICAL alert, flag red, do NOT kill
  UNKNOWN -> pass to behavior engine, watch only
"""

import hashlib
import logging
import pathlib
import threading
import time
import queue
from datetime import datetime, timezone

import requests

from agent.config import (
    DB_PATH, VT_API_KEY, VT_ENABLED, LOCAL_HASH_DB_PATH,
    HASH_SCAN_ENABLED, SKIP_SCAN_PATHS,
)
from database.db import get_connection

logger = logging.getLogger(__name__)

# -- Local malware hash set (loaded once at startup) --------------------------

_local_malware_hashes: dict[str, tuple[str, int]] = {} # sha256 -> (family, severity)
_local_hash_lock = threading.Lock()

# Interval for background database reloading
RELOAD_INTERVAL_SEC = 300  # 5 minutes


def _load_local_db() -> None:
    """Load plain-text malware hashes (sha256:family:severity) into a dict."""
    global _local_malware_hashes
    path = LOCAL_HASH_DB_PATH
    if not pathlib.Path(path).exists():
        logger.warning("Local hash DB not found at %s -- continuing without it", path)
        return

    hashes = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split(":")
                sha = parts[0].lower()
                family = parts[1] if len(parts) > 1 else "Unknown"
                try:
                    severity = int(parts[2]) if len(parts) > 2 else 100
                except ValueError:
                    severity = 100
                
                hashes[sha] = (family, severity)
        
        with _local_hash_lock:
            _local_malware_hashes = hashes
            
        logger.info("Loaded %d malware hashes from local DB", len(hashes))
    except Exception as exc:
        logger.error("Failed to load local hash DB: %s", exc)


def _remote_update_loop() -> None:
    """[IMPROVEMENT 2] Background thread that downloads updated hash list every 24 hours."""
    from agent.config import REMOTE_HASH_DB_URL, HASH_UPDATE_INTERVAL
    while True:
        try:
            logger.info("Checking for remote malware hash updates from %s...", REMOTE_HASH_DB_URL)
            resp = requests.get(REMOTE_HASH_DB_URL, timeout=30)
            if resp.status_code == 200:
                # Merge with local file
                path = LOCAL_HASH_DB_PATH
                path.parent.mkdir(parents=True, exist_ok=True)
                
                existing = set()
                if path.exists():
                    existing = set(path.read_text(encoding="utf-8").splitlines())
                
                new_hashes = set(resp.text.splitlines())
                merged = existing.union(new_hashes)
                
                path.write_text("\n".join(sorted(merged)), encoding="utf-8")
                logger.info("Successfully merged %d new hashes from remote source.", len(new_hashes))
                _load_local_db()
            else:
                logger.warning("Remote hash update failed: HTTP %d", resp.status_code)
        except Exception as e:
            logger.error("Error during remote hash update: %s", e)
        
        time.sleep(HASH_UPDATE_INTERVAL)


def _reload_loop() -> None:
    """Background thread that reloads the local DB periodically."""
    while True:
        time.sleep(RELOAD_INTERVAL_SEC)
        try:
            _load_local_db()
        except Exception:
            pass


# Load on import and start threads
_load_local_db()
threading.Thread(target=_reload_loop, daemon=True, name="HashReloader").start()
threading.Thread(target=_remote_update_loop, daemon=True, name="RemoteHashUpdater").start()


# -- VirusTotal rate limiter --------------------------------------------------
# Free tier: 4 requests per minute

_vt_lock = threading.Lock()
_vt_timestamps: list[float] = []
VT_MAX_PER_MIN = 4


def _vt_rate_wait() -> None:
    """Block until we can make a VT API call within rate limits."""
    with _vt_lock:
        now = time.monotonic()
        # Remove timestamps older than 60s
        _vt_timestamps[:] = [t for t in _vt_timestamps if now - t < 60]
        if len(_vt_timestamps) >= VT_MAX_PER_MIN:
            wait = 60 - (now - _vt_timestamps[0])
            if wait > 0:
                logger.info("VT rate limit -- waiting %.1fs", wait)
                time.sleep(wait)
        _vt_timestamps.append(time.monotonic())


# -- Core functions -----------------------------------------------------------

def get_sha256(exe_path: str) -> str | None:
    """
    Compute SHA-256 of a file.
    Returns None if file is locked / inaccessible / deleted.
    """
    try:
        h = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError, FileNotFoundError):
        return None


def is_cached(sha256: str, db_path=None) -> dict | None:
    """
    Check hash_cache table.
    Returns dict with result/source/vt_score if found, else None.
    """
    conn = get_connection(db_path or DB_PATH)
    try:
        row = conn.execute(
            "SELECT result, source, vt_score, scanned_at FROM hash_cache WHERE sha256 = ?",
            (sha256.lower(),),
        ).fetchone()
        if row:
            return {
                "result": row["result"],
                "source": row["source"],
                "vt_score": row["vt_score"],
                "scanned_at": row["scanned_at"],
            }
        return None
    finally:
        conn.close()


def check_local_db(sha256: str) -> tuple[str, int]:
    """
    Check against local malware hash list.
    Returns (family, severity) if found, else ("unknown", 0).
    """
    with _local_hash_lock:
        res = _local_malware_hashes.get(sha256.lower())
        if res:
            return res # (family, severity)
    return ("unknown", 0)


def check_virustotal(sha256: str) -> tuple[str, str | None]:
    """
    Query VirusTotal API v3 for a hash.

    Returns (result, vt_score) where:
      result   = "clean" | "malware" | "unknown"
      vt_score = "X/Y" format or None

    Handles: no API key, no internet, rate limit, timeout, 404.
    """
    if not VT_ENABLED or not VT_API_KEY:
        if not VT_API_KEY:
            logger.debug("VirusTotal scan skipped: API key not configured (set VT_API_KEY environment variable).")
        return ("unknown", None)

    _vt_rate_wait()

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 404:
            # Hash not in VT database
            return ("unknown", None)

        if resp.status_code == 429:
            # Rate limited -- wait 60s and retry once
            logger.warning("VT 429 rate limit -- waiting 60s for retry")
            time.sleep(60)
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code != 200:
                return ("unknown", None)

        if resp.status_code != 200:
            logger.warning("VT returned %d for %s", resp.status_code, sha256[:16])
            return ("unknown", None)

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        vt_score = f"{malicious}/{total}"

        if malicious >= 3:
            return ("malware", vt_score)
        elif malicious == 0 and suspicious == 0:
            return ("clean", vt_score)
        else:
            return ("unknown", vt_score)

    except requests.exceptions.ConnectionError:
        logger.warning("VT: no internet connection -- skipping")
        return ("unknown", None)
    except requests.exceptions.Timeout:
        logger.warning("VT: timeout for %s -- skipping", sha256[:16])
        return ("unknown", None)
    except Exception as exc:
        logger.error("VT error for %s: %s", sha256[:16], exc)
        return ("unknown", None)



def _save_to_cache(
    sha256: str, exe_path: str, result: str,
    source: str, vt_score: str | None = None, db_path=None,
) -> None:
    """Persist a scan result to the hash_cache table."""
    conn = get_connection(db_path or DB_PATH)
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO hash_cache
                    (sha256, exe_path, result, source, vt_score, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sha256.lower(), exe_path, result, source,
                    vt_score,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    except Exception as exc:
        logger.error("Failed to save hash cache: %s", exc)
    finally:
        conn.close()


def _create_alert(
    pid: int, image: str, sha256: str, result: str,
    vt_score: str | None = None, db_path=None,
) -> None:
    """Insert a MALWARE_HASH alert into the alerts table."""
    conn = get_connection(db_path or DB_PATH)
    try:
        score_info = f" (VT: {vt_score})" if vt_score else ""
        with conn:
            conn.execute(
                """
                INSERT INTO alerts
                    (pid, image_path, alert_type, score, message, timestamp)
                VALUES (?, ?, 'MALWARE_HASH', 100, ?, ?)
                """,
                (
                    pid, image,
                    f"Known malware hash detected{score_info}: {sha256}",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    except Exception as exc:
        logger.error("Failed to create malware alert: %s", exc)
    finally:
        conn.close()


def _whitelist_clean(exe_path: str, sha256: str, is_system: bool = False, db_path=None) -> None:
    """Add a clean process to the whitelist table."""
    from agent.whitelist import add_to_whitelist
    add_to_whitelist(
        exe_path, vendor="SYSTEM (Signature)",
        reason=f"Clean hash scan (sha256={sha256[:16]}...)",
        is_system=is_system,
        sha256=sha256,
        db_path=db_path,
    )


def _persist_process(
    pid: int, image: str, sha256: str, sig: str,
    verdict: str, parent_image: str, db_path=None,
) -> None:
    """Insert a process row in the DB with hash verdict."""
    conn = get_connection(db_path or DB_PATH)
    try:
        now = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute(
                """
                INSERT INTO processes
                    (pid, image_path, image_sha256, parent_image,
                     signature_status, hash_verdict, score, status,
                     first_seen, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, 0, 'ACTIVE', ?, ?)
                """,
                (pid, image, sha256 or None, parent_image, sig, verdict, now, now),
            )
    except Exception:
        pass  # PID may already exist
    finally:
        conn.close()


def _handle_result(
    result: str, exe_path: str, sha256: str, pid: int,
    mode: str, vt_score: str | None, source: str, db_path=None,
    silent: bool = False, engine=None
) -> None:
    """
    Take mode-appropriate action based on scan result.
    [IMPROVEMENT 8] Integrated with behavior engine for unified response.
    """
    from agent.config import SILENT_MODE
    effective_db = db_path or DB_PATH
    is_silent = silent or SILENT_MODE

    if result == "clean":
        if source == "signature":
            # Auto-whitelist if we have a valid, trusted Authenticode signature
            from agent.config import NEVER_WHITELIST
            basename = pathlib.Path(exe_path).name.lower()
            if basename in NEVER_WHITELIST:
                logger.info(
                    "SCAN TRUSTED (IGNORED): PID %d [%s] -> valid signature but in NEVER_WHITELIST",
                    pid, pathlib.Path(exe_path).name,
                )
            else:
                _whitelist_clean(exe_path, sha256, is_system=True, db_path=effective_db)
                if not is_silent:
                    logger.info(
                        "SCAN TRUSTED: PID %d [%s] -> whitelisted (valid signature)",
                        pid, pathlib.Path(exe_path).name,
                    )
        else:
            # VT clean or other sources: DO NOT WHITELIST, just log and watch
            if not is_silent:
                logger.info(
                    "SCAN CLEAN (Non-Signed): PID %d [%s] -> watching behavior (source=%s)",
                    pid, pathlib.Path(exe_path).name, source,
                )

    elif result == "malware":
        # [IMPROVEMENT 8] Notify engine with special hash verdict event
        if engine:
            logger.critical(
                "💀 SCAN MALWARE: PID %d [%s] hash=%s... -- Unified alerting via Engine",
                pid, pathlib.Path(exe_path).name, sha256[:16],
            )
            engine.process_event({
                "type": "HASH_VERDICT",
                "verdict": "malware",
                "pid": pid,
                "image": exe_path,
                "sha256": sha256,
                "source": source,
                "vt_score": vt_score
            })
        
        # Always KILL and QUARANTINE instantly for positive hash scans, even in learning mode!
        logger.critical(
            "💀 SCAN MALWARE: PID %d [%s] hash=%s... -- ENGAGING INSTANT HASH KILL",
            pid, pathlib.Path(exe_path).name, sha256[:16],
        )
        
        from agent.process_killer import kill_process
        kill_process(
            pid=pid,
            image=exe_path,
            score=100,
            reason=f"Hash identified as malware ({sha256[:8]}...)",
            written_files=None,  # kill_process will auto-discover files from events table
            db_path=effective_db,
            bypass_learning_mode=True
        )

    else:  # unknown
        # Pass to behavior engine -- scanning found nothing conclusive
        if engine:
            # [IMPROVEMENT 8] Register suspect penalty
            engine.process_event({
                "type": "HASH_VERDICT",
                "verdict": "unknown",
                "pid": pid,
                "image": exe_path
            })
        if not is_silent:
            logger.info(
                "SCAN UNKNOWN: PID %d [%s] hash=%s... -- watching behavior",
                pid, pathlib.Path(exe_path).name, sha256[:16],
            )


# -- Main scan pipeline -------------------------------------------------------

# -- [IMPROVEMENT 6] Scan Retry Queue -------------------------------------------
_retry_queue = queue.Queue()

def _retry_worker(db_path=None, engine=None):
    """Background thread that retries scans for previously locked files."""
    while True:
        try:
            task = _retry_queue.get()
            if task is None: break
            
            path = task["path"]
            pid = task["pid"]
            attempts = task["attempts"]
            
            time.sleep(0.5) # Wait 500ms before retry
            
            # Retry scan
            res = scan(path, pid, task["mode"], task["sig"], task["parent"], db_path, engine=engine, _retry_attempt=attempts)
            if res == "retry_queued" and attempts < 3:
                # Still locked, re-queue if attempts < 3
                task["attempts"] += 1
                _retry_queue.put(task)
            
            _retry_queue.task_done()
        except Exception as e:
            logger.error("Retry worker error: %s", e)

# Start retry worker
threading.Thread(target=_retry_worker, daemon=True, name="ScanRetryWorker").start()

def should_skip_path(exe_path: str) -> bool:
    """Return True if exe_path is in a trusted directory or has an excluded extension."""
    p = exe_path.lower().replace("/", "\\")
    
    # Check for excluded extensions
    if p.endswith(".ico"):
        return True
        
    for skip in SKIP_SCAN_PATHS:
        if p.startswith(skip.lower()):
            return True
    return False


def scan(
    exe_path: str,
    pid: int = 0,
    mode: str = "learning",
    signature: str = "UNKNOWN",
    parent_image: str = "",
    db_path=None,
    silent: bool = False,
    engine=None,
    _retry_attempt: int = 0
) -> str:
    if not HASH_SCAN_ENABLED:
        return "unknown"

    from agent.config import SILENT_MODE
    effective_db = db_path or DB_PATH
    is_silent = silent or SILENT_MODE

    # -- FAST PATH WHITELIST CHECK BEFORE DOING ANY WORK ----------------
    from agent.whitelist import is_whitelisted_by_path, is_whitelisted
    if is_whitelisted_by_path(exe_path, effective_db):
        logger.debug("Hash scan: %s already whitelisted by path -- skipping", exe_path)
        return "whitelisted"

    # -- STEP 0: Compute SHA-256 ----------------------------------
    sha = get_sha256(exe_path)
    if not sha:
        if _retry_attempt == 0 and pid > 0:
            # [IMPROVEMENT 6] Queue for retry if it's the first attempt and we have a PID
            logger.debug("Hash scan: file locked %s -- queuing for retry", exe_path)
            _retry_queue.put({
                "path": exe_path, "pid": pid, "mode": mode, 
                "sig": signature, "parent": parent_image, "attempts": 1
            })
            return "retry_queued"
            
        logger.debug("Hash scan: unreadable file %s -- skipping", exe_path)
        return "unknown"

    # -- HASH WHITELIST CHECK -------------------------------------
    if is_whitelisted(exe_path, effective_db, sha256=sha):
        logger.debug("Hash scan: %s already whitelisted by sha256 -- skipping", exe_path)
        return "clean"

    # -- STEP 1: Check cache --------------------------------------
    cached = is_cached(sha, effective_db)
    if cached:
        result = cached["result"]
        source = cached["source"]
        vt_score = cached["vt_score"]
        
        # [IMPROVEMENT 2] Local metadata check override
        local_family, local_sev = check_local_db(sha)
        if result == "clean" and local_sev >= 50:
             logger.warning("Hash cache OVERRIDE: %s is in local malware DB!", sha[:16])
             result = "malware"
             source = "local_db"
             
        if not is_silent:
            logger.debug("Hash cache HIT: %s -> %s (%s)", sha[:16], result, source)
            
        if not is_silent:
            _persist_process(pid, exe_path, sha, signature, result, parent_image, effective_db)
            
        _handle_result(result, exe_path, sha, pid, mode, vt_score, source, effective_db, silent=is_silent, engine=engine)
        return result

    # -- STEP 2: Local Malware DB ---------------------------------
    local_family, local_sev = check_local_db(sha)
    if local_sev >= 50:
        if not is_silent:
            _save_to_cache(sha, exe_path, "malware", "local_db", db_path=effective_db)
            _persist_process(pid, exe_path, sha, signature, "malware", parent_image, effective_db)
        _handle_result("malware", exe_path, sha, pid, mode, None, f"local_db:{local_family}", effective_db, silent=is_silent, engine=engine)
        return "malware"

    # -- STEP 3: Signature Check ----------------------------------
    if signature == "UNKNOWN":
        from agent.signature_check import get_signature_status
        signature = get_signature_status(exe_path)

    if signature == "TRUSTED":
        if not is_silent:
            _save_to_cache(sha, exe_path, "clean", "signature", db_path=effective_db)
            _persist_process(pid, exe_path, sha, signature, "clean", parent_image, effective_db)
        _handle_result("clean", exe_path, sha, pid, mode, None, "signature", effective_db, silent=is_silent, engine=engine)
        return "clean"

    # -- STEP 4: VirusTotal ---------------------------------------
    vt_result, vt_score = check_virustotal(sha)
    if vt_result != "unknown":
        if not is_silent:
            _save_to_cache(sha, exe_path, vt_result, "virustotal", vt_score, effective_db)
            _persist_process(pid, exe_path, sha, signature, vt_result, parent_image, effective_db)
        _handle_result(vt_result, exe_path, sha, pid, mode, vt_score, "virustotal", effective_db, silent=is_silent, engine=engine)
        return vt_result

    # -- STEP 5: Unknown ------------------------------------------
    if not is_silent:
        _save_to_cache(sha, exe_path, "unknown", "local_db", db_path=effective_db)
        _persist_process(pid, exe_path, sha, signature, "unknown", parent_image, effective_db)
    _handle_result("unknown", exe_path, sha, pid, mode, None, "local_db", effective_db, silent=is_silent, engine=engine)
    return "unknown"





# -- Async scan wrapper (non-blocking) ----------------------------------------

def scan_async(
    exe_path: str,
    pid: int = 0,
    mode: str = "learning",
    signature: str = "UNKNOWN",
    parent_image: str = "",
    db_path=None,
    callback=None,
    engine=None
) -> None:
    """
    Run scan() in a background thread. Never blocks the calling thread.
    [IMPROVEMENT 6] Handles inaccessible files via retry queue in scan().
    """
    if not HASH_SCAN_ENABLED:
        return

    def _worker():
        try:
            result = scan(exe_path, pid, mode, signature, parent_image, db_path, engine=engine)
            if callback:
                callback(result)
        except Exception:
            import traceback as _tb
            logger.error("Async hash scan crashed for %s:\n%s", exe_path, _tb.format_exc())

    t = threading.Thread(target=_worker, daemon=True, name=f"hash-scan-{pid}")
    t.start()


# -- Diagnostics --------------------------------------------------------------

def get_cache_stats(db_path=None) -> dict:
    """Return hash cache statistics from the DB."""
    conn = get_connection(db_path or DB_PATH)
    try:
        total   = conn.execute("SELECT COUNT(*) FROM hash_cache").fetchone()[0]
        clean   = conn.execute("SELECT COUNT(*) FROM hash_cache WHERE result='clean'").fetchone()[0]
        malware = conn.execute("SELECT COUNT(*) FROM hash_cache WHERE result='malware'").fetchone()[0]
        unknown = conn.execute("SELECT COUNT(*) FROM hash_cache WHERE result='unknown'").fetchone()[0]
        return {"total": total, "clean": clean, "malware": malware, "unknown": unknown}
    finally:
        conn.close()
