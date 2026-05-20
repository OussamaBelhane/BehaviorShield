"""
agent/event_processor.py
-------------------------
Asynchronous event processing pipeline for BehaviorShield.

Architecture:
1.  Reception: Sysmon/Watchdog receive events and push to `event_queue`.
2.  Scoring (Immediate): `_scoring_worker` pulls from `event_queue`, 
    runs BehaviorEngine, and puts result into `db_batch_queue`.
3.  Persistence (Batch): `_db_flusher_worker` collects events from `db_batch_queue`
    and writes them to the DB in batches every 500ms.
"""

import logging
import queue
import threading
import time
import pathlib
from datetime import datetime, timezone
from agent import config
from agent.config import DB_PATH
from database.db import get_connection, is_learning_mode, is_whitelist_enabled

logger = logging.getLogger(__name__)

# Primary queue for incoming raw events
event_queue = queue.Queue()

# Secondary queue for scored events waiting for DB persistence
db_batch_queue = queue.Queue()

class EventProcessor:
    def __init__(self, engine, db_path=None):
        self.engine = engine
        self.db_path = db_path or DB_PATH
        self._shutdown = threading.Event()
        
        # Caching settings to avoid DB spam
        self._learning_mode_cache = True
        self._whitelist_enabled_cache = True
        self._is_paused_cache = False
        self._last_cache_sync = 0

        # Threads
        self.scoring_thread = threading.Thread(target=self._scoring_worker, daemon=True, name="EventScorer")
        self.db_thread = threading.Thread(target=self._db_flusher_worker, daemon=True, name="DBFlusher")

    def _sync_settings(self):
        """Sync global settings from DB once every 5 seconds."""
        if config.SILENT_MODE: return # Don't touch DB in silent mode
        
        now = time.monotonic()
        if now - self._last_cache_sync > 5:
            try:
                from database.db import is_paused
                self._learning_mode_cache = is_learning_mode(self.db_path)
                self._whitelist_enabled_cache = is_whitelist_enabled(self.db_path)
                self._is_paused_cache = is_paused(self.db_path)
                self._last_cache_sync = now
            except Exception as e:
                logger.error("Failed to sync settings cache: %s", e)

    def start(self):
        self.scoring_thread.start()
        self.db_thread.start()
        logger.info("EventProcessor started (Scoring + Batch DB Writer)")

    def stop(self):
        self._shutdown.set()
        # Wake up threads
        event_queue.put(None)
        db_batch_queue.put(None)
        self.scoring_thread.join(timeout=2)
        self.db_thread.join(timeout=2)

    def _scoring_worker(self):
        """Consume raw events, score them, and queue for DB."""
        while not self._shutdown.is_set():
            try:
                event = event_queue.get(timeout=1.0)
                if event is None: break
                
                etype = event.get("type")
                # [IMPROVEMENT 7] Skip scoring for progress events
                if etype == "SCAN_PROGRESS":
                    continue

                self._sync_settings()

                # 1. Immediate Whitelist Re-Check (Catch events already in queue when whitelist changed)
                pid = event.get("pid", 0)
                image = event.get("image", "")
                is_whitelisted = event.get("is_whitelisted", False)
                
                if not is_whitelisted and self._whitelist_enabled_cache and image:
                    from agent.whitelist import is_whitelisted_by_path
                    if is_whitelisted_by_path(image, self.db_path):
                        is_whitelisted = True
                
                # Diagnostic log - Now DEBUG to prevent console flooding
                logger.debug("ScoringWorker received %s from %s (PID %s, whitelisted=%s)", 
                            event.get("type"), event.get("source"), pid, is_whitelisted)

                # 2. Skip scoring if SYSTEM IS PAUSED
                if self._is_paused_cache:
                    logger.debug("Skipping scoring for PID %s (Protection is PAUSED)", pid)
                    event["rules"] = []
                    event["scored_at"] = datetime.now(timezone.utc).isoformat()
                    db_batch_queue.put(event)
                    continue

                # 3. Skip scoring if whitelisted OR already scored (startup scans)
                is_prescored = event.get("type") == "PROCESS_SCAN"
                
                rules = event.get("rules", [])
                if not is_whitelisted and not is_prescored:
                    # Score it!
                    rules = self.engine.process_event(event)
                    if rules:
                        logger.info("PID %s triggered rules: %s", pid, [r.get("rule") for r in rules])
                elif is_whitelisted:
                    rules = [{"rule": "whitelisted", "delta": 0, "description": "Process is Whitelisted"}]
                
                # 2. Add scoring results to the event object
                event["rules"] = rules
                event["scored_at"] = datetime.now(timezone.utc).isoformat()
                
                # 3. Queue for DB batching
                db_batch_queue.put(event)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Scoring worker error: %s", e, exc_info=True)
            finally:
                try:
                    event_queue.task_done()
                except ValueError: pass

    def _db_flusher_worker(self):
        """Batch events and write to DB every 500ms."""
        if config.SILENT_MODE:
            logger.info("SILENT MODE: DB flusher worker suspended.")
            while not self._shutdown.is_set():
                try:
                    event = db_batch_queue.get(timeout=1.0)
                    if event is None: break
                    db_batch_queue.task_done()
                except queue.Empty: continue
            return

        batch = []
        last_flush = time.monotonic()
        
        while not self._shutdown.is_set() or not db_batch_queue.empty():
            try:
                # Wait for an event with a timeout to allow periodic flushing
                try:
                    event = db_batch_queue.get(timeout=0.1)
                    if event is None: 
                        if self._shutdown.is_set(): break
                        continue
                    batch.append(event)
                except queue.Empty:
                    pass

                # Flush if batch is large or enough time has passed
                now = time.monotonic()
                if (len(batch) >= 50 or (now - last_flush >= 0.5)) and batch:
                    self._flush_batch(batch)
                    batch = []
                    last_flush = now

            except Exception as e:
                logger.error("DB flusher worker error: %s", e, exc_info=True)
            finally:
                try:
                    db_batch_queue.task_done()
                except ValueError: pass

    def _flush_batch(self, batch):
        """Perform a single bulk INSERT transaction and update process scores."""
        if config.SILENT_MODE: return
        conn = get_connection(self.db_path or config.DB_PATH)
        try:
            with conn:
                for event in batch:
                    # 1. Calculate total delta
                    rules = event.get("rules", [])
                    total_delta = sum(r.get("delta", 0) for r in rules)
                    
                    # 2. Calculate severity
                    sev = "INFO"
                    if total_delta >= 25: sev = "CRITICAL"
                    elif total_delta >= 10: sev = "WARNING"
                    
                    # 3. Resolve file extension
                    path_for_ext = event.get("dest_path") or event.get("source_path") or ""
                    ext = pathlib.Path(path_for_ext).suffix.lower()

                    # 4. INSERT Event
                    pid = event.get("pid", 0)
                    pname = event.get("process_name") or event.get("image")
                    if not pname and (pid == 0 or pid is None):
                        pname = "[System Watchdog]"
                        pid = 0

                    conn.execute(
                        """
                        INSERT INTO events
                            (pid, process_name, event_type, source_path, dest_path, extension,
                             score_delta, severity, source, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            pid,
                            pname,
                            event.get("event_type", "MODIFY"),
                            event.get("source_path"),
                            event.get("dest_path"),
                            ext,
                            total_delta,
                            sev,
                            event.get("source", "watchdog"),
                            event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                        ),
                    )

                    # 5. UPDATE Process Score
                    if total_delta > 0:
                        now = datetime.now(timezone.utc).isoformat()
                        # Ensure process row exists (e.g. if we missed the start event)
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO processes 
                                (pid, image_path, status, first_seen, last_updated)
                            VALUES (?, ?, 'ACTIVE', ?, ?)
                            """,
                            (pid, pname or "unknown", now, now)
                        )
                        # We use the resolved 'pid' which defaults to 0
                        conn.execute(
                            "UPDATE processes SET score = score + ?, last_updated = ? WHERE pid = ?",
                            (total_delta, now, pid)
                        )
            
            if len(batch) > 0:
                logger.debug("Flushed %d events to DB", len(batch))
        except Exception as e:
            logger.error("Batch DB flush failed: %s", e, exc_info=True)
        finally:
            conn.close()
