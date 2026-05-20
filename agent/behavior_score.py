"""
agent/behavior_score.py
-----------------------
Core scoring engine for BehaviorShield.

Maintains per-PID state and applies 7 behavior rules to determine
threat level. Shadow copy deletion triggers an INSTANT KILL regardless
of total score.
"""

import logging
import threading
import math
from collections import defaultdict, deque, Counter
from datetime import datetime, timezone

from agent.config import (
    SCORE_MASS_RENAME, SCORE_RANSOM_EXTENSION, SCORE_CROSS_DIR_ENCRYPTION,
    SCORE_UNSIGNED_APPDATA, SCORE_READ_WRITE_STORM, SCORE_KNOWN_RANSOM_EXT,
    SCORE_HIGH_ENTROPY, SCORE_SHADOW_COPY_DELETE,
    SCORE_MONITOR, SCORE_ALERT, SCORE_KILL,
    MASS_RENAME_COUNT, MASS_RENAME_WINDOW_SEC,
    READ_WRITE_STORM_COUNT, READ_WRITE_STORM_WINDOW_SEC,
    CROSS_DIR_MIN_DIRS, KNOWN_RANSOM_EXTENSIONS,
    ENTROPY_THRESHOLD, SCORE_KILL_SYNTHETIC,
)

logger = logging.getLogger(__name__)


def _now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def calculate_entropy(path: str) -> float:
    """Calculate Shannon entropy of a file's content (first 4KB for speed)."""
    try:
        with open(path, "rb") as f:
            data = f.read(4096)
        if not data:
            return 0.0
        
        # Shannon Entropy
        entropy = 0
        length = len(data)
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        
        import math
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return entropy
    except (PermissionError, OSError, FileNotFoundError):
        return 0.0
    except Exception as e:
        logger.debug("Entropy calculation error for %s: %s", path, e)
        return 0.0


class ProcessState:
    """Rolling state for a single PID."""

    def __init__(self, pid: int, image: str, signature: str, parent_image: str = "", cmd_line: str = ""):
        self.pid              = pid
        self.image            = image
        self.signature        = signature   # TRUSTED / UNSIGNED / UNKNOWN
        self.parent_image     = parent_image
        self.cmd_line         = cmd_line
        self.score            = 0
        self.hash_verdict     = "unknown"

        # Rolling windows (timestamps)
        self.rename_events    = deque()   # timestamps of rename events
        self.read_events      = deque()   # timestamps of file reads
        self.write_events     = deque()   # timestamps of file writes

        # Directories where encrypted/renamed files were written
        self.encrypted_dirs: set[str] = set()

        # Flags to avoid double-scoring the same rule
        self._scored_mass_rename      = False
        self._scored_cross_dir        = False
        self._scored_read_write_storm = False
        self._scored_unsigned_appdata = False
        self._scored_high_entropy     = False

        # Kill/alert fired flags
        self._kill_fired    = False
        self._alert_fired   = False
        self._monitor_fired = False

        self.first_seen   = _now_iso()
        self.last_updated = _now_iso()

    def _prune(self, dq: deque, window_sec: float) -> None:
        cutoff = _now_ts() - window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()


class BehaviorEngine:
    """
    Thread-safe scoring engine. Call `process_event(event)` from any thread.
    Returns a `ScoringResult` with the updated score and any triggered rules.
    """

    def __init__(self, on_alert=None, on_kill=None, on_instant_kill=None, db_path=None):
        """
        Callbacks:
          on_alert(pid, image, score)         -- score crossed ALERT threshold
          on_kill(pid, image, score)          -- score crossed KILL threshold
          on_instant_kill(pid, image, reason) -- shadow copy deletion detected
        """
        self._states: dict[int, ProcessState] = {}
        self._lock   = threading.Lock()
        self.db_path = db_path

        self.on_alert        = on_alert
        self.on_kill         = on_kill
        self.on_instant_kill = on_instant_kill
        
        self._dir_profile_cache = {} # path -> multiplier

    # -------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------

    def register_process(
        self,
        pid: int,
        image: str,
        signature: str,
        parent_image: str = "",
        cmd_line: str = "",
    ) -> list[dict]:
        """Register a new process from a Sysmon ProcessCreate event."""
        rules = []
        with self._lock:
            if pid not in self._states:
                state = ProcessState(pid, image, signature, parent_image, cmd_line)
                self._states[pid] = state
                logger.debug("Registered PID %d (%s) sig=%s", pid, image, signature)

                # Check immediately if this is an unsigned exe from risky path
                rule = self._check_unsigned_appdata(state)
                if rule:
                    rules.append(rule)
        return rules

    def process_event(self, event: dict) -> list[dict]:
        """
        Process a file event (from Sysmon or watchdog).

        event keys:
          type       -- FILE_RENAME / FILE_CREATE / FILE_MODIFY / SHADOW_COPY_DELETE
          pid        -- process ID (0 = unknown, still processed under bucket pid=-1)
          image      -- process image path (optional, for Sysmon events)
          source_path -- original path (for renames)
          dest_path  -- new path / target file
          signature  -- TRUSTED / UNSIGNED / UNKNOWN (optional)

        Returns a list of triggered rule dicts: [{rule, delta, reason}]
        """
        pid = event.get("pid", 0)

        # Unknown-PID events (watchdog without Sysmon data) are bucketed under
        # the [System Watchdog] state (PID 0) so extension/rename rules still fire.
        if pid is None:
            pid = 0

        with self._lock:
            # Auto-create state if we missed the ProcessCreate event
            if pid not in self._states:
                self._states[pid] = ProcessState(
                    pid,
                    event.get("image", "unknown"),
                    event.get("signature", "UNKNOWN"),
                    cmd_line=event.get("cmd_line", "")
                )
            # Update image on synthetic buckets if we found a better name
            elif pid < 0:
                if event.get("image") and event["image"] != "unknown" and self._states[pid].image == "unknown":
                    self._states[pid].image = event["image"]
                if event.get("cmd_line") and not self._states[pid].cmd_line:
                    self._states[pid].cmd_line = event["cmd_line"]

            state  = self._states[pid]
            rules  = []
            etype  = event.get("type", "")
            
            # [IMPROVEMENT 8] Unified Hash Verdict handling
            if etype == "HASH_VERDICT":
                verdict = event.get("verdict")
                state.hash_verdict = verdict
                if verdict == "malware":
                    rules.append(self._trigger(state, 100, "MALWARE_HASH", f"Hash identified as malware ({event.get('sha256','')[:8]}...)"))
                elif verdict == "unknown":
                    rules.append(self._trigger(state, 5, "SUSPECT_HASH", "Unknown hash verdict (penalty)"))
                self._check_thresholds(state)
                return rules

            dest   = event.get("dest_path") or event.get("target_file", "")
            state.last_updated = _now_iso()

            # [IMPROVEMENT 3] Noise reduction via directory profiling
            multiplier = 1.0
            if dest:
                import pathlib as _pl
                # Ensure backslashes for consistency
                dest_norm = dest.replace("/", "\\")
                dir_path = str(_pl.Path(dest_norm).parent).lower()
                multiplier = self._get_directory_multiplier(dir_path)
                if multiplier < 1.0:
                    logger.debug("Applying multiplier %.2f for trusted noise directory: %s", multiplier, dir_path)

            # -- INSTANT KILL rule -- shadow copy deletion ---------------
            if etype == "SHADOW_COPY_DELETE" or "vssadmin" in event.get("cmd_line", "").lower():
                rules.append(self._trigger(state, SCORE_SHADOW_COPY_DELETE, "SHADOW_COPY_DELETE", "Shadow copy deletion detected"))
                self._fire_instant_kill(state, "Shadow copy deletion")
                return rules

            # -- Rule: Known ransomware extension ----------------------
            ext = self._get_ext(dest)
            if ext and ext.lower() in KNOWN_RANSOM_EXTENSIONS:
                delta = SCORE_KNOWN_RANSOM_EXT
                # Agressive escalation: if already suspicious, make it a kill
                if state.score >= 30:
                    delta = max(delta, SCORE_KILL - state.score + 5)
                rules.append(self._trigger(state, delta, "KNOWN_RANSOM_EXT", f"Known ransomware extension: {ext}", multiplier))

            # -- Rule: Suspicious rename extension ---------------------
            if etype == "FILE_RENAME" and ext and ext.lower() in KNOWN_RANSOM_EXTENSIONS:
                if not any(r["rule"] == "RANSOM_EXTENSION" for r in rules):
                    delta = SCORE_RANSOM_EXTENSION
                    if state.score >= 30:
                        delta = max(delta, SCORE_KILL - state.score + 5)
                    rules.append(self._trigger(state, delta, "RANSOM_EXTENSION", f"Ransomware extension added: {ext}", multiplier))

            # -- Rule: Mass rename -------------------------------------
            if etype == "FILE_RENAME":
                state.rename_events.append(_now_ts())
                state._prune(state.rename_events, MASS_RENAME_WINDOW_SEC)
                if len(state.rename_events) >= MASS_RENAME_COUNT and not state._scored_mass_rename:
                    state._scored_mass_rename = True
                    rules.append(self._trigger(state, SCORE_MASS_RENAME, "MASS_RENAME",
                                               f"{len(state.rename_events)} renames in {MASS_RENAME_WINDOW_SEC}s", multiplier))

            # -- Rule: Cross-directory encryption ---------------------
            if dest and (etype in ("FILE_CREATE", "FILE_RENAME", "FILE_MODIFY")):
                import pathlib as _pl
                parent = str(_pl.Path(dest).parent).lower()
                if ext and ext.lower() in KNOWN_RANSOM_EXTENSIONS:
                    state.encrypted_dirs.add(parent)
                    if len(state.encrypted_dirs) >= CROSS_DIR_MIN_DIRS and not state._scored_cross_dir:
                        state._scored_cross_dir = True
                        rules.append(self._trigger(state, SCORE_CROSS_DIR_ENCRYPTION, "CROSS_DIR_ENCRYPTION",
                                                   f"Encrypted files in {len(state.encrypted_dirs)} directories", multiplier))

            # -- Rule: Read + write storm ------------------------------
            if etype in ("FILE_CREATE", "FILE_MODIFY"):
                state.write_events.append(_now_ts())
                state._prune(state.write_events, READ_WRITE_STORM_WINDOW_SEC)

            if etype == "FILE_READ":
                state.read_events.append(_now_ts())
                state._prune(state.read_events, READ_WRITE_STORM_WINDOW_SEC)

            if (len(state.write_events) + len(state.read_events) >= READ_WRITE_STORM_COUNT
                    and not state._scored_read_write_storm):
                state._scored_read_write_storm = True
                rules.append(self._trigger(state, SCORE_READ_WRITE_STORM, "READ_WRITE_STORM",
                                           f"{len(state.read_events)} reads + {len(state.write_events)} writes in {READ_WRITE_STORM_WINDOW_SEC}s", multiplier))

            # -- Rule: High Entropy (R7) -------------------------------
            if etype in ("FILE_CREATE", "FILE_MODIFY") and not state._scored_high_entropy:
                entropy = calculate_entropy(dest)
                if entropy >= ENTROPY_THRESHOLD:
                    state._scored_high_entropy = True
                    rules.append(self._trigger(state, SCORE_HIGH_ENTROPY, "HIGH_ENTROPY", 
                                                f"High entropy detected: {entropy:.2f} (>{ENTROPY_THRESHOLD})", multiplier))
            
            # [IMPROVEMENT 3] Learning Profile update
            if dest:
                self._update_directory_profile(dir_path)

            # -- Fire threshold callbacks -------------------------------
            self._check_thresholds(state)

        return rules

    # -------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------

    def _trigger(self, state: ProcessState, delta: int, rule: str, reason: str, multiplier: float = 1.0) -> dict:
        actual_delta = int(delta * multiplier)
        state.score += actual_delta
        logger.info("PID %d [%s] +%d -> score=%d (%s)",
                    state.pid, state.image, actual_delta, state.score, reason)
        return {
            "rule":      rule,
            "delta":     actual_delta,
            "reason":    reason,
            "score":     state.score,
            "pid":       state.pid,
            "image":     state.image,
            "timestamp": _now_iso(),
        }

    def _update_directory_profile(self, path: str):
        """[IMPROVEMENT 3] Background learning for directory noise."""
        from database.db import get_connection
        conn = get_connection(self.db_path)
        try:
            with conn:
                conn.execute("""
                    INSERT INTO directory_profiles (path, event_count, last_updated)
                    VALUES (?, 1, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        event_count = event_count + 1,
                        last_updated = excluded.last_updated
                """, (path, _now_iso()))
                
                # Check for "trusted noise" threshold
                # If > 1000 events and not marked trusted yet
                row = conn.execute("SELECT event_count, trusted FROM directory_profiles WHERE path = ?", (path,)).fetchone()
                if row and row["event_count"] >= 1000 and not row["trusted"]:
                    conn.execute("UPDATE directory_profiles SET trusted = 1 WHERE path = ?", (path,))
                    logger.info("Directory %s marked as TRUSTED NOISE (over 1000 events).", path)
                    self._dir_profile_cache[path] = 0.1
        except Exception as e:
            logger.debug("Error updating directory profile for %s: %s", path, e)
        finally:
            conn.close()

    def _check_unsigned_appdata(self, state: ProcessState) -> dict | None:
        from agent.config import is_risky_path
        if state.signature in ("UNSIGNED", "UNKNOWN"):
            if is_risky_path(state.image):
                event = {
                    "rule":      "UNSIGNED_APPDATA",
                    "delta":     SCORE_UNSIGNED_APPDATA,
                    "reason":    f"Unsigned exe from risky path: {state.image}",
                    "score":     state.score + SCORE_UNSIGNED_APPDATA,
                    "pid":       state.pid,
                    "image":     state.image,
                    "timestamp": _now_iso(),
                }
                state.score += SCORE_UNSIGNED_APPDATA
                state._scored_unsigned_appdata = True
                logger.info("PID %d [%s] +%d -> score=%d (UNSIGNED_APPDATA)",
                            state.pid, state.image, SCORE_UNSIGNED_APPDATA, state.score)
                return event
        return None

    # -- [IMPROVEMENT 3] Directory Profile Multiplier --------------------
    
    _dir_profile_cache = {} # path -> multiplier
    
    def _get_directory_multiplier(self, path: str) -> float:
        """Return 0.1 if directory is marked as trusted noise in DB, else 1.0."""
        if path in self._dir_profile_cache:
            return self._dir_profile_cache[path]
        
        from database.db import get_connection
        conn = get_connection(self.db_path)
        try:
            row = conn.execute("SELECT trusted FROM directory_profiles WHERE path = ?", (path,)).fetchone()
            mult = 0.1 if row and row["trusted"] else 1.0
            self._dir_profile_cache[path] = mult
            return mult
        except Exception:
            return 1.0
        finally:
            conn.close()

    def _check_thresholds(self, state: ProcessState) -> None:
        score = state.score
        
        # Determine kill threshold: higher for synthetic buckets (pid < -1000)
        is_synthetic = state.pid < -1000
        kill_threshold = SCORE_KILL_SYNTHETIC if is_synthetic else SCORE_KILL

        if score >= kill_threshold:
            if not state._kill_fired and self.on_kill:
                # Special rule: Synthetic kills ONLY if process name is resolved (not "unknown")
                if is_synthetic and state.image == "unknown":
                    logger.warning("[THRESHOLD WARNING] Synthetic bucket %d reached kill threshold (%d) but process name is UNKNOWN. Skipping kill.", 
                                   state.pid, score)
                    return

                state._kill_fired    = True
                state._alert_fired   = True   # suppress lower alerts
                state._monitor_fired = True
                if is_synthetic:
                    logger.warning("[SYNTHETIC KILL] Triggering kill for synthetic bucket %d [%s] score=%d", 
                                   state.pid, state.image, score)
                self.on_kill(state.pid, state.image, score)
        elif score >= SCORE_ALERT:
            if not state._alert_fired and self.on_alert:
                state._alert_fired   = True
                state._monitor_fired = True
                self.on_alert(state.pid, state.image, score)
        elif score >= SCORE_MONITOR:
            if not state._monitor_fired:
                state._monitor_fired = True
                logger.info("[SURVEILLANCE] PID %d [%s] score=%d", state.pid, state.image, score)
                if self.on_alert:
                    # Pass a flag or just use the score to distinguish in consumer
                    self.on_alert(state.pid, state.image, score)

    def _fire_instant_kill(self, state: ProcessState, reason: str) -> None:
        if self.on_instant_kill:
            self.on_instant_kill(state.pid, state.image, reason)

    @staticmethod
    def _get_ext(path: str) -> str:
        if not path:
            return ""
        import pathlib as _pl
        return _pl.Path(path).suffix

    def get_score(self, pid: int) -> int:
        with self._lock:
            return self._states[pid].score if pid in self._states else 0

    def reset_state(self, pid: int) -> None:
        """Remove state for a PID (e.g. after a kill or for stale unknown-bucket reset)."""
        with self._lock:
            self._states.pop(pid, None)

    def get_all_states(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "pid":          s.pid,
                    "image":        s.image,
                    "signature":    s.signature,
                    "score":        s.score,
                    "first_seen":   s.first_seen,
                    "last_updated": s.last_updated,
                }
                for s in self._states.values()
            ]
