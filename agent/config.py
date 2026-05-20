"""
agent/config.py
---------------
Central configuration for BehaviorShield.
All thresholds, paths, and tuneable values live here.
"""

import pathlib
import os
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

# ── Scoring thresholds ───────────────────────────────────────────
SCORE_MONITOR = 30       # Surveillance renforcée
SCORE_ALERT   = 50       # Alerte
SCORE_KILL    = 75       # KILL immédiat
SCORE_KILL_SYNTHETIC = 95 # Higher threshold for synthetic buckets (SCORE_KILL + 20)

# ── Behavior rule weights ────────────────────────────────────────
SCORE_MASS_RENAME           = 15   # R1: >10 renames in 10s
SCORE_RANSOM_EXTENSION      = 20   # R2: .locked .encrypted .crypt etc
SCORE_CROSS_DIR_ENCRYPTION  = 20   # R3: Encrypted files span >3 directories
SCORE_UNSIGNED_APPDATA      = 25   # R4: Unsigned .exe from AppData/Temp
SCORE_READ_WRITE_STORM      = 15   # R5: >30 files touched in 10s
SCORE_KNOWN_RANSOM_EXT      = 25   # R6: Extension in known ransomware list
SCORE_HIGH_ENTROPY          = 30   # R7: Shannon Entropy > 7.5
SCORE_SHADOW_COPY_DELETE    = 100  # R8: vssadmin delete shadows (INSTANT KILL)

# ── Trigger thresholds ───────────────────────────────────────────
MASS_RENAME_COUNT           = 3    # renames (R1)
MASS_RENAME_WINDOW_SEC      = 10   # seconds (R1)
READ_WRITE_STORM_COUNT      = 10   # files (R5)
READ_WRITE_STORM_WINDOW_SEC = 10   # seconds (R5)
CROSS_DIR_MIN_DIRS          = 2    # distinct parent directories (R3)
ENTROPY_THRESHOLD           = 7.5  # bits (R7)

# ── Known ransomware extensions ──────────────────────────────────
KNOWN_RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".rnsmwr",
    ".cerber", ".locky", ".zepto", ".odin", ".osiris", ".thor",
    ".zzzzz", ".micro", ".aaa", ".abc", ".xyz", ".ttt", ".vvv",
    ".wncry", ".wnry", ".wcry", ".wncrypt", ".wannacry",
    ".petya", ".ryuk", ".maze", ".netwalker", ".revil", ".sodinokibi",
    ".lockbit", ".egregor", ".conti", ".blackcat", ".alphv",
    ".pay2key", ".ransom", ".DECRYPT", ".akira", ".qilin", ".devman",
    ".blacksuit", ".phobos", ".deimos", ".epic", ".dharma", ".wallet",
    ".java", ".encrypt",
}

# ── Risky source paths (dynamic detection) ───────────────────────
def is_risky_path(path_str: str) -> bool:
    """
    Dynamically determine if a path is considered 'risky' (e.g. user profile, temp, network).
    Used to escalate score for unsigned binaries.
    """
    if not path_str: return False
    # Normalize input path
    p = os.path.normcase(os.path.abspath(path_str))
    
    # User Profile (excluding standard safe folders)
    user_profile = os.path.normcase(os.path.abspath(os.getenv("USERPROFILE", "C:\\Users")))
    if p.startswith(user_profile):
        # Exclude standard safe subfolders (normalized)
        safe_subfolders = [
            os.path.normcase(os.path.join(user_profile, s)) 
            for s in ["Desktop", "Documents", "Pictures", "Music", "Videos", "Favorites"]
        ]
        if any(p.startswith(s) for s in safe_subfolders):
            return False
        return True
    
    # Generic Temp / Public paths
    risky_patterns = [
        "appdata\\local\\temp",
        "windows\\temp",
        "users\\public",
        "programdata",
        "\\temp\\",
        "\\tmp\\",
    ]
    if any(r in p for r in risky_patterns):
        return True
        
    # Network Drives (UNC or mapped)
    if p.startswith("\\\\"): return True # UNC
    
    try:
        import win32file
        import win32con
        drive = os.path.splitdrive(path_str)[0] + "\\"
        if drive and len(drive) == 3:
            if win32file.GetDriveType(drive) == win32con.DRIVE_REMOTE:
                return True
    except:
        pass

    return False

# ── Noise filter ──────────────────────────────────────────────────
# Events matching these extensions or path patterns are dropped
# before scoring or DB writes.  Add more as needed.

# Universal extensions -- never ransomware targets
EXCLUDED_EXTENSIONS = {
    ".log",
    ".tmp",
    ".pf",
    ".etl",
    ".db-journal",
    ".db-wal",
    ".db-shm",
    "-journal",
    ".baj",
    ".ico",

    # Game asset files -- never ransomware targets on any PC
    ".wad",
    ".uni",
    ".lockfile",
    ".ok",        # riot status files
}

EXCLUDED_PATH_PATTERNS = {
    # Windows internals -- never touched by ransomware
    "\\windows\\prefetch\\",
    "\\windows\\system32\\winevt\\",
    "\\windows\\softwaredistribution\\",
    "\\windows\\softwareprotectionplatform\\",
    "\\windows\\temp\\",

    # Browser cache -- noise on every PC, never ransomware target
    "\\cache_data\\",
    "\\code cache\\",
    "\\gpucache\\",
    "\\grshadercache\\",
    "\\dawngraphitecache\\",
    "\\dawnwebgpucache\\",
    "\\graphitedawncache\\",
    "\\session storage\\",
    "\\cachestorage\\",
    "\\extension state\\",
    "\\no_vary_search\\",
    "\\gcm store\\",
    "\\shared_proto_db\\",
    "\\indexeddb\\",
}

# ── Watchdog directory exclusion ──────────────────────────────────
# Events where any path segment matches these are ignored entirely.
# This prevents noise from development tools (node_modules, .git, etc).
WATCHDOG_EXCLUDED_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "target", "build", "dist", "debug", "release"
}

# ── Quarantine ───────────────────────────────────────────────────
QUARANTINE_DIR = pathlib.Path("C:/BehaviorShield/Quarantine")
TEST_FOLDER    = pathlib.Path("C:/BehaviorShield/TestFolder")

# ── Database ─────────────────────────────────────────────────────
DB_PATH = pathlib.Path("C:/BehaviorShield/data/behaviorshield.db")
API_TOKEN_PATH = pathlib.Path("C:/BehaviorShield/data/api_token.txt")

# ── Learning mode ────────────────────────────────────────────────
LEARNING_MODE_DAYS = 7

# ── Sysmon event IDs ─────────────────────────────────────────────
SYSMON_CHANNEL     = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROCESS_CREATE = 1
SYSMON_FILE_CREATE    = 11
SYSMON_FILE_RENAME    = 2
SYSMON_FILE_DELETE    = 23
SYSMON_FILE_DELETE_ARCHIVED = 26

# ── Trusted vendors (used in whitelist UI display only) ─────────
TRUSTED_VENDORS = {
    "microsoft corporation",
    "adobe systems",
    "adobe inc",
    "valve corporation",
    "google llc",
    "mozilla corporation",
}

# ── Hash scanning ────────────────────────────────────────────────
HASH_SCAN_ENABLED    = os.getenv("HASH_SCAN_ENABLED", "True").lower() in ("true", "1")

# VirusTotal API Key for threat intelligence lookups.
# SECURITY: This key should be set as a system environment variable (VT_API_KEY),
# and never stored directly in the source code.
VT_API_KEY = os.getenv("VT_API_KEY", "")

# Automatically disable VirusTotal lookups if the API key is missing.
VT_ENABLED = (os.getenv("VT_ENABLED", "True").lower() in ("true", "1")) if VT_API_KEY else False
LOCAL_HASH_DB_PATH   = pathlib.Path(__file__).parent / "hash_db" / "malware_hashes.txt"
REMOTE_HASH_DB_URL   = "https://raw.githubusercontent.com/r-ed-r/BehaviorShield-Hashes/main/malware_hashes.txt" # Example URL
HASH_UPDATE_INTERVAL = 86400 # 24 hours

# ── Silent / Ephemeral Mode ──────────────────────────────────────
# If True, no data is written to disk (DB, cache, logs).
SILENT_MODE = os.getenv("BEHAVIORSHIELD_SILENT", "0") == "1"

# Trusted exe paths -- skip hash scanning entirely
SKIP_SCAN_PATHS = []

# ── Interpreters to never whitelist ──────────────────────────────
# These are LotL (Living off the Land) binaries or interpreters that,
# although digitally signed and trusted, can be used to run arbitrary scripts (like ransomware).
NEVER_WHITELIST = {
    "python.exe", "py.exe", "pythonw.exe", "python3.exe", 
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "node.exe", "java.exe", "javaw.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "bash.exe", "sh.exe", "wsl.exe"
}

# ── Critical system processes to NEVER kill ─────────────────────
# Killing these can cause a Blue Screen of Death (BSOD) or make the UI unusable.
CRITICAL_PROCESSES = {
    "explorer.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "svchost.exe",
    "spoolsv.exe",
    "searchindexer.exe",
    "taskhostw.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "ctfmon.exe",
}
