-- BehaviorShield SQLite Schema
-- Always opened with: PRAGMA journal_mode=WAL;

-- ── Tracked processes ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS processes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pid             INTEGER NOT NULL,
    image_path      TEXT    NOT NULL,
    image_sha256    TEXT,
    cmd_line        TEXT,  -- [IMPROVEMENT 3] Command line capture
    parent_pid      INTEGER,
    parent_image    TEXT,
    signature_status TEXT DEFAULT 'UNKNOWN',   -- TRUSTED / UNSIGNED / UNKNOWN
    hash_verdict    TEXT DEFAULT 'UNKNOWN',   -- CLEAN / MALWARE / UNKNOWN
    score           INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'ACTIVE',      -- ACTIVE / KILLED / WHITELISTED
    first_seen      TEXT NOT NULL,
    last_updated    TEXT NOT NULL
);

-- ── File system events ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    process_id      INTEGER REFERENCES processes(id),
    pid             INTEGER,
    process_name    TEXT,            -- resolved at write-time (exe basename e.g. 'spotify.exe')
    event_type      TEXT NOT NULL,   -- RENAME / CREATE / MODIFY / DELETE / EXTENSION_CHANGE
    source_path     TEXT,
    dest_path       TEXT,
    extension       TEXT,
    score_delta     INTEGER DEFAULT 0,
    severity        TEXT DEFAULT 'INFO',   -- INFO / WARNING / CRITICAL
    source          TEXT DEFAULT 'watchdog', -- 'sysmon' (exact PID) | 'watchdog' (best-effort)
    timestamp       TEXT NOT NULL
);

-- ── Migration: add process_name + source to existing databases ───
CREATE TABLE IF NOT EXISTS _migrations (id INTEGER PRIMARY KEY, name TEXT UNIQUE);
INSERT OR IGNORE INTO _migrations VALUES (1, 'add_events_process_name');
INSERT OR IGNORE INTO _migrations VALUES (2, 'add_events_source');

-- ── Alerts ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    process_id      INTEGER REFERENCES processes(id),
    pid             INTEGER,
    image_path      TEXT,
    alert_type      TEXT NOT NULL,   -- SCORE_THRESHOLD / SHADOW_COPY / INSTANT_KILL
    score           INTEGER DEFAULT 0,
    message         TEXT,
    dismissed       INTEGER DEFAULT 0,
    timestamp       TEXT NOT NULL
);

-- ── Quarantine ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path   TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    process_pid     INTEGER,
    process_image   TEXT,
    file_sha256     TEXT,
    status          TEXT DEFAULT 'QUARANTINED',  -- QUARANTINED / RESTORED / DELETED
    reason          TEXT,                        -- human-readable reason for quarantine
    quarantined_at  TEXT NOT NULL,
    resolved_at     TEXT
);

-- ── Signature-based whitelist ────────────────────────────────────
CREATE TABLE IF NOT EXISTS whitelist (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exe_sha256      TEXT NOT NULL UNIQUE,
    exe_path        TEXT,
    cmd_line_pattern TEXT, -- [IMPROVEMENT 4]
    vendor          TEXT,
    reason          TEXT,
    is_system       INTEGER DEFAULT 0,  -- 1 for system auto-added, 0 for user manual
    added_at        TEXT NOT NULL
);

-- ── Directory Profiles (For learning noise reduction) [IMPROVEMENT 3]
CREATE TABLE IF NOT EXISTS directory_profiles (
    path            TEXT PRIMARY KEY,
    trusted         INTEGER DEFAULT 0,
    event_count     INTEGER DEFAULT 0,
    last_updated    TEXT
);

-- ── Learning mode baseline ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS learning_baseline (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exe_sha256      TEXT NOT NULL,
    exe_path        TEXT,
    avg_file_ops    REAL DEFAULT 0,
    max_file_ops    INTEGER DEFAULT 0,
    observation_count INTEGER DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_updated    TEXT NOT NULL
);

-- ── Hash scan cache ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hash_cache (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT UNIQUE NOT NULL,
    exe_path        TEXT,
    result          TEXT NOT NULL DEFAULT 'unknown',  -- clean / malware / unknown
    source          TEXT DEFAULT 'local_db',          -- local_db / virustotal / signature
    vt_score        TEXT,                             -- "X/72" format if from VT, else NULL
    scanned_at      TEXT NOT NULL
);

-- ── System meta (learning mode start time etc) ───────────────────
CREATE TABLE IF NOT EXISTS system_meta (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);

-- ── Agent internal logs ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS system_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    level           TEXT NOT NULL,
    module          TEXT,
    message         TEXT
);

-- ── Protected Folders (Custom Watchdog Paths) ─────────────────────
CREATE TABLE IF NOT EXISTS protected_folders (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    path            TEXT NOT NULL UNIQUE,
    added_at        TEXT NOT NULL
);
