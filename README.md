# BehaviorShield

**Behavior-based ransomware detection and response system — Final Year Project (PFA)**

> Real-time protection powered by Windows Sysmon event tracing, multi-rule behavior scoring, automatic process termination, and a React dashboard.

---

## Project Structure

```
BehaviorShield/
├── agent/                        # Core detection engine
│   ├── main.py                   # Agent entry point (run as Administrator)
│   ├── tray.py                   # System tray icon (pystray)
│   ├── config.py                 # All thresholds, paths, tunable values
│   ├── behavior_score.py         # 8-rule scoring engine
│   ├── sysmon_reader.py          # Sysmon EvtSubscribe real-time reader
│   ├── monitor.py                # Watchdog FS handler + event router
│   ├── event_processor.py        # Background scoring + DB worker
│   ├── event_writer.py           # Sysmon dedup + DB persistence
│   ├── hash_scanner.py           # SHA-256 + VirusTotal lookup
│   ├── signature_check.py        # WinVerifyTrust via ctypes (no subprocess)
│   ├── process_killer.py         # Kill + quarantine (learning mode aware)
│   ├── process_resolver.py       # PID → image path cache
│   ├── quarantine.py             # Move / restore / delete quarantined files
│   ├── whitelist.py              # Path + SHA-256 based whitelist
│   ├── dedup_alerts.py           # Alert deduplication helper
│   ├── service.py                # Windows Service wrapper
│   └── hash_db/
│       └── malware_hashes.txt    # Local known-bad hash list
│
├── backend/                      # Flask REST API
│   ├── app.py                    # App factory + auth middleware
│   └── routes/
│       ├── alerts.py             # GET/POST /api/alerts
│       ├── control.py            # POST /api/reload, /api/stop
│       ├── events.py             # GET /api/events
│       ├── hash_results.py       # GET /api/hash_results
│       ├── pause.py              # POST /api/pause, /api/resume
│       ├── quarantine.py         # GET/POST /api/quarantine
│       ├── reports.py            # GET /api/reports/generate (PDF)
│       ├── settings.py           # GET/POST /api/settings
│       ├── status.py             # GET /api/status
│       └── whitelist.py          # GET/POST/DELETE /api/whitelist
│
├── database/
│   ├── db.py                     # Connection factory (WAL mode enforced)
│   └── schema.sql                # SQLite schema (8 tables)
│
├── frontend/                     # React 18 + Vite + Tailwind dashboard
│   ├── src/
│   │   ├── pages/                # Dashboard, Alerts, Quarantine, Whitelist, Reports
│   │   └── components/           # Sidebar, shared UI
│   └── dist/                     # Production build (served by Flask)
│
├── config/
│   └── sysmon.xml                # Recommended Sysmon configuration
│
│
├── docs/                         # Project documentation
│   ├── cahier_des_charges.pdf
│   ├── EMSI.png
│   └── EMSI.svg
│
├── reports/
│   └── report_template.html      # WeasyPrint PDF template
│
├── dist/
│   └── BehaviorShield.exe        # Packaged standalone EXE
│
├── tray_main.py                  # All-in-one launcher → BehaviorShield.exe
├── run_agent.py                  # Dev runner: agent only
├── run_backend.py                # Dev runner: Flask only
├── BehaviorShield.spec           # PyInstaller build spec
├── build.ps1                     # One-click EXE build script
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment variable template
├── .gitignore
└── README.md
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | Run agent as Administrator |
| Microsoft Sysmon | Latest | [Download](https://learn.microsoft.com/sysinternals/downloads/sysmon) |
| Node.js | 20+ | For the React dashboard |

---

## Quick Start — Standalone EXE (Recommended)

```powershell
# Just double-click (or right-click → Run as Administrator):
dist\BehaviorShield.exe
```

The EXE:
- Auto-prompts UAC for elevation
- Starts the Flask backend on port **5000**
- Starts the detection agent
- Shows a shield icon in the **system tray**

**Right-click the tray icon** for:
- 🌐 Open Dashboard
- ⏹ Stop / ▶ Resume Protection
- 🔄 Reload Agent
- ❌ Exit

Then open the React dashboard separately at `http://localhost:5173`.

---

## Development Mode

Open **3 terminals**:

### Terminal 1 — Detection Agent (as Administrator)
```powershell
python run_agent.py
```

### Terminal 2 — Flask Backend
```powershell
python run_backend.py
# API: http://localhost:5000
```

### Terminal 3 — React Dashboard
```powershell
cd frontend
npm run dev
# Dashboard: http://localhost:5173
```

---

## Setup

### 1. Install Python dependencies
```powershell
pip install -r requirements.txt
```

### 2. Configure Sysmon
```powershell
# Install Sysmon with recommended config:
sysmon64.exe -accepteula -i config\sysmon.xml
```

### 3. Install frontend dependencies
```powershell
cd frontend
npm install
```

### 4. Build the EXE (optional)
```powershell
.\build.ps1
# Output: dist\BehaviorShield.exe
```

---

---


## Behavior Score Rules

| Rule | Trigger | Score |
|------|---------|-------|
| R1: Mass rename | >10 renames in 10s | +15 |
| R2: Ransomware extension | `.locked`, `.encrypted`, `.crypt`… | +20 |
| R3: Cross-directory spread | Encrypted files in >3 directories | +20 |
| R4: Unsigned AppData/Temp exe | Unsigned binary from risky path | +25 |
| R5: Read+write storm | >30 files touched in 10s | +15 |
| R6: Known ransomware extension | Matches 40+ known extensions | +25 |
| R7: High entropy | Shannon entropy > 7.5 bits | +30 |
| R8: Shadow copy deletion | `vssadmin delete shadows` | **+100 (INSTANT KILL)** |

**Score bands:** `0–29` Normal · `30–49` Monitor · `50–74` Alert · `75+` Kill

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Agent status, KPIs, learning mode |
| GET | `/api/events` | Paginated filesystem events |
| GET | `/api/alerts` | Threat alerts |
| POST | `/api/alerts/<id>/dismiss` | Dismiss alert |
| POST | `/api/pause` | Pause protection (duration in seconds) |
| POST | `/api/resume` | Resume protection |
| POST | `/api/reload` | Restart detection agent |
| POST | `/api/stop` | Stop protection indefinitely |
| GET | `/api/quarantine` | Quarantined files |
| POST | `/api/quarantine/<id>/restore` | Restore + optional whitelist |
| POST | `/api/quarantine/<id>/delete` | Permanent delete |
| GET | `/api/whitelist` | Trusted processes |
| POST | `/api/whitelist` | Add to whitelist |
| DELETE | `/api/whitelist/<id>` | Remove from whitelist |
| GET | `/api/reports/generate` | Download PDF report |
| GET | `/api/settings` | Get agent settings |
| POST | `/api/settings` | Update agent settings |

---

## Key Design Decisions

- **WinVerifyTrust via ctypes** — zero subprocesses for signature checks
- **Sysmon EvtSubscribe** — real-time process attribution (no polling)
- **SQLite WAL mode** — agent writes while Flask reads concurrently
- **SHA-256 whitelist** — malware cannot bypass by renaming itself `explorer.exe`
- **Learning mode (7 days)** — observes only, never kills; enforced in two places
- **Shadow copy = instant kill** — hardcoded rule separate from the score system
- **Tray EXE** — single file, no console window, UAC auto-elevation, pystray tray icon

---

