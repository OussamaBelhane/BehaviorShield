"""
tray_main.py
------------
BehaviorShield — All-in-one launcher.

Packaged by PyInstaller into BehaviorShield.exe (console=False, uac_admin=True).

What this does:
  1. Self-elevates to Administrator via ShellExecuteEx if not already elevated.
  2. Starts the Flask backend (port 5000) in a background daemon thread.
  3. Starts the detection agent in a background daemon thread.
  4. Runs the pystray tray icon on the main thread (required on Windows).

Stopping:
  Right-click the tray icon → Exit  (or Stop → then Exit).
  On Exit, both background threads are signalled to stop gracefully.
"""

import ctypes
import sys
import os
import pathlib
import threading
import time
import logging

# ---------------------------------------------------------------------------
# Project root on sys.path (needed whether running from source or from EXE)
# ---------------------------------------------------------------------------
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Logging (minimal — agent/main.py configures the full logging stack)
# ---------------------------------------------------------------------------
log_handlers = [logging.StreamHandler(sys.stdout)]

# If frozen (EXE), also log to a file in the data directory
if getattr(sys, "frozen", False):
    log_dir = pathlib.Path("C:/BehaviorShield/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_handlers.append(logging.FileHandler(log_dir / "launcher.log", encoding="utf-8"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=log_handlers,
)
logger = logging.getLogger("BehaviorShield.Launcher")

def _fatal_error(msg):
    logger.critical(msg)
    if getattr(sys, "frozen", False):
        ctypes.windll.user32.MessageBoxW(0, msg, "BehaviorShield Critical Error", 0x10)
    sys.exit(1)

# ---------------------------------------------------------------------------
# UAC self-elevation
# ---------------------------------------------------------------------------

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _elevate() -> None:
    """Re-launch this process with admin rights via ShellExecuteEx."""
    import subprocess
    exe = sys.executable
    # When frozen by PyInstaller, sys.executable IS the exe
    script = sys.argv[0]
    params = " ".join(f'"{a}"' for a in sys.argv[1:])

    logger.info("Not running as admin — requesting elevation...")
    try:
        import win32api, win32con
        win32api.ShellExecute(
            0,
            "runas",
            exe if getattr(sys, "frozen", False) else exe,
            f'"{script}" {params}' if not getattr(sys, "frozen", False) else params,
            None,
            win32con.SW_SHOWNORMAL,
        )
    except Exception:
        # Fallback: use ctypes ShellExecuteW
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas",
            exe,
            f'"{script}" {params}' if not getattr(sys, "frozen", False) else " ".join(sys.argv[1:]),
            None, 1
        )
    sys.exit(0)  # Exit the un-elevated copy


# ---------------------------------------------------------------------------
# Flask backend thread
# ---------------------------------------------------------------------------

_flask_started = threading.Event()
_flask_thread: threading.Thread | None = None


def _run_flask() -> None:
    try:
        from backend.app import create_app
        from agent.config import DB_PATH
        app = create_app(db_path=str(DB_PATH))
        logger.info("[Flask] Starting backend on http://127.0.0.1:5000 ...")
        _flask_started.set()
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    except Exception as exc:
        logger.error("[Flask] Backend crashed: %s", exc)
        _flask_started.set()  # unblock main thread even on failure


# ---------------------------------------------------------------------------
# Agent thread  (wraps the restart loop from run_agent.py)
# ---------------------------------------------------------------------------

_agent_stop = threading.Event()


def _run_agent() -> None:
    try:
        from agent.main import main as agent_main
        while not _agent_stop.is_set():
            should_restart = agent_main()
            if not should_restart or _agent_stop.is_set():
                break
            logger.info("[Agent] Restarting BehaviorShield...")
            time.sleep(1)
    except Exception as exc:
        logger.error("[Agent] Agent crashed: %s", exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # 1. Ensure we're running as Administrator
    if not _is_admin():
        _elevate()
        return  # _elevate() calls sys.exit(0); this line is never reached

    logger.info("=" * 60)
    logger.info("  BehaviorShield — Tray Launcher starting (Admin)")
    logger.info("=" * 60)

    # 2. Start Flask backend
    global _flask_thread
    _flask_thread = threading.Thread(
        target=_run_flask, name="FlaskBackend", daemon=True
    )
    _flask_thread.start()

    # Wait up to 5 s for Flask to bind
    _flask_started.wait(timeout=5)
    logger.info("[Launcher] Flask backend ready.")

    # 3. Start the detection agent
    agent_thread = threading.Thread(
        target=_run_agent, name="DetectionAgent", daemon=True
    )
    agent_thread.start()
    logger.info("[Launcher] Detection agent started.")

    # 4. Run the tray icon on the MAIN thread (pystray requirement on Windows)
    #    This blocks until the user clicks "Exit".
    try:
        from agent.tray import run_tray
        run_tray()   # blocks here
    except Exception as exc:
        logger.error("[Tray] Tray icon crashed: %s", exc)

    # 5. Graceful shutdown after tray exits
    logger.info("[Launcher] Tray exited — shutting down...")
    _agent_stop.set()

    # Give agent thread 5 s to stop cleanly
    agent_thread.join(timeout=5)
    logger.info("[Launcher] BehaviorShield stopped.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        _fatal_error(f"Launcher crashed during startup:\n\n{e}\n\n{traceback.format_exc()}")
