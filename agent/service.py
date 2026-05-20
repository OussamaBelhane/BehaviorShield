"""
agent/service.py
----------------
BehaviorShield Windows Service -- runs silently at startup under SYSTEM.

Session 0 isolation note:
  This service runs in Windows Session 0 (isolated from user desktop).
  It starts both the detection agent AND the Flask backend on localhost:5000.
  The system tray icon (agent/tray.py) runs in the user session separately
  and communicates with this service via the Flask API.

Install & control:
  python agent/service.py install     # Register as Windows Service
  python agent/service.py start       # Start
  python agent/service.py stop        # Stop
  python agent/service.py remove      # Uninstall
  python agent/service.py debug       # Run in console (no service, good for testing)
"""

import sys
import pathlib
import threading
import logging
import time

# Add project root to path so other modules import correctly
_PROJECT_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import win32serviceutil
import win32service
import win32event
import servicemanager

from agent.config import DB_PATH
from database.db import init_db

# -- Ensure log directory exists BEFORE setting up FileHandler ----
import pathlib as _pathlib
_pathlib.Path("C:/BehaviorShield/logs").mkdir(parents=True, exist_ok=True)

# -- Service-safe logger (writes to Windows Event Log) -----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("C:/BehaviorShield/logs/service.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("BehaviorShield.Service")


class BehaviorShieldService(win32serviceutil.ServiceFramework):
    _svc_name_         = "BehaviorShield"
    _svc_display_name_ = "BehaviorShield Ransomware Protection"
    _svc_description_  = (
        "Real-time behavior-based ransomware detection and response. "
        "Monitors process behavior, scores threats, and kills ransomware automatically."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event     = win32event.CreateEvent(None, 0, 0, None)
        self._agent_thread   = None
        self._flask_thread   = None
        self._sysmon_reader  = None
        self._watchdog_obs   = None

    # -------------------------------------------------------------
    # Service lifecycle
    # -------------------------------------------------------------

    def SvcDoRun(self):
        """Called by SCM when the service starts."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        logger.info("BehaviorShield Service starting...")

        # Ensure all directories exist + DB initialised
        for d in [
            pathlib.Path("C:/BehaviorShield/data"),
            pathlib.Path("C:/BehaviorShield/logs"),
            pathlib.Path("C:/BehaviorShield/Quarantine"),
            pathlib.Path("C:/BehaviorShield/TestFolder"),
        ]:
            d.mkdir(parents=True, exist_ok=True)

        init_db(DB_PATH)

        # Start Flask backend in background thread
        self._flask_thread = threading.Thread(
            target=self._run_flask, name="FlaskBackend", daemon=True
        )
        self._flask_thread.start()
        logger.info("Flask backend thread started")

        # Give Flask a moment to bind to the port
        time.sleep(2)

        # Start detection agent in background thread
        self._agent_thread = threading.Thread(
            target=self._run_agent, name="DetectionAgent", daemon=True
        )
        self._agent_thread.start()
        logger.info("Detection agent thread started")

        logger.info("BehaviorShield Service fully started -- protection active")

        # Wait for stop signal from SCM
        win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)

    def SvcStop(self):
        """Called by SCM when the service is asked to stop."""
        logger.info("BehaviorShield Service stopping...")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        # Signal threads to stop
        if self._sysmon_reader:
            self._sysmon_reader.stop()
        if self._watchdog_obs:
            self._watchdog_obs.stop()
            self._watchdog_obs.join()

        win32event.SetEvent(self._stop_event)
        logger.info("BehaviorShield Service stopped")

    # -------------------------------------------------------------
    # Subsystem launchers (each runs in its own daemon thread)
    # -------------------------------------------------------------

    def _run_flask(self):
        """Start the Flask backend (non-reloading, production-mode)."""
        try:
            from backend.app import create_app
            app = create_app(db_path=str(DB_PATH))
            # use_reloader=False is mandatory in threads
            app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
        except Exception as exc:
            logger.error("Flask thread crashed: %s", exc)

    def _run_agent(self):
        """Start Sysmon reader + watchdog filesystem monitor."""
        try:
            import pathlib as _pl
            from agent.monitor import build_engine, start_watchdog
            from agent.sysmon_reader import SysmonReader
            from database.db import is_learning_mode

            sysmon_pid_map: dict[str, int] = {}
            engine = build_engine(DB_PATH)

            # Sysmon reader
            def on_sysmon_event(event: dict):
                etype = event.get("type")
                if etype == "PROCESS_CREATE":
                    from agent.signature_check import get_signature_status
                    image = event.get("image", "")
                    sig   = get_signature_status(image) if image else "UNKNOWN"
                    engine.register_process(
                        pid=event["pid"], image=image,
                        signature=sig, parent_image=event.get("parent_image", ""),
                    )
                elif etype == "FILE_CREATE":
                    target = event.get("target_file", "")
                    pid    = event.get("pid", 0)
                    if target and pid:
                        sysmon_pid_map[target] = pid
                    engine.process_event({
                        "type": "FILE_CREATE", "pid": pid,
                        "image": event.get("image", ""), "dest_path": target,
                    })

            self._sysmon_reader = SysmonReader(callback=on_sysmon_event)
            self._sysmon_reader.start()

            # Watchdog
            watch_dirs = [
                str(_pl.Path.home()),
                "C:\\Users\\Public",
                "C:\\BehaviorShield\\TestFolder",
            ]
            self._watchdog_obs = start_watchdog(
                watch_dirs, engine, sysmon_pid_map, DB_PATH
            )

            if is_learning_mode(DB_PATH):
                logger.info("Learning mode active -- observing only")
            else:
                logger.info("Protection mode active -- threats will be killed")

            # Keep thread alive until stop signal (wait(5) blocks 5s then returns
            # False if not set -- True when SvcStop fires SetEvent)
            while not self._stop_event.wait(5):
                pass

        except Exception as exc:
            logger.error("Agent thread crashed: %s", exc)


# -- Entry point --------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Called by SCM, not user -- hand off to service manager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(BehaviorShieldService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # User ran: python agent/service.py install / start / stop / remove / debug
        win32serviceutil.HandleCommandLine(BehaviorShieldService)
