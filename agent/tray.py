"""
agent/tray.py
-------------
BehaviorShield system tray icon -- runs in the USER session (or embedded in
the all-in-one tray_main.py launcher).

Polls Flask backend (/api/status) every 2 seconds to show live state.
Communicates back to the service/agent through the Flask API only.

Right-click menu:
  🌐 Open Dashboard
  ─────────────────
  ⏸ Stop Protection        (when running)
  ▶ Resume Protection       (when stopped/paused)
  🔄 Reload Agent
  ─────────────────
  ❌ Exit

Usage:
  python agent/tray.py              # Start tray icon manually
  python agent/tray.py --install    # Add to Windows Startup (auto-run at login)
  python agent/tray.py --uninstall  # Remove from Windows Startup
"""

import argparse
import sys
import pathlib
import threading
import time
import webbrowser
import urllib.request
import urllib.error
import json
import logging

logger = logging.getLogger("BehaviorShield.Tray")

# Add project root to path (only if running as script)
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pystray
from PIL import Image, ImageDraw

# -- Constants ----------------------------------------------------
API_BASE       = "http://localhost:5000/api"
DASHBOARD_URL  = "http://localhost:5173"   # React dev server; prod: http://localhost:5000
POLL_INTERVAL  = 2   # seconds
STARTUP_KEY    = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_NAME   = "BehaviorShieldTray"

# Indefinite-stop duration: 1 year in seconds
_STOP_DURATION = 365 * 24 * 3600

# -- Auth ---------------------------------------------------------
from agent.config import API_TOKEN_PATH
try:
    _api_token = API_TOKEN_PATH.read_text(encoding="utf-8").strip()
except Exception:
    _api_token = ""

# -- States (updated by polling thread, read by menu renderer) ----
_state = {
    "connected":       False,
    "learning_mode":   True,
    "days_remaining":  7,
    "active_alerts":   0,
    "killed":          0,
    "paused_until":    0.0,   # epoch time when pause expires (0 = not paused)
    "reloading":       False, # True for ~3s after Reload is clicked
}
_state_lock = threading.Lock()


# -----------------------------------------------------------------
# Icon image -- drawn in-memory with Pillow (no external .ico needed)
# -----------------------------------------------------------------

def _make_icon(color: str = "#0ea5e9", alert: bool = False) -> Image.Image:
    """
    Draw a 64×64 shield icon using Pillow.
      color   -- fill colour (blue=ok, amber=paused, red=alert, grey=offline)
      alert   -- if True, adds a small red dot in the top-right corner
    """
    size  = 64
    img   = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw  = ImageDraw.Draw(img)

    cx, cy = size // 2, size // 2

    # Shield outer shape
    shield_pts = [
        (cx,      4),
        (cx + 24, 10),
        (cx + 24, 34),
        (cx,      60),
        (cx - 24, 34),
        (cx - 24, 10),
    ]
    draw.polygon(shield_pts, fill=color)

    # Inner highlight
    inner_pts = [(x + 2 if x > cx else x - 2, y + 4) for x, y in shield_pts[:-1]]
    draw.polygon(inner_pts, fill=_lighten(color))

    # "BS" text in the middle
    draw.text((cx, cy + 2), "BS", fill="white", anchor="mm")

    # Alert dot (red circle, top-right)
    if alert:
        draw.ellipse([46, 4, 60, 18], fill="#ef4444")

    return img


def _lighten(hex_color: str, factor: float = 0.3) -> str:
    """Lighten a hex colour by blending toward white."""
    hex_color = hex_color.lstrip("#")
    r, g, b   = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    r = int(r + (255 - r) * factor)
    g = int(g + (255 - g) * factor)
    b = int(b + (255 - b) * factor)
    return f"#{r:02x}{g:02x}{b:02x}"


def _icon_for_state() -> Image.Image:
    with _state_lock:
        if not _state["connected"]:
            return _make_icon("#6b7280")                           # grey = offline

        if _state["reloading"]:
            return _make_icon("#6366f1")                           # indigo = reloading

        now = time.time()
        if _state["paused_until"] > now:
            return _make_icon("#f59e0b", alert=False)              # amber = paused/stopped

        if _state["learning_mode"]:
            return _make_icon("#8b5cf6", alert=_state["active_alerts"] > 0)  # purple = learning

        if _state["active_alerts"] > 0:
            return _make_icon("#0ea5e9", alert=True)               # blue + red dot = alerts

        return _make_icon("#22c55e")                               # green = protected + clear


# -----------------------------------------------------------------
# Polling thread -- fetches /api/status every POLL_INTERVAL seconds
# -----------------------------------------------------------------

def _poll_loop(icon: pystray.Icon) -> None:
    while True:
        try:
            req = urllib.request.Request(f"{API_BASE}/status")
            req.add_header("X-API-Token", _api_token)
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
            with _state_lock:
                _state["connected"]     = True
                _state["learning_mode"] = data.get("learning_mode", True)
                _state["days_remaining"] = data.get("days_remaining", 0)
                _state["active_alerts"] = data.get("active_alerts", 0)
                _state["killed"]        = data.get("killed_processes", 0)
                _state["paused_until"]  = data.get("paused_until", 0.0)
        except Exception:
            with _state_lock:
                _state["connected"] = False

        # Update icon image + title
        icon.icon  = _icon_for_state()
        icon.title = _build_tooltip()
        icon.update_menu()

        time.sleep(POLL_INTERVAL)


def _build_tooltip() -> str:
    with _state_lock:
        if not _state["connected"]:
            return "BehaviorShield — Offline (service not running)"

        if _state["reloading"]:
            return "BehaviorShield — Reloading agent..."

        now = time.time()
        if _state["paused_until"] > now:
            # Large pause = "stopped"; short pause = countdown
            secs = int(_state["paused_until"] - now)
            if secs > 86400:
                return "BehaviorShield — Protection Stopped"
            return f"BehaviorShield — Paused ({secs}s remaining)"

        if _state["learning_mode"]:
            return f"BehaviorShield — Learning ({_state['days_remaining']}d remaining)"

        alerts = _state["active_alerts"]
        suffix = f" — ⚠ {alerts} alert{'s' if alerts != 1 else ''}" if alerts else ""
        return f"BehaviorShield — Protected{suffix}"


# -----------------------------------------------------------------
# API helpers
# -----------------------------------------------------------------

def _api_post(path: str, payload: dict | None = None, method: str = "POST") -> bool:
    """POST (or custom method) to the Flask API. Returns True on success."""
    try:
        body = json.dumps(payload).encode("utf-8") if payload else b""
        headers = {
            "Content-Type": "application/json",
            "X-API-Token": _api_token,
        }
        req = urllib.request.Request(
            f"{API_BASE}{path}", data=body, headers=headers, method=method
        )
        with urllib.request.urlopen(req, timeout=3):
            pass
        return True
    except Exception as e:
        print(f"[Tray] API call {path} failed: {e}")
        return False


# -----------------------------------------------------------------
# Menu actions
# -----------------------------------------------------------------

def _open_dashboard(icon, item):
    webbrowser.open(DASHBOARD_URL)


def _stop_protection(icon, item):
    """Pause protection indefinitely (1 year) — effectively a 'Stop'."""
    _api_post("/pause", {"duration": _STOP_DURATION})


def _resume_protection(icon, item):
    """Resume protection immediately."""
    _api_post("/resume")


def _reload_agent(icon, item):
    """Ask the backend to signal the agent to restart."""
    with _state_lock:
        _state["reloading"] = True
    icon.icon  = _icon_for_state()
    icon.title = "BehaviorShield — Reloading..."

    ok = _api_post("/reload")

    # Clear reloading flag after 4 s whether or not it succeeded
    def _clear_reload():
        time.sleep(4)
        with _state_lock:
            _state["reloading"] = False
    threading.Thread(target=_clear_reload, daemon=True, name="ReloadClear").start()

    if not ok:
        print("[Tray] Reload request failed — is the backend running?")


def _exit_tray(icon, item):
    icon.stop()


# -----------------------------------------------------------------
# Menu builder (called every poll cycle so counts stay fresh)
# -----------------------------------------------------------------

def _build_menu() -> pystray.Menu:
    with _state_lock:
        connected    = _state["connected"]
        learning     = _state["learning_mode"]
        alerts       = _state["active_alerts"]
        days_left    = _state["days_remaining"]
        killed       = _state["killed"]
        now          = time.time()
        paused_until = _state["paused_until"]
        reloading    = _state["reloading"]

    paused = paused_until > now

    # -- Status line -----------------------------------------------
    if not connected:
        status_text = "⚪  Offline — Service not running"
    elif reloading:
        status_text = "🔄  Reloading agent..."
    elif paused:
        secs = int(paused_until - now)
        if secs > 86400:
            status_text = "🔴  Protection Stopped"
        else:
            status_text = f"⏸  Protection Paused ({secs}s)"
    elif learning:
        status_text = f"📚  Learning Mode — {days_left}d remaining"
    elif alerts > 0:
        status_text = f"⚠️   Protected — {alerts} Alert{'s' if alerts != 1 else ''}"
    else:
        status_text = f"🟢  Protected  |  Threats blocked: {killed}"

    items = [
        pystray.MenuItem(status_text, None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("🌐  Open Dashboard", _open_dashboard),
        pystray.Menu.SEPARATOR,
    ]

    # Stop / Resume toggle
    if paused:
        items.append(pystray.MenuItem("▶  Resume Protection", _resume_protection))
    else:
        items.append(pystray.MenuItem("⏹  Stop Protection", _stop_protection))

    items += [
        pystray.MenuItem("🔄  Reload Agent", _reload_agent),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("❌  Exit", _exit_tray),
    ]

    return pystray.Menu(*items)


# -----------------------------------------------------------------
# Startup registry helpers
# -----------------------------------------------------------------

def _install_startup() -> None:
    """Add the tray app to HKCU Run key so it starts at every login."""
    import winreg
    py_exe    = sys.executable
    tray_path = str(pathlib.Path(__file__).resolve())
    cmd       = f'"{py_exe}" "{tray_path}"'

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, STARTUP_NAME, 0, winreg.REG_SZ, cmd)

    print(f"[OK] BehaviorShield Tray added to Windows Startup.")
    print(f"   Command: {cmd}")


def _uninstall_startup() -> None:
    """Remove from startup registry."""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, STARTUP_NAME)
        print("[OK] BehaviorShield Tray removed from Windows Startup.")
    except FileNotFoundError:
        print("[i]  Entry not found in registry -- nothing to remove.")


# -----------------------------------------------------------------
# Public entry point (also called from tray_main.py)
# -----------------------------------------------------------------

def run_tray() -> None:
    """Start the pystray icon. Blocks until icon.stop() is called."""
    icon = pystray.Icon(
        name   = "BehaviorShield",
        icon   = _make_icon("#6b7280"),   # grey until first poll succeeds
        title  = "BehaviorShield — Connecting...",
        menu   = _build_menu(),
    )

    def on_setup(icon):
        icon.visible = True
        # Start polling thread AFTER icon is ready
        poll_thread = threading.Thread(
            target=_poll_loop, args=(icon,), name="TrayPoller", daemon=True
        )
        poll_thread.start()
        
        try:
            icon.notify("BehaviorShield is now active in the system tray.", "Protection Active")
        except:
            pass

    print("[SHIELD] BehaviorShield tray icon running — check your system tray.")
    icon.run(setup=on_setup)


def main() -> None:
    parser = argparse.ArgumentParser(description="BehaviorShield system tray icon")
    parser.add_argument("--install",   action="store_true", help="Add to Windows Startup registry")
    parser.add_argument("--uninstall", action="store_true", help="Remove from Windows Startup registry")
    args = parser.parse_args()

    if args.install:
        _install_startup()
        return
    if args.uninstall:
        _uninstall_startup()
        return

    run_tray()


if __name__ == "__main__":
    main()
