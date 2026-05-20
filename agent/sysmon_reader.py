"""
agent/sysmon_reader.py
----------------------
Reads Microsoft Sysmon events in real-time using the Windows Event Log API
(pywin32 / win32evtlog). Uses EvtSubscribe (pull mode, no signal event) and
polls with EvtNext on a 500 ms timeout.

Root cause of Error 6 (invalid handle):
  EvtSubscribeToFutureEvents handles are valid immediately after EvtSubscribe
  returns, but calling EvtNext within the first ~200 ms can return winerror 6
  on many Windows builds before the internal channel binding is ready.
  Fix: sleep 1 s after subscription, and only reconnect after SEVERAL
  consecutive Error 6 responses (not just the first one).

Events consumed:
  ID 1  -- ProcessCreate   (image, pid, parent pid, command line)
  ID 11 -- FileCreate      (process pid, target filename)
"""

import threading
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable

import win32evtlog
import win32api
import time

from agent.config import SYSMON_CHANNEL, SYSMON_PROCESS_CREATE, SYSMON_FILE_CREATE, SYSMON_FILE_RENAME, SYSMON_FILE_DELETE, SYSMON_FILE_DELETE_ARCHIVED

logger = logging.getLogger(__name__)

# XML namespace used in Sysmon event XML
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# How many consecutive Error-6 responses before we treat the handle as dead.
# The first 1-2 can happen right after subscription on some Windows builds.
_CONSECUTIVE_ERR6_LIMIT = 3


def _parse_event_xml(xml_str: str) -> dict:
    """Parse the raw XML of a Sysmon event into a clean dict."""
    try:
        root = ET.fromstring(xml_str)
        event_id = int(root.findtext("e:System/e:EventID", namespaces=_NS) or 0)

        data = {}
        for item in root.findall("e:EventData/e:Data", namespaces=_NS):
            name  = item.get("Name", "")
            value = item.text or ""
            data[name] = value

        tc_elem = root.find("e:System/e:TimeCreated", namespaces=_NS)
        timestamp = tc_elem.get("SystemTime", "") if tc_elem is not None else ""

        return {"event_id": event_id, "data": data, "timestamp": timestamp}
    except Exception as exc:
        logger.debug("Failed to parse Sysmon XML: %s", exc)
        return {}


def _format_process_create(parsed: dict) -> dict | None:
    """Convert parsed ID-1 event into an agent-friendly dict."""
    d = parsed.get("data", {})
    try:
        return {
            "type":         "PROCESS_CREATE",
            "pid":          int(d.get("ProcessId", 0)),
            "image":        d.get("Image", ""),
            "parent_pid":   int(d.get("ParentProcessId", 0)),
            "parent_image": d.get("ParentImage", ""),
            "cmd_line":     d.get("CommandLine", ""),
            "user":         d.get("User", ""),
            "timestamp":    parsed.get("timestamp", ""),
        }
    except (ValueError, TypeError):
        return None


def _format_file_create(parsed: dict) -> dict | None:
    """Convert parsed ID-11 event into an agent-friendly dict."""
    d = parsed.get("data", {})
    try:
        return {
            "type":        "FILE_CREATE",
            "pid":         int(d.get("ProcessId", 0)),
            "image":       d.get("Image", ""),
            "target_file": d.get("TargetFilename", ""),
            "timestamp":   parsed.get("timestamp", ""),
        }
    except (ValueError, TypeError):
        return None

def _format_file_rename(parsed: dict) -> dict | None:
    """Convert parsed ID-2 event into an agent-friendly dict."""
    d = parsed.get("data", {})
    try:
        return {
            "type":        "FILE_RENAME",
            "pid":         int(d.get("ProcessId", 0)),
            "image":       d.get("Image", ""),
            "source_path": d.get("SourceFilename", ""),
            "dest_path":   d.get("TargetFilename", ""),
            "timestamp":   parsed.get("timestamp", ""),
        }
    except (ValueError, TypeError):
        return None


def _format_file_delete(parsed: dict) -> dict | None:
    """Convert parsed ID-26 event into an agent-friendly dict."""
    d = parsed.get("data", {})
    try:
        return {
            "type":        "FILE_DELETE",
            "pid":         int(d.get("ProcessId", 0)),
            "image":       d.get("Image", ""),
            "target_file": d.get("TargetFilename", ""),
            "timestamp":   parsed.get("timestamp", ""),
        }
    except (ValueError, TypeError):
        return None


class SysmonReader(threading.Thread):
    """
    Background thread that subscribes to the Sysmon event log and calls
    `callback(event_dict)` for every ProcessCreate or FileCreate event.

    Usage:
        reader = SysmonReader(callback=my_handler)
        reader.start()
        ...
        reader.stop()
    """

    def __init__(self, callback: Callable[[dict], None]):
        super().__init__(name="SysmonReader", daemon=True)
        if not callable(callback):
            raise TypeError(f"SysmonReader callback must be callable! Got: {type(callback)} {callback!r}")
        self.callback    = callback
        self._stop_event = threading.Event()
        self._handle     = None

    # -- Subscription ---------------------------------------------------------

    def _subscribe(self, query: str):
        """
        Open a pull-mode EvtSubscribe handle and return it.

        We MUST provide a SignalEvent to Windows via kwargs, otherwise it expects
        a Callback. Previously, passing 4 positional arguments caused PyWin32 to map
        our string query to the Callback parameter, resulting in background thread
        TypeError crashes when Windows attempted to execute the string as a C callback.
        """
        import win32event
        self._signal_event = win32event.CreateEvent(None, 0, 0, None)
        handle = win32evtlog.EvtSubscribe(
            str(SYSMON_CHANNEL),                         # ChannelPath
            int(win32evtlog.EvtSubscribeToFutureEvents), # Flags
            SignalEvent=self._signal_event,
            Query=str(query),
        )
        return handle

    # -- Main loop ------------------------------------------------------------

    def run(self) -> None:
        while not self._stop_event.is_set():
            # ── Clean up previous handle before reconnecting ───────────────
            if self._handle is not None:
                try:
                    win32evtlog.EvtClose(self._handle)
                except Exception:
                    pass
                self._handle = None

            logger.info("SysmonReader: initializing subscription...")

            queries_to_try = [
                # 1. Targeted XPath (efficient -- only Event IDs 1, 2, 11, 23, 26)
                f"*[System[EventID={int(SYSMON_PROCESS_CREATE)} or EventID={int(SYSMON_FILE_CREATE)} or EventID={int(SYSMON_FILE_RENAME)} or EventID={int(SYSMON_FILE_DELETE)} or EventID={int(SYSMON_FILE_DELETE_ARCHIVED)}]]",
                # 2. Broad wildcard (fallback -- filter in Python)
                "*",
            ]

            for query in queries_to_try:
                try:
                    self._handle = self._subscribe(query)
                    logger.info(
                        "SysmonReader: Subscription SUCCESS (query: %s)",
                        "targeted" if query != "*" else "broad",
                    )
                    logger.info("SysmonReader: Now monitoring for real-time behavioral events.")
                    break
                except Exception as exc:
                    lasterr = win32api.GetLastError()
                    logger.warning(
                        "SysmonReader: Subscription failed (%s): %s  (winerror=%d)",
                        query, exc, lasterr,
                    )

            if not self._handle:
                logger.error("SysmonReader: all subscription methods failed. Retrying in 5s...")
                time.sleep(5)
                continue

            # Give the subscription handle 1 second to fully initialise before
            # the first EvtNext call.  Many Windows builds return winerror 6 if
            # EvtNext is called within ~200 ms of EvtSubscribe returning.
            time.sleep(1.0)

            consecutive_err6 = 0   # track consecutive error-6 responses

            try:
                while not self._stop_event.is_set():
                    try:
                        # Direct poll with 500ms timeout instead of signal wait
                        # This is more robust if Windows fails to signal the event.
                        try:
                            events = win32evtlog.EvtNext(self._handle, 100, 500)
                        except Exception as e:
                            winerr = getattr(e, "winerror", None)
                            if winerr in (258, 259, 4317): # Timeout / No more items / Invalid Operation (on poll)
                                continue
                            raise

                        if not events:
                            continue
                        
                        consecutive_err6 = 0   # successful call -> reset counter

                        for evt in events:
                            try:
                                xml_str = win32evtlog.EvtRender(
                                    evt, win32evtlog.EvtRenderEventXml
                                )
                                parsed = _parse_event_xml(xml_str)
                                if not parsed:
                                    continue

                                eid = parsed["event_id"]
                                if eid == SYSMON_PROCESS_CREATE:
                                    formatted = _format_process_create(parsed)
                                elif eid == SYSMON_FILE_CREATE:
                                    formatted = _format_file_create(parsed)
                                elif eid == SYSMON_FILE_RENAME:
                                    formatted = _format_file_rename(parsed)
                                elif eid == SYSMON_FILE_DELETE or eid == SYSMON_FILE_DELETE_ARCHIVED:
                                    formatted = _format_file_delete(parsed)
                                else:
                                    continue

                                if formatted:
                                    try:
                                        self.callback(formatted)
                                    except Exception:
                                        import traceback as _tb
                                        # Print directly to stderr -- bypasses all encoding/logging issues
                                        _tb.print_exc()
                                        raise

                            except Exception as exc:
                                logger.warning("SysmonReader: error processing event: %s", exc)

                    except Exception as e:
                        winerr = getattr(e, "winerror", None)

                        # 259 = ERROR_NO_MORE_ITEMS -- normal, just no pending events
                        if winerr == 259:
                            consecutive_err6 = 0
                            continue

                        # 258 = WAIT_TIMEOUT -- EvtNext poll timed out, no events
                        if winerr == 258:
                            consecutive_err6 = 0
                            continue

                        # 6 = ERROR_INVALID_HANDLE
                        # The first few can fire right after subscription before the
                        # handle's internal binding is ready.  Only reconnect after
                        # _CONSECUTIVE_ERR6_LIMIT consecutive failures.
                        if winerr == 6:
                            consecutive_err6 += 1
                            if consecutive_err6 < _CONSECUTIVE_ERR6_LIMIT:
                                logger.debug(
                                    "SysmonReader: winerror 6 (handle not ready yet) "
                                    "[%d/%d] -- backing off 500 ms",
                                    consecutive_err6, _CONSECUTIVE_ERR6_LIMIT,
                                )
                                time.sleep(0.5)
                                continue
                            logger.error(
                                "SysmonReader: winerror 6 persists (%d times) -- handle dead. Reconnecting...",
                                consecutive_err6,
                            )
                            break

                        # Any other error -- log and reconnect
                        logger.error(
                            "SysmonReader: unexpected error in EvtNext (winerror=%s): %s. Reconnecting...",
                            winerr, e,
                        )
                        break

            except Exception as exc:
                logger.error("SysmonReader: fatal error in event loop: %s", exc)
                time.sleep(2)

    # -- Shutdown -------------------------------------------------------------

    def stop(self) -> None:
        self._stop_event.set()
        self.join(timeout=3)
        logger.info("SysmonReader stopped")
