import win32evtlog
import win32event

channel = "Application"
flags = win32evtlog.EvtSubscribeToFutureEvents
event = win32event.CreateEvent(None, 0, 0, None)

try:
    print("Testing kwargs with Query=None...")
    h = win32evtlog.EvtSubscribe(channel, flags, SignalEvent=event, Query=None)
    print("Success kwargs!")
except Exception as e:
    print("Failed kwargs:", e)
