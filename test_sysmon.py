import win32evtlog
import win32event

channel = "Microsoft-Windows-Sysmon/Operational"
flags = win32evtlog.EvtSubscribeToFutureEvents
query = "*"
event = win32event.CreateEvent(None, 0, 0, None)

try:
    print("Testing kwargs...")
    h = win32evtlog.EvtSubscribe(channel, flags, SignalEvent=event, Query=query)
    print("Success kwargs!")
except Exception as e:
    print("Failed kwargs:", e)

try:
    print("Testing positional...")
    h = win32evtlog.EvtSubscribe(channel, flags, None, query, None, None, None, event)
    print("Success positional!")
except Exception as e:
    print("Failed positional:", e)
