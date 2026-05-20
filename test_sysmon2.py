import win32evtlog
import win32event

channel = "Microsoft-Windows-Sysmon/Operational"
flags = win32evtlog.EvtSubscribeToFutureEvents
query = "*[System[EventID=1 or EventID=11 or EventID=2 or EventID=23 or EventID=26]]"
event = win32event.CreateEvent(None, 0, 0, None)

try:
    print("Testing specific query kwargs...")
    h = win32evtlog.EvtSubscribe(channel, flags, SignalEvent=event, Query=query)
    print("Success specific query!")
except Exception as e:
    print("Failed specific query:", e)
