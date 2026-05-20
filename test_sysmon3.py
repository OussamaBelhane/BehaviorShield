import win32evtlog
import win32event

channel = "Application"
flags = win32evtlog.EvtSubscribeToFutureEvents
event = win32event.CreateEvent(None, 0, 0, None)

queries = [
    "*",
    "*[System[EventID=1 or EventID=11]]",
    "*[System[(EventID=1 or EventID=11)]]"
]

for q in queries:
    try:
        print(f"Testing {q}...")
        h = win32evtlog.EvtSubscribe(channel, flags, SignalEvent=event, Query=q)
        print("Success!")
    except Exception as e:
        print("Failed:", e)
