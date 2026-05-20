import wmi
import time

try:
    c = wmi.WMI()
    print("Watching Sysmon via WMI...")
    watcher = c.watch_for(
        notification_type="Creation",
        wmi_class="Win32_NTLogEvent",
        delay_secs=1,
        Logfile="Microsoft-Windows-Sysmon/Operational"
    )
    for _ in range(3):
        try:
            event = watcher(timeout_ms=5000)
            print(event)
        except wmi.x_wmi_timed_out:
            print("Timeout")
except Exception as e:
    print("Failed:", e)
