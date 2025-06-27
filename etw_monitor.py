from pywintrace import Trace, EVENT_TRACE_REAL_TIME_MODE

class RobustETWMonitor:
    def __init__(self, callback):
        self.session_name = "LotLDefenseSession"
        self.callback = callback
        self.trace = Trace(self.session_name)
        
    def start(self):
        # Enable process events
        self.trace.enable(
            event_names=["Microsoft-Windows-Kernel-Process/Start"],
            providers=[GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")]
        )
        
        # Set real-time callback
        self.trace.open(real_time=True)
        self.trace.process(real_time_callback=self.event_callback)
        
    def event_callback(self, event):
        if event.EventName == "ProcessStart":
            proc_info = {
                'pid': event.ProcessId,
                'name': event.ImageName,
                'cmdline': event.CommandLine,
                'parent_pid': event.ParentProcessId
            }
            self.callback(proc_info)