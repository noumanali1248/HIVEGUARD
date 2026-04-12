import win32serviceutil
import win32service
import win32event
import servicemanager
import sys
import os

# Add src directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.monitor import PersistenceMonitor

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'monitor_config.json')

class PersistenceMonitorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PersistenceMonitor"
    _svc_display_name_ = "Registry and Startup Persistence Monitor"
    _svc_description_ = "Monitors Windows persistence mechanisms (T1547) and alerts on changes."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.monitor = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        if self.monitor:
            self.monitor.stop()
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.monitor = PersistenceMonitor(CONFIG_PATH)
        self.monitor.start()

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(PersistenceMonitorService)