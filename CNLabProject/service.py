import os
import sys
from pathlib import Path

_data_root = Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'ChildSafe'
os.environ.setdefault('CHILDSAFE_DATA_DIR', str(_data_root))

import servicemanager
import win32event
import win32service
import win32serviceutil
from werkzeug.serving import make_server

from core.paths import ensure_data_dir
ensure_data_dir(restrict=True)

from app import app
from core import machine_proxy
from core.controller import start_system, stop_system
from core.database import init_db

SERVICE_NAME = 'ChildSafeService'


class ChildSafeService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = 'ChildSafe Parental Control'
    _svc_description_ = 'Enforces ChildSafe network rules and hosts the parent dashboard.'

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.http_server = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.http_server:
            self.http_server.shutdown()
        stop_system()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg('ChildSafe service starting')
        try:
            ensure_data_dir(restrict=True)
            init_db()
            start_system(proxy_manager=machine_proxy)
            self.http_server = make_server('127.0.0.1', 5000, app, threaded=True)
            servicemanager.LogInfoMsg('ChildSafe dashboard listening on 127.0.0.1:5000')
            self.http_server.serve_forever()
        except Exception as exc:
            servicemanager.LogErrorMsg(f'ChildSafe service failed: {exc}')
            raise
        finally:
            try:
                stop_system()
            except Exception as exc:
                servicemanager.LogErrorMsg(f'ChildSafe cleanup failed: {exc}')
            servicemanager.LogInfoMsg('ChildSafe service stopped')


def main():
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(ChildSafeService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(ChildSafeService)


if __name__ == '__main__':
    main()