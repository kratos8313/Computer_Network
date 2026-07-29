import sys

import servicemanager
import win32event
import win32service
import win32serviceutil
from werkzeug.serving import make_server

from core.paths import ensure_data_dir

SERVICE_NAME = 'NetGuardService'


class NetGuardService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = 'NetGuard Access Control'
    _svc_description_ = 'Enforces administrator-defined network rules and hosts the local control dashboard.'

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.http_server = None

    def SvcStop(self):
        from core.controller import stop_system
        from core.notifications import send_notification

        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        send_notification(
            'service_stop_requested',
            'The network protection service received a stop request.',
            'critical',
        )
        if self.http_server:
            self.http_server.shutdown()
        stop_system()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        stop_callback = None
        servicemanager.LogInfoMsg('NetGuard service starting')
        try:
            from app import app
            from core import machine_proxy
            from core.controller import start_system, stop_system
            from core.database import init_db

            stop_callback = stop_system
            ensure_data_dir(restrict=True)
            init_db()
            start_system(proxy_manager=machine_proxy)
            self.http_server = make_server('127.0.0.1', 5000, app, threaded=True)
            servicemanager.LogInfoMsg('NetGuard dashboard listening on 127.0.0.1:5000')
            self.http_server.serve_forever()
        except Exception as exc:
            servicemanager.LogErrorMsg(f'NetGuard service failed: {exc}')
            raise
        finally:
            if stop_callback:
                try:
                    stop_callback()
                except Exception as exc:
                    servicemanager.LogErrorMsg(f'NetGuard cleanup failed: {exc}')
            servicemanager.LogInfoMsg('NetGuard service stopped')


def cleanup_policy():
    from core import machine_proxy
    from core.blocker import unblock_all

    unblock_all()
    machine_proxy.disable_proxy()


def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'cleanup':
        cleanup_policy()
        return
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NetGuardService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(NetGuardService)


if __name__ == '__main__':
    main()