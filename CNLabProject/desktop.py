import ctypes
import sys
import tkinter as tk
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import messagebox

import win32service
import win32serviceutil

SERVICE_NAME = 'ChildSafeService'
DASHBOARD_URL = 'http://127.0.0.1:5000'


def service_state():
    try:
        state = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
    except Exception:
        return 'NOT_INSTALLED'
    return {
        win32service.SERVICE_RUNNING: 'RUNNING',
        win32service.SERVICE_START_PENDING: 'STARTING',
        win32service.SERVICE_STOP_PENDING: 'STOPPING',
        win32service.SERVICE_STOPPED: 'STOPPED',
    }.get(state, 'UNAVAILABLE')


def dashboard_ready():
    try:
        with urllib.request.urlopen(DASHBOARD_URL + '/login', timeout=1) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def service_executable():
    return Path(sys.executable).resolve().parent.parent / 'Service' / 'ChildSafeService.exe'


def run_elevated_service(parameters):
    executable = service_executable()
    if not executable.exists():
        return False
    result = ctypes.windll.shell32.ShellExecuteW(
        None, 'runas', str(executable), parameters, str(executable.parent), 0,
    )
    return result > 32


def request_service_start():
    try:
        win32serviceutil.StartService(SERVICE_NAME)
        return True
    except Exception:
        return run_elevated_service('start')


def request_service_install():
    return run_elevated_service('install --startup auto')


class ChildSafeDesktop:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('ChildSafe Parental Control')
        self.root.geometry('480x330')
        self.root.resizable(False, False)
        self.root.configure(bg='#f8fafc')
        self.repair_attempts = 0

        tk.Label(self.root, text='ChildSafe', font=('Segoe UI', 24, 'bold'), bg='#f8fafc', fg='#0f172a').pack(pady=(34, 4))
        tk.Label(self.root, text='Parental Control', font=('Segoe UI', 11), bg='#f8fafc', fg='#64748b').pack()
        self.status = tk.Label(self.root, text='Checking protection…', font=('Segoe UI', 12, 'bold'), bg='#f8fafc')
        self.status.pack(pady=34)

        self.open_button = tk.Button(self.root, width=28, height=2, font=('Segoe UI', 10, 'bold'))
        self.open_button.pack(pady=4)
        tk.Button(self.root, text='Refresh Status', command=self.refresh, width=28, font=('Segoe UI', 9)).pack(pady=7)
        tk.Label(self.root, text='Protection continues when this window is closed.', font=('Segoe UI', 9), bg='#f8fafc', fg='#64748b').pack(pady=14)
        self.refresh()

    def configure_action(self, text, command, enabled=True):
        self.open_button.config(
            text=text,
            command=command,
            state=tk.NORMAL if enabled else tk.DISABLED,
        )

    def refresh(self):
        state = service_state()
        ready = dashboard_ready() if state == 'RUNNING' else False
        if state == 'RUNNING' and ready:
            self.status.config(text='Protection is active', fg='#15803d')
            self.configure_action('Open Parent Dashboard', self.open_dashboard)
        elif state in {'RUNNING', 'STARTING'}:
            self.status.config(text='Protection is starting…', fg='#a16207')
            self.configure_action('Open Parent Dashboard', self.open_dashboard, enabled=False)
            self.root.after(1500, self.refresh)
        elif state == 'NOT_INSTALLED':
            self.status.config(text='Protection service needs repair', fg='#b91c1c')
            self.configure_action('Repair Installation', self.repair_service)
        elif state == 'STOPPED':
            self.status.config(text='Protection is stopped', fg='#b91c1c')
            self.configure_action('Start Protection', self.start_service)
        else:
            self.status.config(text='Protection status is unavailable', fg='#b91c1c')
            self.configure_action('Refresh Status', self.refresh)

    def start_service(self):
        if not request_service_start():
            messagebox.showerror('ChildSafe', 'Windows did not allow the protection service to start.')
            return
        self.status.config(text='Protection is starting…', fg='#a16207')
        self.configure_action('Open Parent Dashboard', self.open_dashboard, enabled=False)
        self.root.after(1200, self.refresh)

    def repair_service(self):
        if not service_executable().exists():
            messagebox.showerror('ChildSafe', 'The service files are missing. Please reinstall ChildSafe.')
            return
        if not request_service_install():
            messagebox.showerror('ChildSafe', 'Windows did not allow the service repair. Please approve the administrator prompt.')
            return
        self.repair_attempts = 0
        self.status.config(text='Repairing protection service…', fg='#a16207')
        self.configure_action('Repairing…', self.refresh, enabled=False)
        self.root.after(1000, self.finish_repair)

    def finish_repair(self):
        state = service_state()
        if state == 'STOPPED':
            request_service_start()
        if state in {'RUNNING', 'STARTING'}:
            self.refresh()
            return
        self.repair_attempts += 1
        if self.repair_attempts < 30:
            self.root.after(1000, self.finish_repair)
            return
        messagebox.showerror('ChildSafe', 'The protection service could not be repaired. Please reinstall ChildSafe.')
        self.refresh()

    def open_dashboard(self):
        webbrowser.open(DASHBOARD_URL, new=1)

    def run(self):
        if service_state() == 'STOPPED':
            request_service_start()
            self.root.after(500, self.refresh)
        self.root.mainloop()


if __name__ == '__main__':
    ChildSafeDesktop().run()