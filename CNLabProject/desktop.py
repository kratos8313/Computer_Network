import ctypes
import sys
import threading
import time
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


def request_service_start():
    try:
        win32serviceutil.StartService(SERVICE_NAME)
        return True
    except Exception:
        executable = Path(sys.executable).resolve().parent.parent / 'Service' / 'ChildSafeService.exe'
        if not executable.exists():
            return False
        result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', str(executable), 'start', str(executable.parent), 0)
        return result > 32


class ChildSafeDesktop:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('ChildSafe Parental Control')
        self.root.geometry('480x330')
        self.root.resizable(False, False)
        self.root.configure(bg='#f8fafc')

        tk.Label(self.root, text='ChildSafe', font=('Segoe UI', 24, 'bold'), bg='#f8fafc', fg='#0f172a').pack(pady=(34, 4))
        tk.Label(self.root, text='Parental Control', font=('Segoe UI', 11), bg='#f8fafc', fg='#64748b').pack()
        self.status = tk.Label(self.root, text='Checking protectionâ€¦', font=('Segoe UI', 12, 'bold'), bg='#f8fafc')
        self.status.pack(pady=34)

        self.open_button = tk.Button(self.root, text='Open Parent Dashboard', command=self.open_dashboard, width=28, height=2, font=('Segoe UI', 10, 'bold'))
        self.open_button.pack(pady=4)
        tk.Button(self.root, text='Refresh Status', command=self.refresh, width=28, font=('Segoe UI', 9)).pack(pady=7)
        tk.Label(self.root, text='Protection continues when this window is closed.', font=('Segoe UI', 9), bg='#f8fafc', fg='#64748b').pack(pady=14)
        self.refresh()

    def refresh(self):
        state = service_state()
        ready = dashboard_ready() if state == 'RUNNING' else False
        if state == 'RUNNING' and ready:
            self.status.config(text='Protection is active', fg='#15803d')
            self.open_button.config(state=tk.NORMAL)
        elif state in {'RUNNING', 'STARTING'}:
            self.status.config(text='Protection is startingâ€¦', fg='#a16207')
            self.open_button.config(state=tk.DISABLED)
            self.root.after(1500, self.refresh)
        elif state == 'NOT_INSTALLED':
            self.status.config(text='Service is not installed', fg='#b91c1c')
            self.open_button.config(state=tk.DISABLED)
        else:
            self.status.config(text='Protection is stopped', fg='#b91c1c')
            self.open_button.config(state=tk.DISABLED)

    def open_dashboard(self):
        webbrowser.open(DASHBOARD_URL, new=1)

    def run(self):
        if service_state() == 'STOPPED':
            request_service_start()
            self.root.after(500, self.refresh)
        self.root.mainloop()


if __name__ == '__main__':
    ChildSafeDesktop().run()