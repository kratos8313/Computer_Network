import sys
import tkinter as tk
from tkinter import messagebox, simpledialog

from core.database import check_password, get_db, log_activity
from core.notifications import send_notification
from utils.logger import log


def password_configured():
    try:
        with get_db() as conn:
            return conn.execute("SELECT 1 FROM settings WHERE key='password'").fetchone() is not None
    except Exception as exc:
        log(f'[SECURITY] Password database unavailable during uninstall: {exc}')
        return False


def authorize(password):
    if not password_configured():
        log('[SECURITY] Uninstall allowed before administrator setup was completed.')
        return True
    allowed = check_password(password)
    if allowed:
        log('[SECURITY] Administrator-authorized uninstall.')
        log_activity('', 'authorized', 'Administrator-authorized uninstall')
        send_notification('uninstall_authorized', 'An administrator authorized application removal.', 'critical')
    else:
        log('[SECURITY] Blocked uninstall attempt.')
        log_activity('', 'denied', 'Invalid administrator password during uninstall attempt')
        send_notification('uninstall_denied', 'An invalid administrator password was entered during an uninstall attempt.', 'critical')
    return allowed


def main():
    root = tk.Tk()
    root.withdraw()
    if not password_configured():
        authorize('')
        root.destroy()
        return 0
    password = simpledialog.askstring(
        'NetGuard Uninstall',
        'Enter the administrator password to uninstall this network control application:',
        show='*',
        parent=root,
    )
    if not password or not authorize(password):
        messagebox.showerror(
            'NetGuard Uninstall',
            'Uninstall blocked. The administrator password was not accepted.',
            parent=root,
        )
        root.destroy()
        return 1
    root.destroy()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())