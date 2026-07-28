import threading
import time
from getpass import getpass
from app import app
from core.controller import start_system, stop_system
from core.database import get_db, init_db, set_password


def main():
    init_db()
    with get_db() as conn:
        configured = conn.execute("SELECT 1 FROM settings WHERE key='password'").fetchone()
    if not configured:
        while True:
            first = getpass('Set administrator password (minimum 8 characters): ')
            second = getpass('Confirm password: ')
            if first != second:
                print('Passwords do not match.')
                continue
            try:
                set_password(first)
                break
            except ValueError as exc:
                print(exc)

    try:
        start_system()
    except Exception as exc:
        print(f'[FATAL] Blocker engine could not start: {exc}')
        return 1

    print('[SYSTEM] Dashboard: http://127.0.0.1:5000')
    dashboard = threading.Thread(
        target=lambda: app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False),
        daemon=True,
    )
    dashboard.start()
    try:
        while dashboard.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_system()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
