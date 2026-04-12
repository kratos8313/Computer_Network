import threading
import os
import sys
import winreg
from core.controller import start_system
from core.database import init_db, get_db, set_password
from app import app

def add_to_startup():
    """Adds the script to Windows Startup registry."""
    try:
        pth = os.path.realpath(sys.argv[0])
        key = winreg.HKEY_CURRENT_USER
        key_value = r"Software\Microsoft\Windows\CurrentVersion\Run"
        open_key = winreg.OpenKey(key, key_value, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(open_key, "ParentalControlSystem", 0, winreg.REG_SZ, f'pythonw "{pth}"')
        winreg.CloseKey(open_key)
        print("[SYSTEM] Added to Windows Startup")
    except Exception as e:
        print(f"[ERROR] Could not add to startup: {e}")

def main():
    # 1. Init Database
    init_db()
    
    # 2. Check for initial password
    conn = get_db()
    pwd = conn.execute("SELECT value FROM settings WHERE key='password'").fetchone()
    conn.close()
    
    if not pwd:
        print("--- INITIAL SETUP ---")
        p = input("Set Parent Password: ")
        set_password(p)
        print("Password set successfully!")

    # 3. Handle Startup Registry
    # add_to_startup() # Commented out by default to avoid accidental registry pollution during testing

    # 4. Start Core Blocker Engine (Proxy + Hosts)
    print("[SYSTEM] Starting Blocker Engine...")
    start_system()

    # 5. Start Web Dashboard in a separate thread
    print("[SYSTEM] Starting Management Dashboard at http://127.0.0.1:5000")
    flask_thread = threading.Thread(target=lambda: app.run(port=5000, debug=False, use_reloader=False), daemon=True)
    flask_thread.start()

    # Keep main thread alive
    print("[SYSTEM] Parental Control System is ACTIVE.")
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        from core.controller import stop_system
        print("[SYSTEM] Shutting down...")
        stop_system()

if __name__ == "__main__":
    main()