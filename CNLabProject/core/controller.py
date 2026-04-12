from core.proxy import stop_proxy
from core.system_proxy import enable_proxy, disable_proxy

running = False
proxy_started = False

def stop_system():
    global running
    running = False
    stop_proxy()
    disable_proxy()
    print("System stopped")

def start_system():
    global running, proxy_started

    if running:
        print("System already running!")
        return

    running = True

    import threading
    from core.proxy import start_proxy, stop_proxy
    from core.blocker import block_sites

    # Start proxy only once
    if not proxy_started:
        enable_proxy()
        threading.Thread(target=start_proxy, daemon=True).start()
        proxy_started = True

    # Blocking loop (Anti-Bypass)
    def loop():
        import time
        block_sites() # Sync immediately on startup
        while running:
            block_sites()
            time.sleep(60) # 60-second re-verification as requested

    threading.Thread(target=loop, daemon=True).start()

    print("System started")