from core.proxy import stop_proxy   # 👈 ADD THIS

running = False
proxy_started = False

def stop_system():
    global running
    running = False
    stop_proxy()
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
        threading.Thread(target=start_proxy, daemon=True).start()
        proxy_started = True

    # Blocking loop
    def loop():
        while running:
            block_sites()

    threading.Thread(target=loop, daemon=True).start()

    print("System started")