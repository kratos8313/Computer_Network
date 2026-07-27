import threading
from core.proxy import start_proxy, stop_proxy
from core.system_proxy import disable_proxy, enable_proxy

_state_lock = threading.Lock()
_stop_event = threading.Event()
_proxy_thread = None
running = False


def stop_system():
    global running, _proxy_thread
    with _state_lock:
        running = False
        _stop_event.set()
        stop_proxy()
        disable_proxy()
        thread = _proxy_thread
        _proxy_thread = None
    if thread and thread.is_alive():
        thread.join(timeout=2)
    print('System stopped')


def start_system(startup_timeout=5):
    global running, _proxy_thread
    with _state_lock:
        if running:
            return True
        from core.blocker import block_sites
        ready = threading.Event()
        startup_error = []
        _stop_event.clear()
        _proxy_thread = threading.Thread(target=start_proxy, args=(ready, startup_error), daemon=True)
        _proxy_thread.start()
        if not ready.wait(startup_timeout) or startup_error:
            stop_proxy()
            message = startup_error[0] if startup_error else 'proxy startup timed out'
            raise RuntimeError(f'Could not start local proxy: {message}')
        try:
            enable_proxy()
        except Exception:
            stop_proxy()
            raise
        running = True

        def sync_loop():
            while not _stop_event.is_set():
                block_sites()
                _stop_event.wait(60)
        threading.Thread(target=sync_loop, daemon=True).start()
    print('System started')
    return True
