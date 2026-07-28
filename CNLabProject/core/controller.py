import threading
import time

from core.proxy import start_proxy, stop_proxy

_state_lock = threading.Lock()
_stop_event = threading.Event()
_proxy_thread = None
_proxy_manager = None
running = False


def stop_system():
    global running, _proxy_thread, _proxy_manager
    with _state_lock:
        running = False
        _stop_event.set()
        stop_proxy()
        manager = _proxy_manager
        _proxy_manager = None
        thread = _proxy_thread
        _proxy_thread = None
    if manager:
        manager.disable_proxy()
    if thread and thread.is_alive():
        thread.join(timeout=2)
    print('System stopped')


def start_system(startup_timeout=5, proxy_manager=None):
    global running, _proxy_thread, _proxy_manager
    if proxy_manager is None:
        from core import system_proxy as proxy_manager
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
            proxy_manager.enable_proxy()
        except Exception:
            stop_proxy()
            raise
        _proxy_manager = proxy_manager
        running = True

        def enforcement_loop():
            next_hosts_sync = 0.0
            while not _stop_event.is_set():
                now = time.monotonic()
                proxy_manager.ensure_proxy()
                if now >= next_hosts_sync:
                    block_sites()
                    next_hosts_sync = now + 60
                _stop_event.wait(2)
        threading.Thread(target=enforcement_loop, daemon=True).start()
    print('System started')
    return True