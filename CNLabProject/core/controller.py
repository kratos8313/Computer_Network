import threading
import time

from core.proxy import start_proxy, stop_proxy

_state_lock = threading.Lock()
_stop_event = threading.Event()
_proxy_thread = None
_enforcement_thread = None
_proxy_manager = None
running = False


def is_protection_running():
    with _state_lock:
        return running


def stop_system():
    global running, _proxy_thread, _enforcement_thread, _proxy_manager
    with _state_lock:
        running = False
        _stop_event.set()
        stop_proxy()
        manager = _proxy_manager
        _proxy_manager = None
        proxy_thread = _proxy_thread
        enforcement_thread = _enforcement_thread
        _proxy_thread = None
        _enforcement_thread = None
    if enforcement_thread and enforcement_thread.is_alive():
        enforcement_thread.join(timeout=3)
    if proxy_thread and proxy_thread.is_alive():
        proxy_thread.join(timeout=2)
    if manager:
        manager.disable_proxy()
    from core.blocker import unblock_all
    unblock_all()
    print('System stopped')


def start_system(startup_timeout=5, proxy_manager=None):
    global running, _proxy_thread, _enforcement_thread, _proxy_manager
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
        _enforcement_thread = threading.Thread(target=enforcement_loop, daemon=True)
        _enforcement_thread.start()
    print('System started')
    return True