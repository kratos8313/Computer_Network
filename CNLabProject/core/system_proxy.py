import ctypes
import threading
import winreg
from dataclasses import dataclass

INTERNET_SETTINGS = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
_lock = threading.Lock()


def _notify_windows():
    wininet = ctypes.windll.Wininet
    wininet.InternetSetOptionW(None, 39, None, 0)
    wininet.InternetSetOptionW(None, 37, None, 0)

@dataclass
class ProxyState:
    enabled: int | None
    server: str | None

_saved_state = None


def _read_value(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return None


def _set_or_delete(key, name, value, value_type):
    if value is None:
        try:
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
    else:
        winreg.SetValueEx(key, name, 0, value_type, value)


def enable_proxy(server='127.0.0.1:8080'):
    global _saved_state
    with _lock, winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        if _saved_state is None:
            _saved_state = ProxyState(_read_value(key, 'ProxyEnable'), _read_value(key, 'ProxyServer'))
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, server)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        _notify_windows()


def is_proxy_enforced(server='127.0.0.1:8080'):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ) as key:
        return _read_value(key, 'ProxyEnable') == 1 and _read_value(key, 'ProxyServer') == server


def ensure_proxy(server='127.0.0.1:8080'):
    if not is_proxy_enforced(server):
        enable_proxy(server)
        return True
    return False


def disable_proxy():
    global _saved_state
    with _lock, winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        if _saved_state is None:
            return
        _set_or_delete(key, 'ProxyEnable', _saved_state.enabled, winreg.REG_DWORD)
        _set_or_delete(key, 'ProxyServer', _saved_state.server, winreg.REG_SZ)
        _saved_state = None
        _notify_windows()