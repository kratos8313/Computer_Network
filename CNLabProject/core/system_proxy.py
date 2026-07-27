import winreg
from dataclasses import dataclass

INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

@dataclass
class ProxyState:
    enabled: int | None
    server: str | None

_saved_state = None


def _read(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return None


def _restore(key, name, value, kind):
    if value is None:
        try:
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
    else:
        winreg.SetValueEx(key, name, 0, kind, value)


def enable_proxy(server='127.0.0.1:8080'):
    global _saved_state
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        if _saved_state is None:
            _saved_state = ProxyState(_read(key, 'ProxyEnable'), _read(key, 'ProxyServer'))
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, server)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)


def disable_proxy():
    global _saved_state
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        if _saved_state is None:
            return
        _restore(key, 'ProxyEnable', _saved_state.enabled, winreg.REG_DWORD)
        _restore(key, 'ProxyServer', _saved_state.server, winreg.REG_SZ)
    _saved_state = None
