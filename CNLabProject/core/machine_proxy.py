import ctypes
import json
import threading
import winreg

from core.paths import PROXY_BACKUP_PATH, ensure_data_dir

POLICY_PATH = r'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
INTERNET_SETTINGS = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
_lock = threading.Lock()


def _notify_windows():
    wininet = ctypes.windll.Wininet
    wininet.InternetSetOptionW(None, 39, None, 0)
    wininet.InternetSetOptionW(None, 37, None, 0)


def _read(root, path, name):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, kind = winreg.QueryValueEx(key, name)
            return {'exists': True, 'value': value, 'kind': kind}
    except FileNotFoundError:
        return {'exists': False, 'value': None, 'kind': None}


def _write(root, path, name, value, kind):
    with winreg.CreateKeyEx(root, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
        winreg.SetValueEx(key, name, 0, kind, value)


def _restore(root, path, name, state):
    with winreg.CreateKeyEx(root, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
        if state['exists']:
            winreg.SetValueEx(key, name, 0, state['kind'], state['value'])
        else:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass


def _backup_once():
    if PROXY_BACKUP_PATH.exists():
        return
    ensure_data_dir()
    state = {
        'per_user': _read(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 'ProxySettingsPerUser'),
        'enabled': _read(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyEnable'),
        'server': _read(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyServer'),
    }
    temporary = PROXY_BACKUP_PATH.with_suffix('.tmp')
    temporary.write_text(json.dumps(state), encoding='utf-8')
    temporary.replace(PROXY_BACKUP_PATH)


def enable_proxy(server='127.0.0.1:8080'):
    with _lock:
        _backup_once()
        _write(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 'ProxySettingsPerUser', 0, winreg.REG_DWORD)
        _write(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyServer', server, winreg.REG_SZ)
        _write(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyEnable', 1, winreg.REG_DWORD)
        _notify_windows()


def is_proxy_enforced(server='127.0.0.1:8080'):
    return (
        _read(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 'ProxySettingsPerUser')['value'] == 0
        and _read(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyEnable')['value'] == 1
        and _read(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyServer')['value'] == server
    )


def ensure_proxy(server='127.0.0.1:8080'):
    if not is_proxy_enforced(server):
        enable_proxy(server)
        return True
    return False


def disable_proxy():
    with _lock:
        if not PROXY_BACKUP_PATH.exists():
            return
        state = json.loads(PROXY_BACKUP_PATH.read_text(encoding='utf-8'))
        _restore(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 'ProxySettingsPerUser', state['per_user'])
        _restore(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyEnable', state['enabled'])
        _restore(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyServer', state['server'])
        PROXY_BACKUP_PATH.unlink(missing_ok=True)
        _notify_windows()