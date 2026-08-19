import ctypes
import json
import os
import threading
import winreg
from pathlib import Path

from core.paths import PROXY_BACKUP_PATH, ensure_data_dir

POLICY_PATH = r'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
INTERNET_SETTINGS = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
_lock = threading.Lock()
MANAGED_PROXY = '127.0.0.1:8080'


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
    _, existing_state = _load_backup()
    if existing_state:
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


def enable_proxy(server=MANAGED_PROXY):
    with _lock:
        _backup_once()
        _write(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 'ProxySettingsPerUser', 0, winreg.REG_DWORD)
        _write(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyServer', server, winreg.REG_SZ)
        _write(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyEnable', 1, winreg.REG_DWORD)
        _notify_windows()


def is_proxy_enforced(server=MANAGED_PROXY):
    return (
        _read(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 'ProxySettingsPerUser')['value'] == 0
        and _read(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyEnable')['value'] == 1
        and _read(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyServer')['value'] == server
    )


def ensure_proxy(server=MANAGED_PROXY):
    if not is_proxy_enforced(server):
        enable_proxy(server)
        return True
    return False


def _backup_candidates():
    program_data = Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData'))
    candidates = [
        PROXY_BACKUP_PATH,
        program_data / 'NetGuard' / 'proxy_backup.json',
        program_data / 'ChildSafe' / 'proxy_backup.json',
    ]
    return list(dict.fromkeys(candidates))


def _load_backup():
    for path in _backup_candidates():
        try:
            state = json.loads(path.read_text(encoding='utf-8'))
            records = [state.get(key) for key in ('per_user', 'enabled', 'server')]
            if all(
                isinstance(record, dict)
                and isinstance(record.get('exists'), bool)
                and (not record['exists'] or record.get('kind') is not None)
                for record in records
            ):
                return path, state
        except (FileNotFoundError, OSError, ValueError, TypeError):
            continue
    return None, None


def _is_managed_proxy_active():
    enabled = _read(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyEnable')
    server = _read(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyServer')
    return enabled['value'] == 1 and str(server['value']).strip().lower() == MANAGED_PROXY


def _emergency_disable_managed_proxy():
    if not _is_managed_proxy_active():
        return False
    _restore(
        winreg.HKEY_LOCAL_MACHINE,
        INTERNET_SETTINGS,
        'ProxyEnable',
        {'exists': True, 'value': 0, 'kind': winreg.REG_DWORD},
    )
    _restore(
        winreg.HKEY_LOCAL_MACHINE,
        INTERNET_SETTINGS,
        'ProxyServer',
        {'exists': False, 'value': None, 'kind': None},
    )
    policy = _read(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 'ProxySettingsPerUser')
    if policy['value'] == 0:
        _restore(
            winreg.HKEY_LOCAL_MACHINE,
            POLICY_PATH,
            'ProxySettingsPerUser',
            {'exists': False, 'value': None, 'kind': None},
        )
    return True


def disable_proxy():
    with _lock:
        backup_path, state = _load_backup()
        if state:
            _restore(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 'ProxySettingsPerUser', state['per_user'])
            _restore(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyEnable', state['enabled'])
            _restore(winreg.HKEY_LOCAL_MACHINE, INTERNET_SETTINGS, 'ProxyServer', state['server'])
            for path in _backup_candidates():
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            _notify_windows()
            return True
        if _emergency_disable_managed_proxy():
            _notify_windows()
            return True
        return False
