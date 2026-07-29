import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESOURCE_ROOT = Path(getattr(sys, '_MEIPASS', PROJECT_ROOT))
_program_data = Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData'))
_legacy_data = _program_data / 'ChildSafe'
_branded_data = _program_data / 'NetGuard'
if getattr(sys, 'frozen', False):
    _default_data = _legacy_data if (_legacy_data / 'parental_control.db').exists() else _branded_data
else:
    _default_data = PROJECT_ROOT / 'config'
_configured_data = os.environ.get('NETGUARD_DATA_DIR') or os.environ.get('CHILDSAFE_DATA_DIR')
CONFIG_DIR = Path(_configured_data) if _configured_data else _default_data
_legacy_db = CONFIG_DIR / 'parental_control.db'
_legacy_log = CONFIG_DIR / 'childsafe.log'
DB_PATH = _legacy_db if _legacy_db.exists() else CONFIG_DIR / 'network_control.db'
SECRET_KEY_PATH = CONFIG_DIR / 'flask_secret.key'
PROXY_BACKUP_PATH = CONFIG_DIR / 'proxy_backup.json'
LOG_PATH = _legacy_log if _legacy_log.exists() else CONFIG_DIR / 'netguard.log'


def ensure_data_dir(restrict=False):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if restrict and os.name == 'nt':
        subprocess.run([
            'icacls', str(CONFIG_DIR), '/inheritance:r',
            '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
        ], capture_output=True, check=True)
    return CONFIG_DIR