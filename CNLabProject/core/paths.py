import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESOURCE_ROOT = Path(getattr(sys, '_MEIPASS', PROJECT_ROOT))
_default_data = (
    Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'ChildSafe'
    if getattr(sys, 'frozen', False)
    else PROJECT_ROOT / 'config'
)
CONFIG_DIR = Path(os.environ.get('CHILDSAFE_DATA_DIR', _default_data))
DB_PATH = CONFIG_DIR / 'parental_control.db'
SECRET_KEY_PATH = CONFIG_DIR / 'flask_secret.key'
PROXY_BACKUP_PATH = CONFIG_DIR / 'proxy_backup.json'
LOG_PATH = CONFIG_DIR / 'childsafe.log'


def ensure_data_dir(restrict=False):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if restrict and os.name == 'nt':
        subprocess.run([
            'icacls', str(CONFIG_DIR), '/inheritance:r',
            '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
        ], capture_output=True, check=True)
    return CONFIG_DIR