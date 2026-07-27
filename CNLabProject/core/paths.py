from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DB_PATH = CONFIG_DIR / "parental_control.db"
SECRET_KEY_PATH = CONFIG_DIR / "flask_secret.key"
LOG_PATH = PROJECT_ROOT / "log.txt"
