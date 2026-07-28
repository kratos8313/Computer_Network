import hashlib
import hmac
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash
from core.paths import CONFIG_DIR, DB_PATH

class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()



def get_db():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("""CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL DEFAULT 'Manual',
            action TEXT NOT NULL DEFAULT 'block' CHECK(action IN ('block', 'allow')))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('category', 'domain')),
            start_time TEXT NOT NULL, end_time TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            domain TEXT, action TEXT, reason TEXT)""")
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('mode', 'blacklist')")


def set_password(password):
    if not password or len(password) < 8:
        raise ValueError("Password must contain at least 8 characters")
    value = generate_password_hash(password, method="scrypt")
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('password', ?)", (value,))


def check_password(password):
    if not password:
        return False
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='password'").fetchone()
    if not row:
        return False
    stored = row['value']
    if stored.startswith(('scrypt:', 'pbkdf2:')):
        return check_password_hash(stored, password)
    legacy = hashlib.sha256(password.encode()).hexdigest()
    if len(stored) == 64 and hmac.compare_digest(legacy, stored):
        set_password(password)
        return True
    return False


def get_setting(key, default=None):
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row['value'] if row else default


def set_setting(key, value):
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))

def add_rule(domain, category='Manual', action='block'):
    from utils.norm import get_root_domain
    domain = get_root_domain(domain)
    if not domain:
        raise ValueError("A valid domain is required")
    if action not in {'block', 'allow'}:
        raise ValueError("Invalid rule action")
    category = (category or 'Manual').strip()[:80]
    with get_db() as conn:
        conn.execute("""INSERT INTO rules (domain, category, action) VALUES (?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET category=excluded.category, action=excluded.action""",
            (domain, category, action))


def get_rules():
    with get_db() as conn:
        return conn.execute("SELECT * FROM rules ORDER BY domain").fetchall()


def delete_rule(rule_id):
    with get_db() as conn:
        conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))


def log_activity(domain, action, reason='Policy'):
    with get_db() as conn:
        conn.execute("INSERT INTO logs (domain, action, reason) VALUES (?, ?, ?)", (domain, action, reason))


def get_logs(limit=100):
    safe_limit = max(1, min(int(limit), 1000))
    with get_db() as conn:
        return conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (safe_limit,)).fetchall()


def get_security_alerts(limit=5):
    safe_limit = max(1, min(int(limit), 100))
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM logs WHERE action='denied' ORDER BY timestamp DESC LIMIT ?",
            (safe_limit,),
        ).fetchall()
