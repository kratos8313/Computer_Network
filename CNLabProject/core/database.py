import sqlite3
import hashlib
import datetime
import os

DB_PATH = "config/parental_control.db"

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # Rules table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            category TEXT,
            action TEXT DEFAULT 'block'
        )
    """)

    # Schedules table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,-- Category name or Domain
            type TEXT,-- 'category' or 'domain'
            start_time TEXT,-- HH:MM
            end_time TEXT   -- HH:MM
        )
    """)

    # Logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            domain TEXT,
            action TEXT,
            reason TEXT
        )
    """)

    # Default settings
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('mode', 'blacklist')")
    
    conn.commit()
    conn.close()

# --- Auth Helpers ---
def set_password(password):
    conn = get_db()
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('password', ?)", (pwd_hash,))
    conn.commit()
    conn.close()

def check_password(password):
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key='password'").fetchone()
    conn.close()
    if not row: return False
    return hashlib.sha256(password.encode()).hexdigest() == row['value']

# --- Rules Helpers ---
def add_rule(domain, category="Manual", action="block"):
    from utils.norm import get_root_domain
    domain = get_root_domain(domain)
    if not domain: return
    
    conn = get_db()
    try:
        conn.execute("INSERT INTO rules (domain, category, action) VALUES (?, ?, ?)", (domain, category, action))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

def get_rules():
    conn = get_db()
    rules = conn.execute("SELECT * FROM rules").fetchall()
    conn.close()
    return rules

def delete_rule(rule_id):
    conn = get_db()
    conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()

# --- Logging ---
def log_activity(domain, action, reason="Policy"):
    conn = get_db()
    conn.execute("INSERT INTO logs (domain, action, reason) VALUES (?, ?, ?)", (domain, action, reason))
    conn.commit()
    conn.close()

def get_logs(limit=100):
    conn = get_db()
    logs = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return logs

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
