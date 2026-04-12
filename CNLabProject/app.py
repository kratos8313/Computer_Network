from flask import Flask, render_template, request, redirect, url_for, session, flash
from core.database import (
    get_db, check_password, add_rule, get_rules, delete_rule, get_logs, init_db
)
from core.blocker import block_sites
from core.proxy import get_proxy_status
import datetime

app = Flask(__name__)
app.secret_key = "super_secret_parental_control_key"

# Ensure DB is initialized
init_db()

def is_logged_in():
    return 'logged_in' in session

@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    conn = get_db()
    mode = conn.execute("SELECT value FROM settings WHERE key='mode'").fetchone()['value']
    rules = get_rules()
    conn.close()
    
    status, error = get_proxy_status()
    
    return render_template('dashboard.html', rules=rules, mode=mode, status=status, status_error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if check_password(password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash("Invalid Password")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/rules/add', methods=['POST'])
def add_new_rule():
    if not is_logged_in(): return redirect(url_for('login'))
    
    domain = request.form.get('domain')
    category = request.form.get('category')
    action = request.form.get('action', 'block')
    
    if domain:
        add_rule(domain, category, action)
        block_sites() # Apply immediately
    
    return redirect(url_for('index'))

@app.route('/rules/delete/<int:rule_id>')
def remove_rule(rule_id):
    if not is_logged_in(): return redirect(url_for('login'))
    delete_rule(rule_id)
    block_sites() # Apply immediately
    return redirect(url_for('index'))

@app.route('/settings/mode', methods=['POST'])
def update_mode():
    if not is_logged_in(): return redirect(url_for('login'))
    
    mode = request.form.get('mode')
    conn = get_db()
    conn.execute("UPDATE settings SET value=? WHERE key='mode'", (mode,))
    conn.commit()
    conn.close()
    
    block_sites() # Apply immediately
    return redirect(url_for('index'))

@app.route('/logs')
def view_logs():
    if not is_logged_in(): return redirect(url_for('login'))
    logs = get_logs(limit=200)
    return render_template('logs.html', logs=logs)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
