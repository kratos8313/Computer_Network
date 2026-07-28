import threading
import time
from functools import wraps

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

from core import controller, machine_proxy
from core.blocker import block_sites
from core.database import add_rule, check_password, delete_rule, get_db, get_logs, get_rules, get_security_alerts, get_setting, init_db, log_activity, set_password, set_setting
from core.notifications import notify_async, send_notification, validate_notification_url
from core.proxy import get_proxy_status
from core.web_security import csrf_token, load_or_create_secret, validate_csrf

app = Flask(__name__)
app.secret_key = load_or_create_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict')
app.jinja_env.globals['csrf_token'] = csrf_token
app.before_request(validate_csrf)
init_db()

_login_lock = threading.Lock()
_login_failures = {}


def is_configured():
    with get_db() as conn:
        return conn.execute("SELECT 1 FROM settings WHERE key='password'").fetchone() is not None


def is_logged_in():
    return session.get('logged_in') is True


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def _login_delay(client):
    with _login_lock:
        failures, blocked_until = _login_failures.get(client, (0, 0.0))
        return max(0, int(blocked_until - time.monotonic())) if failures >= 5 else 0


def _record_login(client, success):
    with _login_lock:
        if success:
            _login_failures.pop(client, None)
            return
        failures, _ = _login_failures.get(client, (0, 0.0))
        failures += 1
        delay = min(300, 30 * (2 ** max(0, failures - 5))) if failures >= 5 else 0
        _login_failures[client] = (failures, time.monotonic() + delay)


def _confirm_admin_password():
    client = f"sensitive:{request.remote_addr or 'local'}"
    remaining = _login_delay(client)
    if remaining:
        flash(f'Too many failed attempts. Try again in {remaining} seconds.')
        return False
    valid = check_password(request.form.get('password'))
    _record_login(client, valid)
    if not valid:
        log_activity('', 'denied', 'Invalid administrator password for sensitive control')
        notify_async('administrator_password_denied', 'An invalid administrator password was entered for a sensitive control.')
        flash('Invalid administrator password')
    return valid


@app.get('/health')
def health():
    return jsonify(service='running', protection=controller.is_protection_running())


@app.get('/')
@login_required
def index():
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='mode'").fetchone()
    mode = row['value'] if row else 'blacklist'
    status, error = get_proxy_status()
    return render_template(
        'dashboard.html',
        rules=get_rules(),
        mode=mode,
        status=status,
        status_error=error,
        protection_running=controller.is_protection_running(),
        security_alerts=get_security_alerts(),
        notification_url=get_setting('notification_url', ''),
        notification_configured=bool(get_setting('notification_url', '')),
    )


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if is_configured():
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirmation = request.form.get('confirmation', '')
        if password != confirmation:
            flash('Passwords do not match')
        else:
            try:
                set_password(password)
                session.clear()
                session['logged_in'] = True
                csrf_token()
                return redirect(url_for('index'))
            except ValueError as exc:
                flash(str(exc))
    return render_template('setup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not is_configured():
        return redirect(url_for('setup'))
    client = request.remote_addr or 'local'
    remaining = _login_delay(client)
    if remaining:
        flash(f'Too many failed attempts. Try again in {remaining} seconds.')
        return render_template('login.html'), 429
    if request.method == 'POST':
        valid = check_password(request.form.get('password'))
        _record_login(client, valid)
        if valid:
            session.clear()
            session['logged_in'] = True
            csrf_token()
            return redirect(url_for('index'))
        flash('Invalid password')
    return render_template('login.html')


@app.post('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.post('/protection/pause')
@login_required
def pause_protection():
    if _confirm_admin_password():
        controller.stop_system()
        log_activity('', 'paused', 'Protection paused by administrator')
        notify_async('protection_paused', 'Network protection was paused by an authenticated administrator.', 'critical')
        flash('Protection is paused. It will resume automatically after a service restart or reboot.')
    return redirect(url_for('index'))


@app.post('/protection/resume')
@login_required
def resume_protection():
    if _confirm_admin_password():
        try:
            controller.start_system(proxy_manager=machine_proxy)
            log_activity('', 'resumed', 'Protection resumed by administrator')
            notify_async('protection_resumed', 'Network protection was resumed by an authenticated administrator.', 'info')
            flash('Protection is active')
        except RuntimeError as exc:
            flash(str(exc))
    return redirect(url_for('index'))


@app.post('/settings/notifications')
@login_required
def update_notifications():
    if not _confirm_admin_password():
        return redirect(url_for('index'))
    try:
        url = validate_notification_url(request.form.get('notification_url'))
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for('index'))
    set_setting('notification_url', url)
    supplied_secret = request.form.get('notification_secret', '').strip()
    if supplied_secret:
        set_setting('notification_secret', supplied_secret)
    elif request.form.get('clear_notification_secret') == '1':
        set_setting('notification_secret', '')
    if not url:
        flash('Immediate remote notifications are disabled')
    elif send_notification('notification_test', 'Immediate security notifications are configured.', 'info'):
        flash('Notification settings saved and test alert delivered')
    else:
        flash('Settings saved, but the test alert could not be delivered')
    return redirect(url_for('index'))


@app.post('/rules/add')
@login_required
def add_new_rule():
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='mode'").fetchone()
    mode = row['value'] if row else 'blacklist'
    default_action = 'allow' if mode == 'whitelist' else 'block'
    try:
        add_rule(request.form.get('domain'), request.form.get('category'), request.form.get('action', default_action))
        block_sites()
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for('index'))


@app.post('/rules/delete/<int:rule_id>')
@login_required
def remove_rule(rule_id):
    delete_rule(rule_id)
    block_sites()
    return redirect(url_for('index'))


@app.post('/settings/mode')
@login_required
def update_mode():
    mode = request.form.get('mode')
    if mode not in {'blacklist', 'whitelist'}:
        return ('Invalid mode', 400)
    with get_db() as conn:
        conn.execute("UPDATE settings SET value=? WHERE key='mode'", (mode,))
    block_sites()
    return redirect(url_for('index'))


@app.get('/logs')
@login_required
def view_logs():
    return render_template('logs.html', logs=get_logs(limit=200))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)