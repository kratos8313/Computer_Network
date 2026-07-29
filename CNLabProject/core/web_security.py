import os
import secrets
from flask import abort, request, session
from core.paths import CONFIG_DIR, SECRET_KEY_PATH


def load_or_create_secret():
    configured = os.environ.get('NETGUARD_SECRET') or os.environ.get('PARENTAL_CONTROL_SECRET')
    if configured:
        if len(configured) < 32:
            raise RuntimeError('NETGUARD_SECRET must be at least 32 characters')
        return configured
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        value = SECRET_KEY_PATH.read_text(encoding='utf-8').strip()
        if value:
            return value
    except FileNotFoundError:
        pass
    value = secrets.token_urlsafe(48)
    SECRET_KEY_PATH.write_text(value, encoding='utf-8')
    return value


def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


def validate_csrf():
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        supplied = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
        expected = session.get('_csrf_token')
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            abort(400, 'Invalid CSRF token')
