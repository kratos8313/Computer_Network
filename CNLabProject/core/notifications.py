import json
import socket
import threading
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.database import get_setting, log_activity
from utils.logger import log

_alert_lock = threading.Lock()
_recent_blocked = {}
BLOCKED_ALERT_WINDOW = 300


def validate_notification_url(value):
    value = (value or '').strip()
    if not value:
        return ''
    if len(value) > 2048:
        raise ValueError('Notification URL is too long')
    parsed = urlparse(value)
    if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError('Notification URL must be a valid HTTPS address without embedded credentials')
    return value


def _log_delivery_failure(event, exc):
    log(f'[NOTIFICATION ERROR] {event}: {exc}')
    try:
        log_activity('', 'notification_failed', f'{event}: {exc}')
    except Exception as log_exc:
        log(f'[NOTIFICATION LOG ERROR] {event}: {log_exc}')


def notification_configured():
    try:
        return bool(get_setting('notification_url', ''))
    except Exception as exc:
        _log_delivery_failure('configuration_read', exc)
        return False


def send_notification(event, message, severity='warning'):
    try:
        url = get_setting('notification_url', '')
        if not url:
            return False
        secret = get_setting('notification_secret', '')
        payload = json.dumps({
            'application': 'ChildSafe Network Control',
            'event': event,
            'severity': severity,
            'message': message,
            'computer': socket.gethostname(),
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'ChildSafe-Network-Control/1.1',
        }
        if secret:
            headers['Authorization'] = f'Bearer {secret}'
        request = urllib.request.Request(url, data=payload, headers=headers, method='POST')
        with urllib.request.urlopen(request, timeout=5) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f'notification endpoint returned HTTP {response.status}')
        try:
            log_activity('', 'notified', f'{event}: immediate notification delivered')
        except Exception as exc:
            log(f'[NOTIFICATION LOG ERROR] {event}: {exc}')
        return True
    except Exception as exc:
        _log_delivery_failure(event, exc)
        return False


def notify_blocked_activity(domain, reason):
    if not notification_configured():
        return False
    key = (domain or '').strip().lower()
    now = time.monotonic()
    with _alert_lock:
        previous = _recent_blocked.get(key)
        if previous is not None and now - previous < BLOCKED_ALERT_WINDOW:
            return False
        _recent_blocked[key] = now
        if len(_recent_blocked) > 1000:
            cutoff = now - BLOCKED_ALERT_WINDOW
            for item, timestamp in list(_recent_blocked.items()):
                if timestamp < cutoff:
                    _recent_blocked.pop(item, None)
    return notify_async(
        'blocked_network_activity',
        f'Blocked access to {domain}. Reason: {reason}',
        'warning',
    )


def notify_async(event, message, severity='warning'):
    if not notification_configured():
        return False
    threading.Thread(
        target=send_notification,
        args=(event, message, severity),
        daemon=True,
        name='ChildSafeNotification',
    ).start()
    return True