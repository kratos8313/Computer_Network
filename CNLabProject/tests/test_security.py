import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import blocker, database, notifications, proxy
import os
os.environ.setdefault('PARENTAL_CONTROL_SECRET', 'test-secret-key-that-is-long-enough-123456')
import app as webapp


class DatabaseSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_patch = mock.patch.object(database, 'DB_PATH', root / 'control.db')
        self.dir_patch = mock.patch.object(database, 'CONFIG_DIR', root)
        self.db_patch.start()
        self.dir_patch.start()
        database.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.dir_patch.stop()
        self.temp.cleanup()

    def test_password_uses_scrypt(self):
        database.set_password('correct horse')
        self.assertTrue(database.check_password('correct horse'))
        self.assertFalse(database.check_password('wrong password'))
        with database.get_db() as conn:
            stored = conn.execute("SELECT value FROM settings WHERE key='password'").fetchone()['value']
        self.assertTrue(stored.startswith('scrypt:'))

    def test_legacy_hash_is_migrated(self):
        legacy = hashlib.sha256(b'old password').hexdigest()
        with database.get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO settings VALUES ('password', ?)", (legacy,))
        self.assertTrue(database.check_password('old password'))
        with database.get_db() as conn:
            stored = conn.execute("SELECT value FROM settings WHERE key='password'").fetchone()['value']
        self.assertTrue(stored.startswith('scrypt:'))

    def test_security_alerts_include_denied_attempts_only(self):
        database.log_activity('', 'authorized', 'Expected administrator action')
        database.log_activity('', 'denied', 'Blocked uninstall attempt')
        alerts = database.get_security_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['reason'], 'Blocked uninstall attempt')


class HostsContentTests(unittest.TestCase):
    def test_managed_block_preserves_system_lines(self):
        original = ['127.0.0.1 localhost\n']
        result = blocker.managed_content(original, ['example.com'])
        self.assertEqual(result[0], original[0])
        self.assertIn('127.0.0.1 example.com\n', result)
        self.assertIn('::1 example.com\n', result)

    def test_malformed_markers_are_rejected(self):
        with self.assertRaises(ValueError):
            blocker.managed_content([blocker.MARKER_START], [])


class ProxyParsingTests(unittest.TestCase):
    def test_authority_parser_supports_ipv6(self):
        self.assertEqual(proxy._parse_authority('[2606:4700:4700::1111]:443', 443), ('2606:4700:4700::1111', 443))

    def test_disallowed_port_is_rejected(self):
        with self.assertRaises(ValueError):
            proxy._validate_destination('example.com', 22, {443})


class NotificationSecurityTests(unittest.TestCase):
    def test_notification_url_requires_https_without_embedded_credentials(self):
        with self.assertRaises(ValueError):
            notifications.validate_notification_url('http://example.org/alert')
        with self.assertRaises(ValueError):
            notifications.validate_notification_url('https://user:pass@example.org/alert')
        self.assertEqual(
            notifications.validate_notification_url('https://example.org/alert'),
            'https://example.org/alert',
        )

    def test_notification_payload_contains_machine_event_and_bearer_secret(self):
        response = mock.MagicMock()
        response.status = 204
        response.__enter__.return_value = response
        settings = {'notification_url': 'https://example.org/alert', 'notification_secret': 'secret-token'}
        with mock.patch.object(notifications, 'get_setting', side_effect=lambda key, default='': settings.get(key, default)), mock.patch.object(notifications.urllib.request, 'urlopen', return_value=response) as open_url, mock.patch.object(notifications, 'log_activity') as activity:
            self.assertTrue(notifications.send_notification('test_event', 'Test message', 'critical'))
        request = open_url.call_args.args[0]
        payload = json.loads(request.data.decode('utf-8'))
        self.assertEqual(payload['event'], 'test_event')
        self.assertEqual(payload['severity'], 'critical')
        self.assertTrue(payload['computer'])
        self.assertEqual(request.get_header('Authorization'), 'Bearer secret-token')
        activity.assert_called_once_with('', 'notified', 'test_event: immediate notification delivered')

    def test_notification_configuration_failure_does_not_escape(self):
        with mock.patch.object(notifications, 'get_setting', side_effect=RuntimeError('database unavailable')), mock.patch.object(notifications, 'log_activity'), mock.patch.object(notifications, 'log'):
            self.assertFalse(notifications.notification_configured())
            self.assertFalse(notifications.send_notification('test_event', 'Test message'))

    def test_blocked_activity_notifications_are_deduplicated(self):
        notifications._recent_blocked.clear()
        with mock.patch.object(
            notifications,
            'notification_configured',
            return_value=True,
        ), mock.patch.object(
            notifications.time,
            'monotonic',
            side_effect=[100, 101, 401],
        ), mock.patch.object(
            notifications,
            'notify_async',
            return_value=True,
        ) as notify:
            self.assertTrue(notifications.notify_blocked_activity('Example.com', 'Blocked by policy'))
            self.assertFalse(notifications.notify_blocked_activity('example.com', 'Blocked by policy'))
            self.assertTrue(notifications.notify_blocked_activity('example.com', 'Blocked by policy'))

        self.assertEqual(notify.call_count, 2)
        notify.assert_called_with(
            'blocked_network_activity',
            'Blocked access to example.com. Reason: Blocked by policy',
            'warning',
        )


class WebSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_patch = mock.patch.object(database, 'DB_PATH', root / 'web.db')
        self.dir_patch = mock.patch.object(database, 'CONFIG_DIR', root)
        self.block_patch = mock.patch.object(webapp, 'block_sites', lambda: None)
        self.db_patch.start()
        self.dir_patch.start()
        self.block_patch.start()
        database.init_db()
        database.set_password('correct horse')
        webapp.app.config.update(TESTING=True)
        webapp._login_failures.clear()
        self.client = webapp.app.test_client()

    def tearDown(self):
        self.block_patch.stop()
        self.db_patch.stop()
        self.dir_patch.stop()
        self.temp.cleanup()

    def test_login_is_rate_limited(self):
        with self.client.session_transaction() as session:
            session['_csrf_token'] = 'login-token'
        for _ in range(5):
            self.client.post('/login', data={'password': 'wrong password', '_csrf_token': 'login-token'})
        response = self.client.post('/login', data={'password': 'wrong password', '_csrf_token': 'login-token'})
        self.assertEqual(response.status_code, 429)

    def authenticated_session(self):
        with self.client.session_transaction() as session:
            session['logged_in'] = True
            session['_csrf_token'] = 'control-token'

    def test_administrator_can_pause_protection_after_password_confirmation(self):
        self.authenticated_session()
        with mock.patch.object(webapp.controller, 'stop_system') as stop:
            response = self.client.post('/protection/pause', data={
                'password': 'correct horse',
                '_csrf_token': 'control-token',
            })
        self.assertEqual(response.status_code, 302)
        stop.assert_called_once_with()

    def test_wrong_password_cannot_pause_protection(self):
        self.authenticated_session()
        with mock.patch.object(webapp.controller, 'stop_system') as stop:
            response = self.client.post('/protection/pause', data={
                'password': 'wrong password',
                '_csrf_token': 'control-token',
            })
        self.assertEqual(response.status_code, 302)
        stop.assert_not_called()

    def test_administrator_can_resume_protection_after_password_confirmation(self):
        self.authenticated_session()
        with mock.patch.object(webapp.controller, 'start_system') as start:
            response = self.client.post('/protection/resume', data={
                'password': 'correct horse',
                '_csrf_token': 'control-token',
            })
        self.assertEqual(response.status_code, 302)
        start.assert_called_once_with(proxy_manager=webapp.machine_proxy)

    def test_health_reports_protection_state(self):
        with mock.patch.object(webapp.controller, 'is_protection_running', return_value=False):
            response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {'service': 'running', 'protection': False})

    def test_administrator_can_save_and_test_notification_endpoint(self):
        self.authenticated_session()
        with mock.patch.object(webapp, 'send_notification', return_value=True) as notify:
            response = self.client.post('/settings/notifications', data={
                'password': 'correct horse',
                'notification_url': 'https://example.org/security',
                'notification_secret': 'secret-token',
                '_csrf_token': 'control-token',
            })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(database.get_setting('notification_url'), 'https://example.org/security')
        self.assertEqual(database.get_setting('notification_secret'), 'secret-token')
        notify.assert_called_once_with('notification_test', 'Immediate security notifications are configured.', 'info')

    def test_templates_render(self):
        self.assertEqual(self.client.get('/login').status_code, 200)

    def test_state_change_requires_csrf(self):
        with self.client.session_transaction() as session:
            session['logged_in'] = True
            session['_csrf_token'] = 'expected-token'
        self.assertEqual(self.client.post('/settings/mode', data={'mode': 'blacklist'}).status_code, 400)
        response = self.client.post('/settings/mode', data={'mode': 'blacklist', '_csrf_token': 'expected-token'})
        self.assertEqual(response.status_code, 302)

if __name__ == '__main__':
    unittest.main()
