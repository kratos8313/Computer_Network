import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import blocker, database, proxy
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
