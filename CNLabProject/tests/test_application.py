import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault('PARENTAL_CONTROL_SECRET', 'test-secret-key-that-is-long-enough-123456')

import app as webapp
import desktop
from core import controller, database, machine_proxy


class InitialSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_patch = mock.patch.object(database, 'DB_PATH', root / 'setup.db')
        self.dir_patch = mock.patch.object(database, 'CONFIG_DIR', root)
        self.db_patch.start()
        self.dir_patch.start()
        database.init_db()
        webapp.app.config.update(TESTING=True)
        self.client = webapp.app.test_client()

    def tearDown(self):
        self.db_patch.stop()
        self.dir_patch.stop()
        self.temp.cleanup()

    def test_unconfigured_install_redirects_to_setup(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/setup'))

    def test_parent_can_complete_setup_without_terminal(self):
        with self.client.session_transaction() as session:
            session['_csrf_token'] = 'setup-token'
        response = self.client.post('/setup', data={
            '_csrf_token': 'setup-token',
            'password': 'correct horse',
            'confirmation': 'correct horse',
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(database.check_password('correct horse'))


class MachineProxyWatchdogTests(unittest.TestCase):
    def test_ensure_repairs_changed_proxy(self):
        with mock.patch.object(machine_proxy, 'is_proxy_enforced', return_value=False), mock.patch.object(machine_proxy, 'enable_proxy') as enable:
            self.assertTrue(machine_proxy.ensure_proxy())
            enable.assert_called_once_with('127.0.0.1:8080')

    def test_ensure_leaves_correct_proxy_untouched(self):
        with mock.patch.object(machine_proxy, 'is_proxy_enforced', return_value=True), mock.patch.object(machine_proxy, 'enable_proxy') as enable:
            self.assertFalse(machine_proxy.ensure_proxy())
            enable.assert_not_called()


class DesktopRecoveryTests(unittest.TestCase):
    def test_repair_requests_an_elevated_automatic_install(self):
        with mock.patch.object(desktop, 'run_elevated_service', return_value=True) as run:
            self.assertTrue(desktop.request_service_install())
        run.assert_called_once_with('--startup auto install')


class ControllerLifecycleTests(unittest.TestCase):
    def test_service_manager_is_enabled_watched_and_restored(self):
        ensured = threading.Event()

        class Manager:
            def __init__(self):
                self.enabled = False
                self.disabled = False
            def enable_proxy(self):
                self.enabled = True
            def ensure_proxy(self):
                ensured.set()
            def disable_proxy(self):
                self.disabled = True

        manager = Manager()

        def fake_proxy(ready, errors):
            ready.set()
            controller._stop_event.wait(2)

        with mock.patch.object(controller, 'start_proxy', side_effect=fake_proxy), mock.patch.object(controller, 'stop_proxy'), mock.patch('core.blocker.block_sites'), mock.patch('core.blocker.unblock_all') as unblock:
            controller.start_system(proxy_manager=manager)
            self.assertTrue(ensured.wait(1))
            controller.stop_system()

        self.assertTrue(manager.enabled)
        self.assertTrue(manager.disabled)
        unblock.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()