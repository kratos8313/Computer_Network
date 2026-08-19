import os
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault('NETGUARD_SECRET', 'test-secret-key-that-is-long-enough-123456')

import app as webapp
import desktop
import uninstall_guard
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

    def test_administrator_can_complete_setup_without_terminal(self):
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

    def test_cleanup_falls_back_only_for_netguard_proxy(self):
        with mock.patch.object(machine_proxy, '_load_backup', return_value=(None, None)), \
                mock.patch.object(machine_proxy, '_emergency_disable_managed_proxy', return_value=True) as disable, \
                mock.patch.object(machine_proxy, '_notify_windows') as notify:
            self.assertTrue(machine_proxy.disable_proxy())
        disable.assert_called_once_with()
        notify.assert_called_once_with()

    def test_cleanup_does_not_change_unrelated_proxy_without_backup(self):
        with mock.patch.object(machine_proxy, '_load_backup', return_value=(None, None)), \
                mock.patch.object(machine_proxy, '_emergency_disable_managed_proxy', return_value=False) as disable, \
                mock.patch.object(machine_proxy, '_notify_windows') as notify:
            self.assertFalse(machine_proxy.disable_proxy())
        disable.assert_called_once_with()
        notify.assert_not_called()

    def test_cleanup_finds_backup_in_legacy_data_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_backup = root / 'ChildSafe' / 'proxy_backup.json'
            legacy_backup.parent.mkdir()
            state = {
                'per_user': {'exists': False, 'value': None, 'kind': None},
                'enabled': {'exists': True, 'value': 0, 'kind': 4},
                'server': {'exists': False, 'value': None, 'kind': None},
            }
            legacy_backup.write_text(json.dumps(state), encoding='utf-8')
            with mock.patch.dict(os.environ, {'PROGRAMDATA': str(root)}), \
                    mock.patch.object(machine_proxy, 'PROXY_BACKUP_PATH', root / 'NetGuard' / 'proxy_backup.json'):
                path, loaded = machine_proxy._load_backup()
        self.assertEqual(path, legacy_backup)
        self.assertEqual(loaded, state)


class DesktopRecoveryTests(unittest.TestCase):
    def test_repair_requests_an_elevated_automatic_install(self):
        with mock.patch.object(desktop, 'run_elevated_service', return_value=True) as run:
            self.assertTrue(desktop.request_service_install())
        run.assert_called_once_with('--startup auto install')


class UninstallGuardTests(unittest.TestCase):
    def test_administrator_password_authorizes_uninstall(self):
        with mock.patch.object(uninstall_guard, 'password_configured', return_value=True), mock.patch.object(uninstall_guard, 'check_password', return_value=True), mock.patch.object(uninstall_guard, 'log') as log, mock.patch.object(uninstall_guard, 'log_activity') as activity, mock.patch.object(uninstall_guard, 'send_notification') as notify:
            self.assertTrue(uninstall_guard.authorize('correct horse'))
        log.assert_called_once_with('[SECURITY] Administrator-authorized uninstall.')
        activity.assert_called_once_with('', 'authorized', 'Administrator-authorized uninstall')
        notify.assert_called_once_with('uninstall_authorized', 'An administrator authorized application removal.', 'critical')

    def test_invalid_password_blocks_and_logs_uninstall(self):
        with mock.patch.object(uninstall_guard, 'password_configured', return_value=True), mock.patch.object(uninstall_guard, 'check_password', return_value=False), mock.patch.object(uninstall_guard, 'log') as log, mock.patch.object(uninstall_guard, 'log_activity') as activity, mock.patch.object(uninstall_guard, 'send_notification') as notify:
            self.assertFalse(uninstall_guard.authorize('wrong password'))
        log.assert_called_once_with('[SECURITY] Blocked uninstall attempt.')
        activity.assert_called_once_with('', 'denied', 'Invalid administrator password during uninstall attempt')
        notify.assert_called_once_with('uninstall_denied', 'An invalid administrator password was entered during an uninstall attempt.', 'critical')


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
