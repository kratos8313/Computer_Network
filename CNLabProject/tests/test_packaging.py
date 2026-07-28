import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class PackagingSafetyTests(unittest.TestCase):
    def installer_text(self):
        return (ROOT / 'packaging' / 'ChildSafe.iss').read_text(encoding='utf-8')

    def test_uninstaller_always_runs_policy_cleanup(self):
        installer = self.installer_text()
        self.assertIn('Parameters: "cleanup"', installer)
        self.assertIn('RunOnceId: "CleanupPolicy"', installer)

    def test_service_registration_fails_setup_cleanly(self):
        installer = self.installer_text()
        self.assertIn('AfterInstall: InstallService', installer)
        self.assertIn('procedure ExecRequired', installer)
        self.assertIn('RaiseException(ErrorMessage', installer)
        self.assertIn('if not ServiceExists then', installer)
        self.assertIn("'--startup auto install'", installer)
        self.assertIn("'--startup auto update'", installer)
        self.assertNotIn("'install --startup auto'", installer)
        self.assertNotIn("'update --startup auto'", installer)

    def test_upgrade_stops_service_without_restart_manager(self):
        installer = self.installer_text()
        self.assertIn('function PrepareToInstall', installer)
        self.assertIn("'stop {#ServiceName}'", installer)
        self.assertIn('CloseApplications=no', installer)
        self.assertIn('RestartApplications=no', installer)

    def test_uninstall_requires_the_administrator_guard(self):
        installer = self.installer_text()
        build_script = (ROOT / 'packaging' / 'build.ps1').read_text(encoding='utf-8')
        self.assertIn('ChildSafeUninstallGuard\\*', installer)
        self.assertIn('function InitializeUninstall', installer)
        self.assertIn('ChildSafeUninstallGuard.exe', installer)
        self.assertIn('ChildSafeUninstallGuard.spec', build_script)
        self.assertTrue((ROOT / 'packaging' / 'ChildSafeUninstallGuard.spec').exists())
        self.assertTrue((ROOT / 'CNLabProject' / 'uninstall_guard.py').exists())

    def test_service_registration_has_no_import_time_app_initialization(self):
        service = (ROOT / 'CNLabProject' / 'service.py').read_text(encoding='utf-8')
        prefix = service.split('class ChildSafeService', 1)[0]
        runtime_prefix = service.split('def SvcDoRun', 1)[0]
        self.assertNotIn('ensure_data_dir(restrict=True)', prefix)
        self.assertNotIn('from app import app', runtime_prefix)
        self.assertIn("sys.argv[1].lower() == 'cleanup'", service)


if __name__ == '__main__':
    unittest.main()