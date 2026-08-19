import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class PackagingSafetyTests(unittest.TestCase):
    def installer_text(self):
        return (ROOT / 'packaging' / 'NetGuard.iss').read_text(encoding='utf-8')

    def test_netguard_brand_is_used_for_build_and_installer(self):
        installer = self.installer_text()
        build_script = (ROOT / 'packaging' / 'build.ps1').read_text(encoding='utf-8')
        workflow = (ROOT / '.github' / 'workflows' / 'build-windows.yml').read_text(encoding='utf-8')
        self.assertIn('#define AppName "NetGuard Access Control"', installer)
        self.assertIn('OutputBaseFilename=NetGuard-Setup', installer)
        self.assertIn('NetGuardService.spec', build_script)
        self.assertIn('NetGuard-Windows-Installer', workflow)
        self.assertIn('installer-output/NetGuard-Setup.exe', workflow)

    def test_legacy_service_is_removed_only_after_netguard_starts(self):
        installer = self.installer_text()
        self.assertIn('#define LegacyServiceName "ChildSafeService"', installer)
        install_service = installer.split('procedure InstallService;', 1)[1]
        self.assertLess(
            install_service.index("ExecRequired(ServiceExe, 'start'"),
            install_service.index("Exec(ExpandConstant('{sys}\\sc.exe'), 'delete {#LegacyServiceName}'"),
        )
    def test_uninstaller_always_runs_policy_cleanup(self):
        installer = self.installer_text()
        self.assertIn('Parameters: "cleanup"', installer)
        self.assertIn('RunOnceId: "CleanupPolicy"', installer)
        self.assertIn('procedure EmergencyDisableManagedProxy', installer)
        self.assertIn("CompareText(Trim(ProxyServer), '127.0.0.1:8080')", installer)
        self.assertIn('CurUninstallStep = usPostUninstall', installer)
        self.assertIn("'stop {#ServiceName}'", installer)
        self.assertIn("'delete {#ServiceName}'", installer)
        self.assertLess(
            installer.index('CurUninstallStep = usUninstall'),
            installer.rindex('EmergencyDisableManagedProxy;'),
        )

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
        self.assertIn('NetGuardUninstallGuard\\*', installer)
        self.assertIn('function InitializeUninstall', installer)
        self.assertIn('NetGuardUninstallGuard.exe', installer)
        self.assertIn('NetGuardUninstallGuard.spec', build_script)
        self.assertTrue((ROOT / 'packaging' / 'NetGuardUninstallGuard.spec').exists())
        self.assertTrue((ROOT / 'CNLabProject' / 'uninstall_guard.py').exists())

    def test_service_registration_has_no_import_time_app_initialization(self):
        service = (ROOT / 'CNLabProject' / 'service.py').read_text(encoding='utf-8')
        prefix = service.split('class NetGuardService', 1)[0]
        runtime_prefix = service.split('def SvcDoRun', 1)[0]
        self.assertNotIn('ensure_data_dir(restrict=True)', prefix)
        self.assertNotIn('from app import app', runtime_prefix)
        self.assertIn("sys.argv[1].lower() == 'cleanup'", service)

    def test_service_restores_network_before_sending_stop_notification(self):
        service = (ROOT / 'CNLabProject' / 'service.py').read_text(encoding='utf-8')
        stop_handler = service.split('def SvcStop', 1)[1].split('def SvcDoRun', 1)[0]
        self.assertLess(stop_handler.index('stop_system()'), stop_handler.index('send_notification('))


if __name__ == '__main__':
    unittest.main()
