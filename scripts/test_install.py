"""Verify archive integrity, installed gateway execution and safe uninstall offline."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def safe_member(name):
    path = PurePosixPath(name)
    return not path.is_absolute() and '..' not in path.parts and not '\\' in name and ':' not in name


def main():
    windows = platform.system() == 'Windows'
    suffix = '.zip' if windows else '.tar.gz'
    pattern = '*-' + platform.system().lower() + '-' + platform.machine() + suffix
    archives = list((ROOT / 'release-artifacts').glob(pattern))
    assert len(archives) == 1, 'Use a clean platform artifact directory'
    archive = archives[0]
    checksum = archive.with_suffix(archive.suffix + '.sha256').read_text().split()[0]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == checksum
    with tempfile.TemporaryDirectory(prefix='sentinel-install-test-') as temp:
        temp = Path(temp)
        if windows:
            with zipfile.ZipFile(archive) as zipped:
                assert all(safe_member(item.filename) for item in zipped.infolist())
                zipped.extractall(temp)
            package = temp / archive.name.removesuffix('.zip')
        else:
            with tarfile.open(archive) as tar:
                assert all(safe_member(item.name) for item in tar.getmembers())
                tar.extractall(temp, filter='data')
            package = temp / archive.name.removesuffix('.tar.gz')
        prefix = temp / 'installed'
        installer = [sys.executable, str(package / 'installer.py')]
        subprocess.run(installer + ['--prefix', str(prefix)], check=True, capture_output=True, text=True)
        if windows:
            executable = [str(prefix / '.venv' / 'Scripts' / 'python.exe'), str(prefix / 'sentinel')]
        else:
            executable = [str(prefix / 'sentinel')]
        result = subprocess.run(executable + ['example'], check=True, capture_output=True, text=True)
        assert ['ALLOW', 'ALLOW', 'DENY', 'REQUIRE_APPROVAL'] == [line.split()[1] for line in result.stdout.splitlines()]
        duplicate = subprocess.run(installer + ['--prefix', str(prefix)], capture_output=True)
        assert duplicate.returncode != 0
        subprocess.run(installer + ['--uninstall', '--prefix', str(prefix)], check=True, capture_output=True)
        assert not prefix.exists()
        data = package / 'contracts' / 'report-task.json'
        data.write_text('{}')
        tamper = subprocess.run(installer + ['--prefix', str(prefix)], capture_output=True)
        assert tamper.returncode != 0 and not prefix.exists()
    report = {'status': 'passed', 'checks': ['archive_checksum', 'offline_install',
              'real_installed_gateway_allow_deny_approval', 'refuse_overwrite', 'marked_uninstall',
              'tampered_manifest_rejected'], 'artifact': archive.name}
    report_path = ROOT / 'reports' / f'public-installer-{platform.system().lower()}.json'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
