#!/usr/bin/env python3
"""Offline, user-owned, side-by-side installer. Requires Python 3.12+ with venv."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parent
MARKER = '.sentinel-install.json'
REPARSE_POINT = 0x400
WINDOWS_ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$p = [System.IO.Path]::GetFullPath($env:SENTINEL_INSTALL_PREFIX)
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
if ($env:SENTINEL_INSTALL_ACL_MODE -eq 'create') {
    if ([System.IO.Directory]::Exists($p) -or [System.IO.File]::Exists($p)) { throw 'Install prefix already exists' }
    $newAcl = New-Object System.Security.AccessControl.DirectorySecurity
    $newAcl.SetAccessRuleProtection($true, $false)
    $newAcl.SetOwner($current)
    foreach ($sid in @($current, $system)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
        $newAcl.AddAccessRule($rule)
    }
    [System.IO.Directory]::CreateDirectory($p, $newAcl) | Out-Null
}
$acl = Get-Acl -LiteralPath $p
if (-not $acl.AreAccessRulesProtected) { throw 'Install DACL is not protected' }
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $current.Value) { throw 'Unexpected install directory owner' }
$rules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
if ($rules.Count -ne 2) { throw 'Install DACL must contain only user and SYSTEM rules' }
$allowed = @($current.Value, $system.Value)
foreach ($rule in $rules) {
    if ($rule.IdentityReference.Value -notin $allowed) { throw 'Unexpected install DACL principal' }
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { throw 'Unexpected install DACL rule type' }
    if ($rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl) { throw 'Unexpected install DACL rights' }
    if (($rule.InheritanceFlags -band $inherit) -ne $inherit) { throw 'Install DACL must protect child files and directories' }
    if ($rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) { throw 'Unexpected install DACL propagation' }
}
"""


def _is_reparse(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return bool(getattr(info, 'st_file_attributes', 0) & REPARSE_POINT)


def _check_windows_path(prefix, *, must_not_exist=False):
    raw = str(prefix)
    if not prefix.drive or len(prefix.drive) != 2 or prefix.root != '\\' or raw.startswith('\\\\') or ':' in raw[2:]:
        raise ValueError('Windows installation requires a local drive path without alternate streams')
    if not prefix.parent.is_dir():
        raise ValueError('Choose an existing trusted parent directory')
    for ancestor in (prefix.parent, *prefix.parent.parents):
        if _is_reparse(ancestor):
            raise ValueError('Windows installation parent cannot contain reparse points')
    if must_not_exist and (prefix.exists() or prefix.is_symlink() or _is_reparse(prefix)):
        raise ValueError('Prefix already exists; use a new version-specific directory')


def _windows_volume_has_persistent_acls(prefix):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    get_info = kernel.GetVolumeInformationW
    get_info.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint,
                         ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
                         ctypes.POINTER(ctypes.c_uint), ctypes.c_wchar_p, ctypes.c_uint]
    get_info.restype = ctypes.c_int
    flags = ctypes.c_uint(0)
    root = prefix.drive + '\\'
    if not get_info(root, None, 0, None, None, ctypes.byref(flags), None, 0) or not (flags.value & 0x8):
        raise ValueError('Installation drive must support persistent filesystem ACLs')


def _windows_acl(prefix, mode):
    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    if not shell.is_file():
        raise RuntimeError('Windows PowerShell is required to establish installation ACLs')
    environment = dict(os.environ)
    environment['SENTINEL_INSTALL_PREFIX'] = str(prefix)
    environment['SENTINEL_INSTALL_ACL_MODE'] = mode
    result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', WINDOWS_ACL_SCRIPT],
                            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError('Windows installation ACL validation failed: ' + result.stderr.strip()[-500:])


def _tree_has_reparse(root):
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in dirs + files:
            if _is_reparse(base / name):
                return True
    return False


def verify(root):
    manifest = json.loads((root / 'MANIFEST.json').read_text(encoding='utf-8'))
    if manifest['system'] != platform.system() or manifest['machine'] != platform.machine():
        raise ValueError('Package platform does not match this machine')
    for name, digest in manifest['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name:
            raise ValueError('Unsafe manifest path')
        file = root / relative
        if not file.is_file() or file.is_symlink() or _is_reparse(file):
            raise ValueError('Unsafe package file')
        for parent in file.parents:
            if parent == root.parent:
                break
            if parent != root and _is_reparse(parent):
                raise ValueError('Reparse point in package path')
        if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise ValueError(f'Package verification failed: {name}')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True, help='New version-specific user-owned directory')
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()
    prefix = Path(os.path.abspath(args.prefix.expanduser()))
    windows = os.name == 'nt'
    if sys.version_info < (3, 12):
        raise SystemExit('Python 3.12+ is required')
    if windows and sys.version_info[:2] != (3, 12):
        raise SystemExit('The Windows package requires Python 3.12 for its bundled pywin32 wheel')
    if windows:
        _check_windows_path(prefix, must_not_exist=not args.uninstall)
        _windows_volume_has_persistent_acls(prefix)
        if prefix in (Path(os.path.abspath(Path.home())), ROOT):
            raise SystemExit('Unsafe installation prefix')
    else:
        if os.geteuid() == 0:
            raise SystemExit('Do not install or uninstall as root')
        if prefix.is_symlink() or prefix in (Path('/'), Path.home(), ROOT):
            raise SystemExit('Unsafe installation prefix')
    if args.uninstall:
        marker = prefix / MARKER
        if not marker.is_file() or marker.is_symlink() or _is_reparse(marker):
            raise SystemExit('Not a marked Sentinel installation')
        record = json.loads(marker.read_text(encoding='utf-8'))
        if record.get('prefix') != str(prefix) or record.get('product') != 'sentinel-ai':
            raise SystemExit('Installation marker mismatch')
        if (prefix / '.local-state').exists():
            raise SystemExit('Move private .local-state to a safe backup before uninstalling')
        if windows:
            if _is_reparse(prefix):
                raise SystemExit('Refusing to uninstall a reparse-point installation root')
            _windows_acl(prefix, 'verify')
            if _tree_has_reparse(prefix):
                raise SystemExit('Refusing to uninstall a tree containing reparse points')
        elif prefix.stat().st_uid != os.getuid():
            raise SystemExit('Not a user-owned Sentinel installation')
        shutil.rmtree(prefix)
        print('Installation removed; externally stored state was not changed')
        return
    manifest = verify(ROOT)
    if prefix.exists():
        raise SystemExit('Prefix already exists; use a new version-specific directory')
    if not prefix.parent.is_dir() or (not windows and prefix.parent.is_symlink()):
        raise SystemExit('Choose an existing trusted parent directory')
    if windows:
        _windows_acl(prefix, 'create')
    else:
        prefix.mkdir(mode=0o700)
    try:
        for name in manifest['files']:
            if windows and name.startswith('vendor/') and name.lower().endswith('.whl'):
                continue
            dest = prefix / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
            if not windows:
                dest.chmod(0o700 if name in ('bin/sentinel-runtime', 'sentinel') else 0o600)
        venv.EnvBuilder(with_pip=windows).create(prefix / '.venv')
        if windows:
            wheels = [name for name in manifest['files'] if name.startswith('vendor/') and name.lower().endswith('.whl')]
            if len(wheels) != 1 or not wheels[0].lower().endswith('pywin32-312-cp312-cp312-win_amd64.whl'):
                raise ValueError('Windows package must contain the pinned offline pywin32 312 wheel')
            python = prefix / '.venv' / 'Scripts' / 'python.exe'
            subprocess.run([str(python), '-m', 'pip', 'install', '--no-index', '--no-deps', str(ROOT / wheels[0])],
                           check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        marker_data = {'product': 'sentinel-ai', 'prefix': str(prefix), 'version': manifest['version']}
        marker = prefix / MARKER
        marker.write_text(json.dumps(marker_data, sort_keys=True) + '\n', encoding='utf-8')
        if not windows:
            marker.chmod(0o600)
    except Exception:
        if prefix.exists() and (not windows or not _tree_has_reparse(prefix)):
            shutil.rmtree(prefix)
        raise
    if windows:
        print('Installed. Run in PowerShell: & "' + str(prefix / '.venv' / 'Scripts' / 'python.exe') + '" "' + str(prefix / 'sentinel') + '" example')
    else:
        print('Installed. Run: ' + str(prefix / 'sentinel') + ' example')


if __name__ == '__main__':
    main()
