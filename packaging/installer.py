#!/usr/bin/env python3
"""Offline, user-owned, side-by-side installer. Requires Python 3.12+ with venv."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import venv

ROOT = Path(__file__).resolve().parent
MARKER = '.sentinel-install.json'


def verify(root):
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    if manifest['system'] != platform.system() or manifest['machine'] != platform.machine():
        raise ValueError('Package platform does not match this machine')
    for name, digest in manifest['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unsafe manifest path')
        file = root / relative
        if file.is_symlink() or hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise ValueError('Package verification failed')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True, help='New version-specific user-owned directory')
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()
    prefix = args.prefix.absolute()
    if os.name == 'nt' or sys.version_info < (3, 12):
        raise SystemExit('Use Python 3.12+ on macOS/Linux; Windows uses WSL2')
    if os.geteuid() == 0:
        raise SystemExit('Do not install or uninstall as root')
    if prefix.is_symlink() or prefix in (Path('/'), Path.home(), ROOT):
        raise SystemExit('Unsafe installation prefix')
    if args.uninstall:
        marker = prefix / MARKER
        if not marker.is_file() or marker.is_symlink() or prefix.stat().st_uid != os.getuid():
            raise SystemExit('Not a user-owned Sentinel installation')
        record = json.loads(marker.read_text())
        if record.get('prefix') != str(prefix) or record.get('product') != 'sentinel-ai':
            raise SystemExit('Installation marker mismatch')
        if (prefix / '.local-state').exists():
            raise SystemExit('Move private .local-state to a safe backup before uninstalling')
        shutil.rmtree(prefix)
        print('Installation removed; externally stored state was not changed')
        return
    manifest = verify(ROOT)
    if prefix.exists():
        raise SystemExit('Prefix already exists; use a new version-specific directory')
    if not prefix.parent.is_dir() or prefix.parent.is_symlink():
        raise SystemExit('Choose an existing trusted parent directory')
    prefix.mkdir(mode=0o700)
    try:
        # Copy only verified files; no unlisted files from an extracted archive.
        for name in manifest['files']:
            dest = prefix / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
            dest.chmod(0o700 if name in ('bin/sentinel-runtime', 'sentinel') else 0o600)
        venv.EnvBuilder(with_pip=False).create(prefix / '.venv')
        (prefix / MARKER).write_text(json.dumps({'product': 'sentinel-ai', 'prefix': str(prefix), 'version': manifest['version']}))
        (prefix / MARKER).chmod(0o600)
    except Exception:
        shutil.rmtree(prefix)
        raise
    print('Installed. Run: ' + str(prefix / 'sentinel') + ' example')


if __name__ == '__main__':
    main()
