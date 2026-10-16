"""Create deterministic, allowlisted runtime archives; never publish them."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.3.0-rc.2'
DIRECTORIES = ('agent_harness', 'control_plane', 'sentinel_sdk', 'sentinel_sync', 'examples',
               'simulated_tools', 'contracts', 'policies', 'dashboard/dist', 'docs')
SUFFIXES = {'.py', '.json', '.cedar', '.html', '.css', '.js', '.svg', '.md'}


def build(binary, output, windows_wheel=None):
    windows = platform.system() == 'Windows'
    if windows and windows_wheel is None:
        raise ValueError('Windows releases require --windows-wheel for offline pywin32 installation')
    if not windows and windows_wheel is not None:
        raise ValueError('--windows-wheel is only valid on Windows')
    files = {}
    for directory in DIRECTORIES:
        for path in sorted((ROOT / directory).rglob('*')):
            if path.is_symlink():
                raise ValueError('Symlinks are forbidden in release inputs')
            if path.is_file() and path.suffix in SUFFIXES and '__pycache__' not in path.parts:
                files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    fixed = [('packaging/installer.py', 'installer.py'), ('packaging/sentinel', 'sentinel'),
             ('README.md', 'README.md'), ('requirements-sync.txt', 'requirements-sync.txt'),
             ('LICENSE', 'LICENSE'), ('packaging/third-party-notices.txt', 'THIRD_PARTY_NOTICES.txt'),
             ('docs/installation.md', 'INSTALL.md'), ('SECURITY.md', 'SECURITY.md')]
    for source, destination in fixed:
        files[destination] = (ROOT / source).read_bytes()
    binary_name = 'sentinel-runtime.exe' if windows else 'sentinel-runtime'
    files['bin/' + binary_name] = binary.read_bytes()
    if windows:
        wheel = Path(windows_wheel)
        if wheel.is_symlink() or not wheel.is_file() or wheel.name.lower() != 'pywin32-312-cp312-cp312-win_amd64.whl':
            raise ValueError('Expected the official pywin32-312-cp312-cp312-win_amd64.whl file')
        files['vendor/' + wheel.name] = wheel.read_bytes()
        with zipfile.ZipFile(wheel) as wheel_archive:
            names = wheel_archive.namelist()
            licenses = [entry for entry in names
                        if '/.dist-info/licenses/' in entry.lower() or
                        Path(entry).name.lower() in ('license.txt', 'license', 'copying.txt', 'copying')]
            licenses = [entry for entry in licenses if not entry.endswith('/')]
            if not licenses:
                raise ValueError('The pywin32 wheel must contain its license texts')
            for entry in sorted(set(licenses)):
                lower = entry.lower()
                marker = '.dist-info/licenses/'
                tail = entry[lower.find(marker) + len(marker):] if marker in lower else Path(entry).name
                from pathlib import PurePosixPath
                dest = 'vendor/pywin32-licenses/' + tail
                taken = {k.lower() for k in files}
                n = 2
                while dest.lower() in taken:
                    p = PurePosixPath(tail)
                    dest = 'vendor/pywin32-licenses/' + str(p.with_name(f'{p.stem}-{n}{p.suffix}'))
                    n += 1
                files[dest] = wheel_archive.read(entry)
    runtime = files['bin/' + binary_name]
    if any(marker in runtime for marker in (b'/Users/', b'/home/runner/', b'C:\\Users\\', b'\\_work\\')):
        raise ValueError('Build with Rust path remapping to avoid personal or runner paths')
    seen = {}
    for key in files:
        seen.setdefault(key.lower(), []).append(key)
    clashes = {k: v for k, v in seen.items() if len(v) > 1}
    if clashes:
        raise ValueError(f'Case-insensitive name collision in package: {clashes}')
    manifest = {'version': VERSION, 'system': platform.system(), 'machine': platform.machine(),
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
                'provenance': 'Local build; unsigned and not notarized; see CI and Cargo.lock'}
    files['MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    output.mkdir(parents=True, exist_ok=True)
    name = f'sentinel-ai-{VERSION}-{platform.system().lower()}-{platform.machine()}'
    if windows:
        archive = output / (name + '.zip')
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
            for filename, data in sorted(files.items()):
                info = zipfile.ZipInfo(name + '/' + filename, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100644 & 0xFFFF) << 16
                zipped.writestr(info, data)
    else:
        archive = output / (name + '.tar.gz')
        with archive.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as zipped, tarfile.open(fileobj=zipped, mode='w') as tar:
            for filename, data in sorted(files.items()):
                item = tarfile.TarInfo(name + '/' + filename)
                item.size = len(data)
                item.mode = 0o755 if filename in ('sentinel', 'bin/sentinel-runtime') else 0o644
                tar.addfile(item, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + '.sha256').write_text(digest + '  ' + archive.name + '\n')
    print(json.dumps({'artifact': archive.name, 'sha256': digest, 'files': len(files)}))
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    default_binary = ROOT / 'target' / 'release' / ('sentinel-runtime.exe' if platform.system() == 'Windows' else 'sentinel-runtime')
    parser.add_argument('--binary', type=Path, default=default_binary)
    parser.add_argument('--output', type=Path, default=ROOT / 'release-artifacts')
    parser.add_argument('--windows-wheel', type=Path)
    args = parser.parse_args()
    build(args.binary, args.output, args.windows_wheel)
