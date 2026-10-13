"""Create deterministic, allowlisted runtime tarballs; never publish them."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.3.0-rc.1'
DIRECTORIES = ('agent_harness', 'control_plane', 'sentinel_sdk', 'sentinel_sync', 'examples',
               'simulated_tools', 'contracts', 'policies', 'dashboard/dist', 'docs')
SUFFIXES = {'.py', '.json', '.cedar', '.html', '.css', '.js', '.svg', '.md'}


def build(binary, output):
    files = {}
    for directory in DIRECTORIES:
        for path in sorted((ROOT / directory).rglob('*')):
            if path.is_symlink():
                raise ValueError('Symlinks are forbidden in release inputs')
            if path.is_file() and path.suffix in SUFFIXES and '__pycache__' not in path.parts:
                files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    for source, destination in [('packaging/installer.py', 'installer.py'), ('packaging/sentinel', 'sentinel'),
                                ('README.md', 'README.md'), ('requirements-sync.txt', 'requirements-sync.txt'), ('LICENSE', 'LICENSE'), ('packaging/third-party-notices.txt', 'THIRD_PARTY_NOTICES.txt'), ('docs/installation.md', 'INSTALL.md'), ('SECURITY.md', 'SECURITY.md')]:
        files[destination] = (ROOT / source).read_bytes()
    files['bin/sentinel-runtime'] = binary.read_bytes()
    if b'/Users/' in files['bin/sentinel-runtime'] or b'/home/runner/' in files['bin/sentinel-runtime']:
        raise ValueError('Build with RUSTFLAGS=--remap-path-prefix=<build-root>=/sentinel-build')
    manifest = {'version': VERSION, 'system': platform.system(), 'machine': platform.machine(),
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
                'provenance': 'Local build; unsigned and not notarized; see CI and Cargo.lock'}
    files['MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    output.mkdir(parents=True, exist_ok=True)
    name = f'sentinel-ai-{VERSION}-{platform.system().lower()}-{platform.machine()}'
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
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/sentinel-runtime')
    parser.add_argument('--output', type=Path, default=ROOT / 'release-artifacts')
    args = parser.parse_args()
    build(args.binary, args.output)
