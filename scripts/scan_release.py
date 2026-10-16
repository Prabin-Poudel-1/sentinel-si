"""High-signal pre-publication checks. Not a replacement for full Git-history review."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.venv', '.local-state', 'target', 'node_modules', '.wrangler', '__pycache__', '.pytest_cache', 'release-artifacts', 'reports', 'work'}
PATTERNS = [re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
            re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'), re.compile(rb'github_pat_[A-Za-z0-9_]{40,}'),
            re.compile(rb'AKIA[0-9A-Z]{16}'), re.compile(rb'/Users/[a-zA-Z][^/\s]{2,}/')]
FORBIDDEN = {'.local-state', '.dev.vars', '.env', 'node_modules', '.git', '.venv', '.wrangler', 'reports'}


def inspect(name, data):
    parts = PurePosixPath(name).parts
    if any(p in FORBIDDEN for p in parts) or name.endswith(('.sqlite', '.sqlite-wal', '.sqlite-shm', '.pem', '.key', '.p12', '.pfx', '.xml')):
        return 'forbidden_private_file'
    if any(pattern.search(data) for pattern in PATTERNS):
        return 'secret_or_personal_path_pattern'
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', action='store_true')
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    findings, count = [], 0
    if args.source:
        for path in ROOT.rglob('*'):
            if set(path.relative_to(ROOT).parts) & EXCLUDED or not path.is_file():
                continue
            if path.name == 'scan_release.py':
                continue
            name = path.relative_to(ROOT).as_posix()
            reason = inspect(name, path.read_bytes()); count += 1
            if reason:
                findings.append({'file': name, 'finding': reason})
    if args.artifacts:
        archives = [*args.artifacts.glob('*.tar.gz'), *args.artifacts.glob('*.zip')]
        for archive in archives:
            if archive.suffix.lower() == '.zip':
                with zipfile.ZipFile(archive) as zipped:
                    for item in zipped.infolist():
                        member = PurePosixPath(item.filename)
                        mode = (item.external_attr >> 16) & 0o170000
                        if member.is_absolute() or '..' in member.parts or '\\' in item.filename or ':' in item.filename or mode == 0o120000:
                            findings.append({'file': archive.name, 'finding': 'unsafe_archive_entry'}); continue
                        if item.is_dir():
                            continue
                        reason = inspect(item.filename, zipped.read(item)); count += 1
                        if reason:
                            findings.append({'file': item.filename, 'finding': reason})
            else:
                with tarfile.open(archive) as tar:
                    for item in tar:
                        name = item.name
                        member = PurePosixPath(name)
                        if not item.isfile() or member.is_absolute() or '..' in member.parts or '\\' in name or ':' in name:
                            findings.append({'file': archive.name, 'finding': 'unsafe_archive_entry'}); continue
                        reason = inspect(name, tar.extractfile(item).read()); count += 1
                        if reason:
                            findings.append({'file': name, 'finding': reason})
    print(json.dumps({'files_scanned': count, 'findings': findings,
                      'scope': 'Allowlisted source/artifacts; excluded private working state; no Git history available unless separately reviewed'}, indent=2))
    if findings or count == 0:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
