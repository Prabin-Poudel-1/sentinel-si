"""Collect locked Rust dependency license metadata and shipped license texts."""
import os
from pathlib import Path
import tomllib

ROOT=Path(__file__).resolve().parents[1]
cargo=Path(os.environ.get('CARGO_HOME',str(Path.home()/'.cargo')))
packages=tomllib.loads((ROOT/'Cargo.lock').read_text(encoding='utf-8'))['package']
parts=['# Third-party Rust dependency notices\n\nIncludes locked dependencies; not all are compiled on every platform.\nPython, optional keyring, browser and development tooling are separately installed and retain their licenses.\n']
for package in sorted(packages,key=lambda p:(p['name'],p['version'])):
    if 'source' not in package:continue
    matches=list((cargo/'registry/src').glob('*/'+package['name']+'-'+package['version']))
    if not matches:raise SystemExit('Missing license metadata: '+package['name'])
    root=matches[0];meta=tomllib.loads((root/'Cargo.toml').read_text(encoding='utf-8'))['package']
    parts.append('\n## '+package['name']+' '+package['version']+'\nLicense: '+meta.get('license','See license file')+'\n')
    names={p for pattern in ('LICENSE*','COPYING*','NOTICE*','license*') for p in root.glob(pattern) if p.is_file()}
    if meta.get('license-file'):names.add(root/meta['license-file'])
    for path in sorted(names):
        if root.resolve() not in path.resolve().parents:raise SystemExit('Unsafe dependency license path')
        parts.append('\n'+path.name+'\n'+path.read_text(encoding='utf-8', errors='replace')+'\n')
(ROOT/'packaging/third-party-notices.txt').write_text(''.join(parts), encoding='utf-8')
print('Locked dependency license notices collected')
