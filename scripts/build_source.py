"""Allowlisted source snapshot for owner review; never copies private working state."""
import hashlib
from pathlib import Path
import zipfile
from scan_release import inspect

ROOT=Path(__file__).resolve().parents[1]
DIRECTORIES=('.github','agent_harness','benchmarks','cloud','contracts','control_plane','dashboard/dist',
             'docs','examples','packaging','policies','runtime','scripts','sentinel_sdk','sentinel_sync','simulated_tools','tests','web')
EXCLUDE={'node_modules','.wrangler','__pycache__','.pytest_cache','wrangler.local.toml','.dev.vars','.DS_Store'}
EXTENSIONS={'.py','.rs','.toml','.lock','.txt','.md','.json','.js','.cjs','.html','.css','.svg','.cedar','.sql','.yml','.yaml'}
files={}
for directory in DIRECTORIES:
    for path in (ROOT/directory).rglob('*'):
        relative=path.relative_to(ROOT)
        if any(part in EXCLUDE for part in relative.parts) or not path.is_file():continue
        if path.name.startswith('.env') or path.name.startswith('.dev.vars'):continue
        if path.suffix not in EXTENSIONS and path.name not in {'_headers','sentinel'}:continue
        if path.is_symlink():raise SystemExit('Source symlink rejected')
        data=path.read_bytes()
        if path.name!='scan_release.py' and inspect(relative.as_posix(),data):raise SystemExit('Source scan failed: '+relative.as_posix())
        files[relative.as_posix()]=data
for name in ('Cargo.toml','Cargo.lock','pyproject.toml','requirements-dev.txt','requirements-sync.txt','.gitignore','README.md','SECURITY.md','LICENSE'):
    files[name]=(ROOT/name).read_bytes()
archive=ROOT.parent/'sentinel-ai-0.3.0-rc.1-source.zip'
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as output:
    for name,data in sorted(files.items()):
        info=zipfile.ZipInfo('sentinel-ai/'+name,date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
        info.external_attr=0o100644<<16
        output.writestr(info,data)
archive.with_suffix('.zip.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
print('Source snapshot: '+archive.name+'; '+str(len(files))+' allowlisted files; no local reports/state/history')
