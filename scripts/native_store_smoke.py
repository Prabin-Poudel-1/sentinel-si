"""Synthetic native Keychain lifecycle; no access to existing account credentials."""
import json, secrets, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
if sys.platform != 'darwin':
    raise SystemExit('This explicit native lifecycle smoke test requires macOS')
from sentinel_sync.credentials import SystemCredentials
from keyring.backends.macOS import api
# Never display an OS authentication dialog during unattended verification.
original=api.create_query
def no_ui(**kwargs):
    kwargs['kSecUseAuthenticationUI']=api.k_('kSecUseAuthenticationUIFail')
    return original(**kwargs)
api.create_query=no_ui
name='synthetic-public-rc-'+secrets.token_hex(16)
report={'scope':'native macOS Keychain with synthetic unique test entry; UI authentication disabled','status':'not_verified'}
store=None
try:
    store=SystemCredentials()
    assert store.get(name) is None
    store.set(name,'synthetic-only-first')
    assert store.get(name)=='synthetic-only-first'
    store.set(name,'synthetic-only-rotated')
    assert store.get(name)=='synthetic-only-rotated'
    store.delete(name)
    assert store.get(name) is None
    report.update(status='passed',checks=['native_backend','set_get','replace_get','delete_absent'])
except Exception as exc:
    report.update(status='unavailable',error_category=type(exc).__name__)
finally:
    if store:
        try: store.delete(name)
        except Exception: report['cleanup']='could_not_confirm'
    (ROOT/'reports/public-native-store.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

if report["status"] != "passed": raise SystemExit(1)
