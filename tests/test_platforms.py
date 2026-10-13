"""Portable transport and platform-specific security boundaries; no mock OS claims."""
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_harness.platform_security import private_directory, child_environment, runtime_binary
from agent_harness.transport import exchange
from agent_harness.supervisor import Supervisor, ROOT
from control_plane.auth import Auth
from control_plane.service import advanced_template


@pytest.mark.parametrize('script', [
    'import time; time.sleep(10)',
    'import sys,time;sys.stdin.readline();sys.stdout.write("{");sys.stdout.flush();time.sleep(10)',
])
def test_threaded_pipe_deadline_cancels_owned_process(script):
    process = subprocess.Popen([sys.executable, '-u', '-c', script], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            exchange(process, b'{}\n', .2, threaded=True)
        assert time.monotonic() - start < 2
        process.wait(timeout=2)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdin.close()
        process.stdout.close()


def test_threaded_transport_real_runtime_and_concurrent_gateway(monkeypatch):
    # Exercise Windows transport algorithm on every OS; this is not Windows validation.
    import agent_harness.gateway as gateway
    monkeypatch.setattr(gateway, 'exchange', lambda p, w, t: exchange(p, w, t, threaded=True))
    with Supervisor() as controller:
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: controller.gateway.call('read_file', 'README.md'), range(24)))
        assert all(r['decision'] == 'ALLOW' for r in responses)
        assert len({r['event_id'] for r in responses}) == 24


def test_child_environment_omits_provider_secrets(monkeypatch):
    monkeypatch.setenv('SENTINEL_MODEL_KEY', 'SYNTHETIC-ONLY')
    environment = child_environment()
    assert set(environment) == ({'LANG', 'SystemRoot'} if os.name == 'nt' else {'LANG'})
    assert 'SYNTHETIC-ONLY' not in repr(environment)
    assert runtime_binary(ROOT).suffix == ('.exe' if os.name == 'nt' else '')


@pytest.mark.parametrize('resource', [r'C:\secrets\x', r'C:relative', r'\\server\share\x',
    r'\\?\C:\x', r'\\.\GLOBALROOT\Device\x', 'README.md:stream', r'..\x',
    'docs/../README.md', 'CON', 'NUL', 'file. ', 'docs//x'])
def test_windows_style_resources_never_escape_virtual_scope(resource):
    with Supervisor() as controller:
        for operation in ['read_file', 'write_file', 'isolated_read', 'isolated_write']:
            assert controller.gateway.call(operation, resource)['decision'] == 'DENY'


@pytest.mark.skipif(os.name != 'nt', reason='Requires actual Windows kernel')
def test_windows_native_file_denial_even_when_contract_grants():
    with Supervisor(template=advanced_template(), isolated=True) as controller:
        for operation, resource in [('isolated_read', 'input.txt'), ('isolated_write', 'output.txt')]:
            result = controller.gateway.call(operation, resource)
            assert result['reason'] == 'unsupported_platform' and not result['executed']
        assert controller.gateway.call('wasm_run', 'sim:checksum', 'ABC')['data'] == 'checksum:198'


@pytest.mark.skipif(os.name != 'nt', reason='Requires actual Windows DACL and share-mode enforcement')
def test_windows_state_acl_inheritance_and_handle_pinning(tmp_path):
    import win32security as ws
    import win32api
    import win32con as wc
    path = tmp_path / 'private'
    guard = private_directory(path)
    try:
        item = path / 'synthetic.txt'
        item.write_text('synthetic')
        token = ws.OpenProcessToken(win32api.GetCurrentProcess(), wc.TOKEN_QUERY)
        try:
            user = ws.ConvertSidToStringSid(ws.GetTokenInformation(token, ws.TokenUser)[0])
        finally:
            token.Close()
        sd = ws.GetNamedSecurityInfo(str(item), ws.SE_FILE_OBJECT, ws.DACL_SECURITY_INFORMATION)
        acl = sd.GetSecurityDescriptorDacl()
        assert {ws.ConvertSidToStringSid(acl.GetAce(i)[2]) for i in range(acl.GetAceCount())} == {user, 'S-1-5-18'}
        # Conflicting DELETE access must be rejected while the guard is open.
        import win32file as wf
        import pywintypes
        with pytest.raises(pywintypes.error) as failure:
            attempt = wf.CreateFile(
                str(path), wc.DELETE,
                wc.FILE_SHARE_READ | wc.FILE_SHARE_WRITE | wc.FILE_SHARE_DELETE,
                None, wc.OPEN_EXISTING, wc.FILE_FLAG_BACKUP_SEMANTICS, None
            )
            attempt.Close()
        assert failure.value.args[0] == 32
        # Handle denies DELETE sharing: root cannot be renamed out from under its owner.
        with pytest.raises(OSError):
            path.rename(tmp_path / 'substituted')
        reopened = private_directory(path, initialize=False)
        reopened.close()
    finally:
        guard.close()


@pytest.mark.skipif(os.name != 'nt', reason='Requires native Windows reparse points')
def test_windows_junction_state_is_rejected(tmp_path):
    import _winapi
    target = tmp_path / 'target'
    target.mkdir()
    junction = tmp_path / 'junction'
    _winapi.CreateJunction(str(target), str(junction))
    try:
        with pytest.raises((ValueError, OSError)):
            private_directory(junction)
        assert list(target.iterdir()) == []
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != 'nt', reason='Requires Windows DACL and hardlink metadata')
def test_windows_broad_acl_and_linked_state_fail_closed(tmp_path):
    import win32security as ws
    import ntsecuritycon as nt
    root = tmp_path / 'state'
    Auth.initialize(root, 'SYNTHETIC-PASSWORD-ONLY')
    hardlink = root / 'linked.json'
    os.link(root / 'administrator.json', hardlink)
    with pytest.raises(ValueError):
        Auth(root)
    hardlink.unlink()
    acl = ws.ACL()
    acl.AddAccessAllowedAce(ws.ACL_REVISION, nt.FILE_ALL_ACCESS,
                           ws.CreateWellKnownSid(ws.WinWorldSid, None))
    ws.SetNamedSecurityInfo(str(root), ws.SE_FILE_OBJECT,
                           ws.DACL_SECURITY_INFORMATION | ws.PROTECTED_DACL_SECURITY_INFORMATION,
                           None, None, acl, None)
    with pytest.raises(ValueError):
        Auth(root)


def test_benchmark_without_posix_resource_metrics(monkeypatch):
    from benchmarks import phase2
    monkeypatch.setattr(phase2, 'resource', None)
    report = phase2.run(1, 1729)
    assert all(arm['cpu_seconds_self_and_children'] is None and
               arm['process_high_water_rss_native_units'] is None for arm in report['arms'].values())
    assert report['arms']['D_sentinel_full']['completed_tasks'] == 1
    assert report['arms']['D_sentinel_full']['unauthorized_executed'] == 0
