"""Host state checks; hostile same-UID code remains outside the boundary."""
import os
import pytest
from agent_harness.platform_security import private_directory

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='POSIX descriptor checks')


def test_state_reopen_requires_private_mode(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match='0700'):
        private_directory(tmp_path, initialize=False)
    guard = private_directory(tmp_path)
    guard.close()
    guard = private_directory(tmp_path, initialize=False)
    guard.close()


def test_state_symlink_does_not_chmod_target(tmp_path):
    target = tmp_path / 'target'
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    link = tmp_path / 'link'
    link.symlink_to(target)
    with pytest.raises(ValueError):
        private_directory(link)
    assert target.stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'directory'])
def test_state_rejects_redirected_child(tmp_path, kind):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    outside = tmp_path / 'outside'
    outside.write_text('synthetic')
    child = state / 'control.sqlite'
    if kind == 'symlink':
        child.symlink_to(outside)
    elif kind == 'hardlink':
        os.link(outside, child)
    else:
        child.mkdir()
    with pytest.raises(ValueError, match='Linked or unexpected'):
        private_directory(state, initialize=False)
