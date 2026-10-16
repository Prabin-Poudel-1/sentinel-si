"""Release packaging safety checks."""
import importlib.util
from pathlib import Path


def _load_build_release_module():
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'build_release.py'
    spec = importlib.util.spec_from_file_location('build_release', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_case_insensitive_collisions_detected():
    module = _load_build_release_module()
    collisions = module._case_insensitive_collisions([
        'vendor/pywin32-licenses/License.txt',
        'vendor/pywin32-licenses/license.txt',
        'vendor/pywin32-licenses/README.txt',
    ])
    assert collisions == {
        'vendor/pywin32-licenses/license.txt': [
            'vendor/pywin32-licenses/License.txt',
            'vendor/pywin32-licenses/license.txt',
        ]
    }


def test_case_insensitive_collisions_empty_when_unique():
    module = _load_build_release_module()
    assert module._case_insensitive_collisions([
        'vendor/pywin32-licenses/pythonwin/License.txt',
        'vendor/pywin32-licenses/win32/License.txt',
    ]) == {}
