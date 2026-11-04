"""Default discovery must ignore generated package trees without blocking explicit tests."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('explicit', [False, True])
def test_discovery_is_scoped_but_explicit_paths_still_work(tmp_path, explicit):
    (tmp_path / 'pyproject.toml').write_bytes((ROOT / 'pyproject.toml').read_bytes())
    tests = tmp_path / 'tests'
    tests.mkdir()
    (tests / 'test_probe.py').write_text('def test_normal():\n    assert True\n')
    generated = tmp_path / 'package-0.0.0' / 'tests'
    generated.mkdir(parents=True)
    (generated / 'conftest.py').write_text(
        'raise RuntimeError("GENERATED_BUILD_TREE_WAS_COLLECTED")\n')
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    requested = scratch / 'test_requested.py'
    requested.write_text('def test_requested():\n    assert True\n')
    env = dict(os.environ)
    for name in ('PYTEST_ADDOPTS', 'PYTEST_PLUGINS', 'PYTHONPATH'):
        env.pop(name, None)
    env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    command = [sys.executable, '-m', 'pytest', '-q']
    if explicit:
        command.append(str(requested))
    result = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True,
                            text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '1 passed' in result.stdout
    assert 'GENERATED_BUILD_TREE_WAS_COLLECTED' not in result.stdout + result.stderr
