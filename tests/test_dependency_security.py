"""Prevent known vulnerable optional HTTP resolution from silently returning."""

from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10; supplied by the build development extra.
    import tomli as tomllib

from packaging.version import Version

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(("name", "minimum"), [("httpx2", "2.12.0"), ("urllib3", "2.8.0")])
def test_optional_http_transport_security_floor_and_lock_agree(name, minimum):
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    assert f"{name}>={minimum}" in project["tool"]["uv"]["constraint-dependencies"]
    assert {"name": name, "specifier": f">={minimum}"} in lock["manifest"]["constraints"]
    clients = [item for item in lock["package"] if item["name"] == name]
    assert clients
    assert all(Version(item["version"]) >= Version(minimum) for item in clients)
    assert project["project"]["dependencies"] == []
