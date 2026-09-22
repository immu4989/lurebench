"""Prevent known vulnerable optional HTTP resolution from silently returning."""

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10; supplied by the build development extra.
    import tomli as tomllib

from packaging.version import Version

ROOT = Path(__file__).parents[1]


def test_optional_http_transport_security_floor_and_lock_agree():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    assert "httpx2>=2.12.0" in project["tool"]["uv"]["constraint-dependencies"]
    assert {"name": "httpx2", "specifier": ">=2.12.0"} in lock["manifest"]["constraints"]
    clients = [item for item in lock["package"] if item["name"] == "httpx2"]
    assert clients
    assert all(Version(item["version"]) >= Version("2.12.0") for item in clients)
    assert project["project"]["dependencies"] == []
