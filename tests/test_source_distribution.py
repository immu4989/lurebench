"""Source archives must retain reviewed reproduction inputs without unsafe members."""

import importlib.util
import io
import tarfile
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "source_contract", ROOT / "scripts/check_source_distribution.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


@pytest.fixture
def project(tmp_path):
    package = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["name"]
    source = tmp_path / "source"
    source.mkdir()
    files = {name: b"reviewed\n" for name in checker.TOP_LEVEL}
    files["pyproject.toml"] = (
        f'[project]\nname = "{package}"\nversion = "0.0.0"\n').encode()
    files.update({
        f"{package}/__init__.py": b"# code\n",
        "tests/conftest.py": b"# portable fixtures\n",
        "tests/test_example.py": b"# test\n",
        "scripts/check_example.py": b"# reproduction\n",
        ".github/workflows/ci.yml": b"name: example\n",
        "docs/image.svg": b"<svg/>\n",
    })
    if package == "lurescope":
        files["MANIFEST.in"] = b"# reviewed manifest\n"
    for name, data in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return source, package, files


def write_archive(target, package, files, *, extra=()):
    with tarfile.open(target, "w:gz") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(f"{package}-0.0.0/{name}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        for member, data in extra:
            archive.addfile(member, io.BytesIO(data))
    return target


def test_complete_inputs_and_allowed_backend_metadata(tmp_path, project):
    root, package, files = project
    member = tarfile.TarInfo(f"{package}-0.0.0/PKG-INFO")
    member.size = 8
    archive = write_archive(tmp_path / "source.tar.gz", package, files,
                            extra=[(member, b"metadata")])
    assert checker.verify(archive, root, package) == len(files)


@pytest.mark.parametrize("name", ["tests/conftest.py", "scripts/check_example.py",
                                  ".github/workflows/ci.yml", "docs/image.svg", "uv.lock"])
@pytest.mark.parametrize("mutation", ["missing", "stale"])
def test_omitted_or_changed_reproduction_inputs_fail(tmp_path, project, name, mutation):
    root, package, files = project
    modified = dict(files)
    if mutation == "missing":
        del modified[name]
    else:
        modified[name] = b"x" * len(files[name])
    archive = write_archive(tmp_path / "source.tar.gz", package, modified)
    with pytest.raises(ValueError, match="missing|stale"):
        checker.verify(archive, root, package)


@pytest.mark.parametrize("name", [
    "../outside", "/absolute", "other-0.0.0/file", "{prefix}/a/../b",
    "{prefix}//file", "{prefix}/./file", "{prefix}/a\\b", "{prefix}/tests/__pycache__/x.pyc",
    "{prefix}/build/copied.py", "{prefix}/.env", "{prefix}/.env.production",
    "{prefix}/.netrc", "{prefix}/.pypirc",
])
def test_extra_unsafe_or_transient_paths_are_rejected(tmp_path, project, name):
    root, package, files = project
    member = tarfile.TarInfo(name.format(prefix=f"{package}-0.0.0"))
    archive = write_archive(tmp_path / "source.tar.gz", package, files, extra=[(member, b"")])
    with pytest.raises(ValueError):
        checker.verify(archive, root, package)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                                  tarfile.CHRTYPE, tarfile.GNUTYPE_SPARSE])
def test_extra_nonregular_members_are_rejected(tmp_path, project, kind):
    root, package, files = project
    member = tarfile.TarInfo(f"{package}-0.0.0/unrelated")
    member.type, member.linkname = kind, "/outside"
    archive = write_archive(tmp_path / "source.tar.gz", package, files, extra=[(member, b"")])
    with pytest.raises(ValueError, match="nonregular"):
        checker.verify(archive, root, package)


def test_duplicate_member_cannot_shadow_checked_bytes(tmp_path, project):
    root, package, files = project
    member = tarfile.TarInfo(f"{package}-0.0.0/tests/conftest.py")
    archive = write_archive(tmp_path / "source.tar.gz", package, files, extra=[(member, b"")])
    with pytest.raises(ValueError, match="duplicate"):
        checker.verify(archive, root, package)


@pytest.mark.parametrize("budget", ["compressed", "member", "total", "count"])
def test_archive_resource_budgets(tmp_path, project, monkeypatch, budget):
    root, package, files = project
    member = tarfile.TarInfo(f"{package}-0.0.0/extra")
    member.size = 129
    archive = write_archive(tmp_path / "source.tar.gz", package, files,
                            extra=[(member, b"x" * 129)])
    setting, limit = {
        "compressed": ("MAX_ARCHIVE_BYTES", archive.stat().st_size - 1),
        "member": ("MAX_MEMBER_BYTES", 128),
        "total": ("MAX_TOTAL_BYTES", sum(len(data) for data in files.values())),
        "count": ("MAX_MEMBERS", len(files)),
    }[budget]
    monkeypatch.setattr(checker, setting, limit)
    with pytest.raises(ValueError, match="limit"):
        checker.verify(archive, root, package)


def test_source_symlink_is_not_followed(tmp_path, project):
    root, package, _ = project
    target = root / "tests/conftest.py"
    target.rename(root / "tests/saved.py")
    target.symlink_to(root / "tests/saved.py")
    with pytest.raises(ValueError, match="symlink"):
        checker.required_sources(root, package)


def test_corrupt_archive_cli_fails_without_traceback(tmp_path, project, capsys):
    root, package, _ = project
    archive = tmp_path / "broken.tar.gz"
    archive.write_bytes(b"not a source archive")
    with pytest.raises(SystemExit) as caught:
        checker.main([str(archive), "--root", str(root), "--package", package])
    assert caught.value.code == 1
    assert "source reproduction contract failed" in capsys.readouterr().err


def test_ci_runs_the_source_archive_gate():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "scripts/check_source_distribution.py" in workflow
    assert "Run tests from the source distribution" in workflow
    release = (ROOT / ".github/workflows/release.yml").read_text()
    build = release.split("\n  build:", 1)[1].split("\n  attest-release:", 1)[0]
    assert "scripts/check_source_distribution.py" in build
    assert "scripts/check_mandate_wheel.py" in build
