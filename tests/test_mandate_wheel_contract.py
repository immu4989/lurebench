import importlib.util
from pathlib import Path
from zipfile import ZipFile

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/check_mandate_wheel.py"
SPEC = importlib.util.spec_from_file_location("mandate_wheel_contract", SCRIPT)
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


@pytest.fixture(params=["lurebench", "lurescope"])
def source_and_members(tmp_path, request):
    package = request.param
    root = tmp_path / "source"
    source = {
        f"{package}/mandate.py": b"# code\n",
        "spec/luremandate-plan-v1.schema.json": b'{"schema":true}\n',
        "conformance/luremandate-v1/verification.json": b'{"evidence":true}\n',
    }
    members = {}
    for relative, payload in source.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        if relative.startswith(package + "/"):
            destination = relative
        elif package == "lurebench":
            destination = (
                f"lurebench/{relative}"
                if relative.startswith("spec/")
                else relative.replace("conformance/", "lurebench/conformance_data/", 1)
            )
        else:
            destination = f"lurescope-0.0.0.data/data/share/lurescope/{relative}"
        members[destination] = payload
    return package, root, members


def wheel_at(path, members):
    with ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return path


def test_exact_code_schema_and_corpus_are_required(tmp_path, source_and_members):
    package, root, members = source_and_members
    wheel = wheel_at(tmp_path / "package.whl", members)
    assert contract.verify(wheel, root, package) == 3


@pytest.mark.parametrize("kind", ["code", "schema", "corpus"])
def test_missing_artifact_is_rejected(tmp_path, source_and_members, kind):
    package, root, members = source_and_members
    index = {"code": 0, "schema": 1, "corpus": 2}[kind]
    del members[list(members)[index]]
    with pytest.raises(ValueError, match="missing"):
        contract.verify(wheel_at(tmp_path / "package.whl", members), root, package)


def test_stale_bytes_are_rejected(tmp_path, source_and_members):
    package, root, members = source_and_members
    members[next(iter(members))] += b"# stale"
    with pytest.raises(ValueError, match="stale"):
        contract.verify(wheel_at(tmp_path / "package.whl", members), root, package)


def test_duplicate_zip_entries_are_rejected(tmp_path, source_and_members):
    package, root, members = source_and_members
    wheel = wheel_at(tmp_path / "package.whl", members)
    name = next(iter(members))
    with ZipFile(wheel, "a") as archive, pytest.warns(UserWarning, match="Duplicate"):
        archive.writestr(name, members[name])
    with pytest.raises(ValueError, match="duplicate"):
        contract.verify(wheel, root, package)


def test_cli_reports_corrupt_archive_without_traceback(tmp_path, capsys):
    wheel = tmp_path / "broken.whl"
    wheel.write_bytes(b"not a zip")
    with pytest.raises(SystemExit) as raised:
        contract.main([str(wheel), "--package", "lurebench"])
    assert raised.value.code == 1
    assert "wheel authority contract failed" in capsys.readouterr().err
