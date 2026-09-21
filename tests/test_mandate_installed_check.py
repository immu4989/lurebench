"""The packaging smoke check must fail closed on incomplete CLI diagnostics."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/check_installed_mandate.py"
PACKAGE = "lurebench"
COUNT = 7


def fake_install(tmp_path, report, *, producer_import=False):
    root = tmp_path / "installed"
    package = root / PACKAGE
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    code = (
        ("import lurebench\n" if producer_import else "")
        + "def main(args):\n"
        + f"    print({json.dumps(report)!r})\n"
        + "    return 0\n"
    )
    (package / "cli.py").write_text(code)
    metadata = root / f"{PACKAGE}-0.0.0.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {PACKAGE}\nVersion: 0.0.0\n"
    )
    (metadata / "RECORD").write_text(
        f"{metadata.name}/METADATA,,\n{PACKAGE}/__init__.py,,\n{PACKAGE}/cli.py,,\n"
    )
    return root


def report():
    return {
        "kind": f"{PACKAGE}-mandate-reference-selftest",
        "reference_only": True,
        "package_version": "0.0.0",
        "summary": {"status": "pass", "passed": COUNT, "total": COUNT},
        "results": [
            {
                "status": "pass",
                "rejection_probes": {
                    "boolean-version": True,
                    "float-version": True,
                    "unknown-field": True,
                    "derived-claim": True,
                },
            }
            for _ in range(COUNT)
        ],
    }


def run(root, cwd):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--package", PACKAGE, "--installed-root", str(root)],
        cwd=cwd, capture_output=True, text=True, timeout=20, check=False,
    )


def test_complete_installed_diagnostic_is_accepted(tmp_path):
    result = run(fake_install(tmp_path, report()), tmp_path)
    assert result.returncode == 0, result.stderr
    assert "including rejection probes" in result.stdout


@pytest.mark.parametrize(
    "defect", ["missing-profile", "accepted-tamper", "missing-probe", "wrong-version",
               "wrong-kind", "reference-alias", "float-count"]
)
def test_incomplete_or_misbound_diagnostic_is_rejected(tmp_path, defect):
    value = report()
    if defect == "missing-profile":
        value["results"].pop()
    elif defect == "accepted-tamper":
        value["results"][0]["rejection_probes"]["derived-claim"] = False
    elif defect == "missing-probe":
        del value["results"][0]["rejection_probes"]["derived-claim"]
    elif defect == "wrong-version":
        value["package_version"] = "other"
    elif defect == "wrong-kind":
        value["kind"] = "other"
    elif defect == "reference-alias":
        value["reference_only"] = 1
    else:
        value["summary"]["passed"] = float(COUNT)
    result = run(fake_install(tmp_path, value), tmp_path)
    assert result.returncode == 1
    assert "installed authority check failed" in result.stderr
    assert "Traceback" not in result.stderr


def test_check_refuses_source_checkout_as_working_directory(tmp_path):
    result = run(fake_install(tmp_path, report()), ROOT)
    assert result.returncode == 1
    assert "outside the source checkout" in result.stderr
