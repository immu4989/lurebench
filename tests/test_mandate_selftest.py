import hashlib
import json

from lurebench.cli import main
from lurebench.mandate_selftest import REFERENCE_CASES, reference_corpus_root, run_mandate_selftest


def test_builtin_reference_selftest_reports_exact_input_hashes():
    report = run_mandate_selftest()
    assert report["reference_only"] is True
    assert report["summary"] == {"status": "pass", "passed": 7, "total": 7}
    root = reference_corpus_root()
    for item in report["results"]:
        assert item["rejection_probes"] == {
            "boolean-version": True,
            "float-version": True,
            "unknown-field": True,
            "derived-claim": True,
        }
        assert (
            item["artifact_sha256"]
            == hashlib.sha256((root / item["artifact"]).read_bytes()).hexdigest()
        )


def test_selftest_detects_validator_that_accepts_tampered_evidence(monkeypatch):
    import importlib

    _, module_name, validator_name, relative = REFERENCE_CASES[0]
    value = json.loads((reference_corpus_root() / relative).read_bytes())
    module = importlib.import_module(f"lurebench.{module_name}")
    monkeypatch.setattr(module, validator_name, lambda _: value)
    report = run_mandate_selftest()
    assert report["summary"]["status"] == "fail"
    assert report["summary"]["passed"] == 6
    assert report["results"][0]["status"] == "fail"
    assert not any(report["results"][0]["rejection_probes"].values())


def test_missing_references_are_errors_and_never_skipped(tmp_path):
    report = run_mandate_selftest(tmp_path)
    assert report["summary"] == {"status": "fail", "passed": 0, "total": 7}
    assert len(report["results"]) == len(REFERENCE_CASES)
    assert all(item["status"] == "error" for item in report["results"])


def test_corrupt_reference_keeps_other_profiles_visible(tmp_path):
    root = reference_corpus_root()
    for _, _, _, relative in REFERENCE_CASES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((root / relative).read_bytes())
    bad = tmp_path / REFERENCE_CASES[0][3]
    bad.write_text('{"private-error-message":"must not leak"}')
    report = run_mandate_selftest(tmp_path)
    assert report["summary"]["status"] == "fail"
    assert report["summary"]["passed"] == 7 - 1
    assert report["results"][0]["status"] == "error"
    assert "must not leak" not in json.dumps(report)


def test_selftest_cli_writes_private_nonoverwriting_diagnostics(tmp_path, capsys):
    output = tmp_path / "selftest.json"
    args = ["mandate-selftest"] + ["--json", "--out", str(output)]
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert json.loads(output.read_text()) == report
    assert report["reference_only"] is True
    assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == original
