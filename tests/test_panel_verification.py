"""Strict, read-only reproduction of complete cached comparison reports."""

import json

import pytest
from test_panel import fixture_plan

from lurebench.cli import main
from lurebench.panel import run_cached_panel, verify_cached_panel


def fixture_report(tmp_path):
    dataset, plan_path, _ = fixture_plan(tmp_path)
    report = run_cached_panel(dataset, plan_path)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    return dataset, plan_path, path, report


def test_reproduction_is_read_only_and_never_constructs_a_model(tmp_path, monkeypatch, capsys):
    import lurebench.detectors as detectors

    dataset, plan, report, _ = fixture_report(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.iterdir()}
    monkeypatch.setattr(detectors, "get_detector", lambda *a, **k: pytest.fail("live detector"))
    args = ["verify-panel", "-d", str(dataset), "--plan", str(plan), "--report", str(report)]
    assert main(args) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["matches_replay"] is True
    assert str(tmp_path) not in output
    assert "synthetic 0" not in output
    assert {p: p.read_bytes() for p in tmp_path.iterdir()} == before
    report.write_text(report.read_text().replace('"schema_version": 1', '"schema_version": true'))
    assert main(args) == 2
    assert "no live fallback" in capsys.readouterr().err


@pytest.mark.parametrize("change", [
    lambda r: r["family_adjustment"]["adjusted_p_values"].update(improved=0.),
    lambda r: r["comparisons"]["improved"]["overall"].update(records=8.0),
    lambda r: r["all_models_coanswered"].update(records=False),
    lambda r: r["input_fingerprint"].update(sha256="0" * 64),
    lambda r: r.update(limitations=[]),
    lambda r: r.update(demonstration={"synthetic": True}),
    lambda r: r.pop("detector_identities"),
])
def test_every_field_and_numeric_type_must_match(tmp_path, change, capsys):
    dataset, plan, path, report = fixture_report(tmp_path)
    change(report)
    path.write_text(json.dumps(report))
    result = verify_cached_panel(dataset, plan, path)
    assert result["matches_replay"] is False
    assert main(["verify-panel", "-d", str(dataset), "--plan", str(plan), "--report", str(path)]) == 1
    assert json.loads(capsys.readouterr().out)["matches_replay"] is False


def test_report_formatting_can_change_but_missing_cache_never_falls_back(tmp_path):
    dataset, plan, path, report = fixture_report(tmp_path)
    first = verify_cached_panel(dataset, plan, path)
    path.write_text(json.dumps(report, indent=2, sort_keys=True))
    second = verify_cached_panel(dataset, plan, path)
    assert first["matches_replay"] and second["matches_replay"]
    assert first["supplied_report_sha256"] != second["supplied_report_sha256"]
    assert first["replayed_report_canonical_sha256"] == second["replayed_report_canonical_sha256"]
    (tmp_path / "improved.json").write_text("{}")
    with pytest.raises(ValueError, match="no live fallback"):
        verify_cached_panel(dataset, plan, path)


@pytest.mark.parametrize("bad", ['[]', '{"schema_version":1,"schema_version":1}',
                               '{"schema_version":1,"analysis":"private-value"}'])
def test_bad_report_fails_before_replay(tmp_path, monkeypatch, bad):
    import lurebench.panel as panel

    path = tmp_path / "report.json"
    path.write_text(bad)
    monkeypatch.setattr(panel, "run_cached_panel", lambda *a: pytest.fail("bad report reached replay"))
    with pytest.raises(ValueError):
        verify_cached_panel(tmp_path / "missing", tmp_path / "missing-plan", path)


def test_report_symlink_and_oversize_rejected_before_replay(tmp_path, monkeypatch):
    import lurebench.panel as panel

    path = tmp_path / "report.json"
    path.write_bytes(b" " * (1024 * 1024 + 1))
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    monkeypatch.setattr(panel, "run_cached_panel", lambda *a: pytest.fail("unsafe report reached replay"))
    for target in (path, alias):
        with pytest.raises(ValueError):
            verify_cached_panel(tmp_path / "missing", tmp_path / "missing-plan", target)
