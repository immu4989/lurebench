"""Offline tutorial artifacts retain synthetic labels and can be replayed exactly."""

import importlib.util
import json
from pathlib import Path

import pytest

from lurebench.panel import run_cached_panel

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("panel_demo", ROOT / "scripts/run_comparison_demo.py")
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


def test_demo_is_deterministic_read_only_replay_and_explicitly_synthetic(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    report = demo.run_demo(first)
    assert demo.run_demo(second) == report
    before = {p.name: p.read_bytes() for p in first.iterdir()}
    assert {p.name: p.read_bytes() for p in second.iterdir()} == before
    assert report.pop("demonstration")["not_evidence_of_detector_performance"] is True
    assert run_cached_panel(first / "messages.jsonl", first / "plan.json") == report
    assert {p.name: p.read_bytes() for p in first.iterdir()} == before
    common = report["all_models_coanswered"]
    assert common["records"] == 8
    assert common["positive_records"] == common["negative_records"] == 4
    assert common["baseline_accuracy"] == .5
    assert report["family_adjustment"]["adjusted_p_values"] == {
        "improved": .25, "selective": .25,
    }
    assert all(json.loads(line)["meta"]["synthetic"]
               for line in (first / "messages.jsonl").read_text().splitlines())
    with pytest.raises(FileExistsError):
        demo.run_demo(first)
    assert {p.name: p.read_bytes() for p in first.iterdir()} == before


def test_demo_refuses_symlink_output(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    with pytest.raises(FileExistsError):
        demo.run_demo(alias)
    assert list(target.iterdir()) == []
