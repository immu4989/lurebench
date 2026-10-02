"""Declared dependence cannot inflate exact-binomial FPR validation size."""

import pytest

from lurebench.calibration import build_policy, validate_risk_control_groups
from lurebench.cli import main
from lurebench.schema import Lure, save_jsonl


def test_policy_rejects_grouped_negatives_but_preserves_empirical_analysis():
    ids = [f"r{i}" for i in range(42)]
    labels, scores = [0] * 40 + [1, 1], [.1] * 40 + [.9, .9]
    groups = dict.fromkeys(ids, "single-campaign")
    with pytest.raises(ValueError, match="repeated negative-class lineage"):
        build_policy("fixed-model", "fraud", ids, labels, scores,
                     objective="risk_controlled_fpr", target_fpr=.1, groups=groups)
    policy, _ = build_policy("fixed-model", "fraud", ids, labels, scores,
                             objective="target_fpr", target_fpr=.1, groups=groups)
    assert policy.schema_version == 1
    assert policy.risk_control is None
    # One negative per declared group passes only the known-dependence check.
    # Correlated positives do not inflate the denominator of an FPR claim.
    groups = {key: key if index < 40 else "positive-family" for index, key in enumerate(ids)}
    policy, _ = build_policy("fixed-model", "fraud", ids, labels, scores,
                             objective="risk_controlled_fpr", target_fpr=.1, groups=groups)
    assert policy.risk_control.validation_negatives == 40


@pytest.mark.parametrize("groups", [{}, {"a": "x"}, {"a": "x", "b": "y", "extra": "z"},
    {"a": "", "b": "y"}, {"a": "x", "b": "bad\ud800"}, ["a", "b"]])
def test_invalid_group_annotations_fail(groups):
    with pytest.raises(ValueError):
        validate_risk_control_groups(["a", "b"], [0, 1], groups)


@pytest.mark.parametrize("task", ["fraud", "provenance"])
def test_cli_checks_transitive_negative_lineage_before_loading_detector(tmp_path, monkeypatch, capsys, task):
    import lurebench.cli as cli

    # a and b connect through the positive bridge and absent parent. For the
    # provenance task the negatives are human messages, even when fraud-labelled.
    label = 0 if task == "fraud" else 1
    records = [
        Lure(id="a", text="Synthetic a", label=label, source="human",
             typology="benign" if label == 0 else "phishing", meta={"parent_id": "absent"}),
        Lure(id="bridge", text="Synthetic bridge", label=1, source="ai", typology="phishing",
             meta={"seed_id": "absent", "family_id": "other"}),
        Lure(id="b", text="Synthetic b", label=label, source="human",
             typology="benign" if label == 0 else "phishing", meta={"rewrite_of": "other"}),
    ]
    dataset, output = tmp_path / "validation.jsonl", tmp_path / "policy.json"
    save_jsonl(records, dataset)
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: pytest.fail("detector loaded"))
    assert main(["calibrate", "-d", str(dataset), "-m", "heuristic-v0", "--task", task,
                 "--objective", "risk_controlled_fpr", "--target-fpr", "0.1",
                 "--out", str(output)]) == 1
    assert "repeated negative-class lineage" in capsys.readouterr().err
    assert not output.exists()
