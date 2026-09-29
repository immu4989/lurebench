"""Independent enumeration checks for paired tests and missing-score bounds."""

import itertools
import json
import math
from types import SimpleNamespace

import pytest

from lurebench.cli import main
from lurebench.comparison import compare_paired
from lurebench.detectors.cache import CachedDetector
from lurebench.schema import Lure, save_jsonl


def test_exact_test_matches_integer_binomial_enumeration():
    for left_only in range(11):
        for right_only in range(11):
            n = left_only + right_only
            # Include one concordant pair so n=0 is a defined no-discordance test.
            truths = {str(i): 1 for i in range(n + 1)}
            left = {str(i): float(i < left_only or i == n) for i in range(n + 1)}
            right = {str(i): float(i >= left_only) for i in range(n + 1)}
            result = compare_paired(truths, left, right)
            expected = min(1, 2 * sum(math.comb(n, k) for k in range(min(left_only, right_only) + 1))
                           / (1 << n))
            assert result["paired_test"]["p_value"] == pytest.approx(expected, abs=1e-14)
            assert result["overall"]["coanswered_accuracy_delta"] == (right_only - left_only) / (n + 1)
            reverse = compare_paired(truths, right, left)
            assert reverse["paired_test"]["p_value"] == result["paired_test"]["p_value"]
            assert reverse["overall"]["coanswered_accuracy_delta"] == -result["overall"]["coanswered_accuracy_delta"]


def test_completion_bounds_match_exhaustive_binary_assignments():
    for truths in itertools.product((0, 1), repeat=2):
        for observed in itertools.product((0., 1., None), repeat=4):
            left, right = observed[:2], observed[2:]
            result = compare_paired(dict(zip(("a", "b"), truths, strict=True)),
                                    dict(zip(("a", "b"), left, strict=True)),
                                    dict(zip(("a", "b"), right, strict=True)))
            possibilities = []
            choices = [(0., 1.) if value is None else (value,) for value in observed]
            for completion in itertools.product(*choices):
                delta = sum(int(completion[2+i] == truths[i]) - int(completion[i] == truths[i])
                            for i in range(2)) / 2
                possibilities.append(delta)
            bounds = result["overall"]["all_record_binary_completion_delta_bounds"]
            assert bounds == {"lower": min(possibilities), "upper": max(possibilities)}
            assert result["overall"]["coanswered"] == sum(a is not None and b is not None
                                                          for a, b in zip(left, right, strict=True))


def test_abstention_is_not_a_negative_or_silent_intersection():
    report = compare_paired({"a": 0, "b": 1}, {"a": None, "b": .9}, {"a": .1, "b": None})
    assert report["overall"]["coanswered_accuracy_delta"] is None
    assert report["paired_test"]["p_value"] is None
    assert report["paired_test"]["conditional_on_coanswered"] is True
    assert report["overall"]["baseline_abstained"] == 1
    assert report["overall"]["candidate_abstained"] == 1
    with pytest.raises(ValueError):
        compare_paired({"a": 0, "b": 1}, {"a": .2}, {"a": .2, "b": .9})


def test_class_cohorts_and_threshold_ties():
    report = compare_paired({"a": 0, "b": 1}, {"a": .5, "b": .5}, {"a": .4, "b": .5})
    assert report["by_class"]["positive"]["coanswered_accuracy_delta"] == 0
    assert report["by_class"]["negative"]["coanswered_accuracy_delta"] == 1
    empty = compare_paired({"a": 1}, {"a": .9}, {"a": .9})
    assert empty["by_class"]["negative"]["all_record_binary_completion_delta_bounds"] is None
    assert empty["paired_test"]["p_value"] == 1


@pytest.mark.parametrize("bad", [True, -.1, 1.1, "0.2", float("nan"), float("inf")])
def test_invalid_scores_fail(bad):
    with pytest.raises(ValueError):
        compare_paired({"a": 1}, {"a": bad}, {"a": .9})


@pytest.mark.parametrize("bad", [True, "1", 1.0, -1, None])
def test_invalid_truths_fail(bad):
    with pytest.raises(ValueError):
        compare_paired({"a": bad}, {"a": .9}, {"a": .9})


@pytest.mark.parametrize("key", [None, 1, "", "a\nb", "a" * 513])
def test_invalid_identifiers_fail(key):
    with pytest.raises(ValueError):
        compare_paired({key: 1}, {key: .9}, {key: .9})


def test_numpy_integer_truths_produce_plain_json_counts():
    np = pytest.importorskip("numpy")
    result = compare_paired({"a": np.int64(1)}, {"a": .9}, {"a": .1})
    json.dumps(result, allow_nan=False)


def test_cli_reuses_exact_cached_records_without_model_construction(tmp_path, monkeypatch, capsys):
    import lurebench.cli as cli

    def forbidden(*args, **kwargs):
        pytest.fail("detector constructed during cached comparison")

    records = [Lure(id="a", text="synthetic", label=1, source="human", typology="phishing")]
    dataset = tmp_path / "records.jsonl"
    save_jsonl(records, dataset)
    args = ["compare-cached", "--task", "fraud", "-d", str(dataset)]
    for name, value in [("baseline", .1), ("candidate", .9)]:
        path = tmp_path / f"{name}.json"
        det = CachedDetector(SimpleNamespace(name=name, task="fraud", score=lambda r, v=value: v),
                             str(path), flush_every=1)
        det.score(records[0])
        args.extend([f"--{name}-cache", str(path), f"--{name}-name", name])
    monkeypatch.setattr(cli, "get_detector", forbidden)
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["overall"]["coanswered_accuracy_delta"] == 1
    assert result["paired_test"]["p_value"] == 1  # one pair is not persuasive evidence
    save_jsonl(records + records, dataset)
    assert main(args) == 2
    assert "no live fallback" in capsys.readouterr().err
    records[0].text = "not cached"
    save_jsonl(records, dataset)
    assert main(args) == 2
    assert "incomplete" in capsys.readouterr().err
