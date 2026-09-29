import itertools

import pytest

from lurebench.audit import audit_splits, family_id, jaccard, shingles
from lurebench.cli import _parse_splits, main
from lurebench.corpus_v2 import cluster_records
from lurebench.schema import Lure


def _lure(record_id, text, **meta):
    return Lure(
        id=record_id, text=text, label=1, source="human", typology="phishing", meta=meta
    )


def test_audit_finds_cross_split_near_duplicate():
    train = [_lure("train-1", "please verify your account now using the secure portal link")]
    test = [_lure("test-1", "please verify your account now using the secure portal today")]
    result = audit_splits({"train": train, "test": test}, threshold=0.4, shingle_size=3)
    assert not result.passed
    assert result.near_duplicates[0].left_id == "train-1"


def test_audit_finds_explicit_family_overlap_without_similar_text():
    train = [_lure("a", "alpha beta gamma", family_id="scenario-7")]
    test = [_lure("b", "completely unrelated words", family_id="scenario-7")]
    result = audit_splits({"train": train, "test": test})
    assert result.family_overlaps == [("scenario-7", "train", "test")]


def test_audit_clean_splits_pass_and_fallback_family_is_record_id():
    train = [_lure("a", "alpha beta gamma delta epsilon")]
    test = [_lure("b", "one two three four five")]
    result = audit_splits({"train": train, "test": test})
    assert result.passed
    assert family_id(train[0]) == "a"


@pytest.mark.parametrize("threshold", [0, .25, .5, .8, 1])
@pytest.mark.parametrize("size", [1, 2, 5])
def test_indexed_audit_matches_exhaustive_reference(threshold, size):
    texts = ["", "!!!", "Alpha", "alpha", "beta", "alpha beta", "beta alpha",
             "alpha beta gamma", "ALPHA BETA delta", "café 東京"]
    left = [_lure(f"left-{i}", text) for i, text in enumerate(texts)]
    right = [_lure(f"right-{i}", text) for i, text in enumerate(reversed(texts))]
    expected = {
        (a.id, b.id, round(jaccard(shingles(a.text, size), shingles(b.text, size)), 6))
        for a, b in itertools.product(left, right)
        if jaccard(shingles(a.text, size), shingles(b.text, size)) >= threshold
    }
    audit = audit_splits({"train": left, "test": right}, threshold, size)
    observed = {(p.left_id, p.right_id, p.similarity) for p in audit.near_duplicates}
    assert observed == expected
    assert len(audit.near_duplicates) == len(expected)


def test_family_in_three_splits_reports_all_three_boundaries():
    splits = {name: [_lure(name, name, family_id="shared")]
              for name in ["train", "validation", "test"]}
    assert set(audit_splits(splits).family_overlaps) == {
        ("shared", "train", "validation"), ("shared", "train", "test"),
        ("shared", "validation", "test"),
    }


def test_empty_shingles_are_conservatively_clustered():
    records = [_lure("a", "!!!"), _lure("b", "???"), _lure("c", "ordinary words")]
    clusters, _ = cluster_records(records)
    assert sorted(sorted(r.id for r in c.records) for c in clusters) == [["a", "b"], ["c"]]


@pytest.mark.parametrize("bad", [True, False, 0, -1, 21, 1.0, "5", None])
def test_invalid_shingle_controls_fail_even_for_empty_splits(bad):
    with pytest.raises(ValueError):
        audit_splits({"train": [], "test": []}, shingle_size=bad)
    with pytest.raises(ValueError):
        cluster_records([_lure("a", "one")], shingle_size=bad)


@pytest.mark.parametrize("bad", [True, False, float("nan"), float("inf"), -.1, 1.1, "0.8", None])
def test_invalid_threshold_controls_fail(bad):
    with pytest.raises(ValueError):
        audit_splits({"train": [], "test": []}, threshold=bad)
    with pytest.raises(ValueError):
        cluster_records([_lure("a", "one")], threshold=bad)


@pytest.mark.parametrize("pairs", [["train=a", "train=b"], ["=a"], ["train="], ["missing"]])
def test_split_options_cannot_silently_replace_inputs(pairs):
    with pytest.raises(ValueError):
        _parse_splits(pairs)


def test_cli_single_split_cannot_claim_a_clean_boundary_audit(tmp_path, capsys):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    assert main(["audit-splits", "--split", f"train={path}"]) == 1
    captured = capsys.readouterr()
    assert "at least two" in captured.err
    assert not captured.out
