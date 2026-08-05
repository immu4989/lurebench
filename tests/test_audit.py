from lurebench.audit import audit_splits, family_id
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
