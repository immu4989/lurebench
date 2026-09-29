"""Synthetic producer/consumer check; no providers, files, or deployment claims."""

from types import SimpleNamespace

from lurescope.capacity import plan_capacity

from lurebench.harness import run
from lurebench.schema import Lure


def main():
    truths = [1, 0, 0, 1, 1, 0]
    scores = [.9, .9, .1, .1, None, None]
    records = [Lure(id=str(i), text=f"synthetic {i}", label=label, source="human",
                    typology="phishing" if label else "benign")
               for i, label in enumerate(truths)]
    detector = SimpleNamespace(name="synthetic-interop", task="fraud",
                               score=lambda r: scores[int(r.id)])
    report = run(detector, records).decision_counts()
    assert set(report["counts"].values()) == {1}
    projection = plan_capacity(report, messages_per_period=600, prevalences=[.5],
                               review_minutes_per_case=6, available_review_hours=40)
    row = projection["scenarios"][0]
    assert row["expected_review_cases"] == 400
    assert row["required_review_hours"] == 40
    assert row["exceeds_review_capacity"] is False
    assert set(row["expected_outcomes"].values()) == {100.}
    print("capacity interop: six outcomes preserved; synthetic projection verified")


if __name__ == "__main__":
    main()
