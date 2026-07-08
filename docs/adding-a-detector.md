# Adding a detector

A LureBench detector is any object that scores a `Lure`. Contributing one is a
subclass with a single method, plus one line in the registry.

## The interface

```python
from lurebench.detectors.base import Detector
from lurebench.schema import Lure

class MyDetector(Detector):
    name = "my-detector"          # id used on the leaderboard
    task = "fraud"                # "fraud" (lure vs benign) or "provenance" (ai vs human)
    requires = []                 # optional-dependency extras, if any

    def score(self, lure: Lure) -> float | None:
        # return P(positive) in [0, 1], or None to abstain on this record
        return my_probability(lure.text)
```

That is the whole contract. `score` returns a probability for the detector's task:
for `fraud`, the probability the text is a fraud lure; for `provenance`, the
probability it was AI-written. Return `None` to skip a record (it is excluded from
the metrics and counted as skipped).

## Trainable detectors

If your detector learns from data, add a `train` classmethod so it can be fit on a
split and used in the cross-generator evaluation:

```python
    @classmethod
    def train(cls, records, task="fraud") -> "MyDetector":
        ...  # fit on records, return a ready-to-score instance
```

See `lurebench/detectors/tfidf.py` for a complete trainable example. Any detector
with `.train(records, task="provenance")` works with `lurebench cross-generator`.

## Register it

Add one line to `lurebench/detectors/__init__.py`. Dependency-free detectors go in
`_EAGER`; anything that imports heavy libraries goes in `_LAZY` so `import lurebench`
stays light:

```python
_LAZY = {
    "my-detector": "lurebench.detectors.my_detector:MyDetector",
    ...
}
```

Heavy imports (torch, transformers, an API client) must be imported lazily **inside**
`__init__`, not at module top level, and declared as an optional extra in
`pyproject.toml`.

## Run it

```bash
lurebench leaderboard --dataset data/full/core/test.jsonl -m my-detector
lurebench leaderboard --dataset data/full/core/test.jsonl -m my-detector --task provenance
```

Add a test that constructs the detector (or asserts a clean error when its extra is
absent) and scores it over `data/samples/lures.jsonl`. See `tests/` for the pattern.
Then open a PR. New detectors are the most valuable contribution: the point of the
benchmark is to see what beats the baselines.
