"""TF-IDF + Logistic Regression detector — the classical trained baseline.

Unlike ``heuristic-v0`` (hand-written keyword rules), this is a genuine trained
model: word/bigram TF-IDF features into an L2 logistic regression. It's the
standard "classical ML" bar every stronger detector should beat, it trains in
seconds on CPU, and it's fully reproducible from the train split.

Train once, then it loads from a saved artifact:

    lurebench train --dataset data/full/core/train.jsonl --out models/tfidf-logreg-fraud.joblib
    lurebench leaderboard -d data/full/core/test.jsonl -m tfidf-logreg

Requires the ``train`` extra: pip install "lurebench[train]"
"""

from __future__ import annotations

import os
from typing import List, Optional, Sequence

from ..schema import Lure
from .base import Detector

DEFAULT_MODEL = "models/tfidf-logreg-fraud.joblib"


class TfidfLogisticDetector(Detector):
    name = "tfidf-logreg"
    task = "fraud"
    requires = ["scikit-learn", "joblib"]

    def __init__(self, model_path: Optional[str] = None, task: str = "fraud") -> None:
        self.task = task
        self.model_path = model_path or DEFAULT_MODEL
        self._pipe = self._load(self.model_path)

    # --- construction helpers ------------------------------------------------

    @classmethod
    def from_pipeline(cls, pipeline, task: str) -> "TfidfLogisticDetector":
        obj = cls.__new__(cls)
        obj.task = task
        obj.model_path = None
        obj._pipe = pipeline
        return obj

    @staticmethod
    def _load(path: str):
        try:
            import joblib
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "TfidfLogisticDetector requires the 'train' extra: pip install 'lurebench[train]'"
            ) from exc
        if not os.path.exists(path):
            raise RuntimeError(
                f"no trained model at {path!r}. Train one first:\n"
                f"  lurebench train --dataset <train.jsonl> --out {path}"
            )
        blob = joblib.load(path)
        return blob["pipeline"]

    # --- training ------------------------------------------------------------

    @classmethod
    def train(cls, records: Sequence[Lure], task: str = "fraud") -> "TfidfLogisticDetector":
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
            from sklearn.pipeline import Pipeline
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "training requires the 'train' extra: pip install 'lurebench[train]'"
            ) from exc
        from ..harness import TASK_TARGET

        target = TASK_TARGET[task]
        texts = [r.text for r in records]
        labels = [target(r) for r in records]
        pipeline = Pipeline(
            [
                ("tfidf", TfidfVectorizer(
                    ngram_range=(1, 2), min_df=2, max_features=50000, sublinear_tf=True,
                )),
                ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
            ]
        )
        pipeline.fit(texts, labels)
        return cls.from_pipeline(pipeline, task)

    def save(self, path: str) -> None:
        import joblib

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        joblib.dump({"pipeline": self._pipe, "task": self.task}, path)

    # --- scoring -------------------------------------------------------------

    def score(self, lure: Lure) -> Optional[float]:
        proba = self._pipe.predict_proba([lure.text])[0]
        classes = list(self._pipe.classes_)
        idx = classes.index(1) if 1 in classes else len(classes) - 1
        return float(proba[idx])

    def top_positive_features(self, top_k: int = 25) -> List[str]:
        """The words most predictive of the positive class — the targeted attacker's
        list of terms to avoid. Requires a linear model with named features."""
        try:
            vec = self._pipe.named_steps.get("tfidf") or self._pipe.named_steps.get("vec")
            clf = self._pipe.named_steps.get("clf") or self._pipe.named_steps.get("logreg")
            names = vec.get_feature_names_out()
            coef = clf.coef_[0]
        except (AttributeError, KeyError, IndexError):
            return []
        order = sorted(range(len(coef)), key=lambda i: coef[i], reverse=True)
        return [str(names[i]) for i in order[:top_k]]
