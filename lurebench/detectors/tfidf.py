"""TF-IDF + Logistic Regression detector — the classical trained baseline.

Unlike ``heuristic-v0`` (hand-written keyword rules), this is a genuine trained
model: word/bigram TF-IDF features into an L2 logistic regression. It's the
standard "classical ML" bar every stronger detector should beat, it trains in
seconds on CPU, and it's fully reproducible from the train split.

Train once, then it loads from a saved artifact:

    lurebench train --dataset data/full/core/train.jsonl --out models/tfidf-logreg-fraud.joblib
    lurebench leaderboard -d data/full/core/test.jsonl -m tfidf-logreg

Requires the ``train`` extra: pip install "lurebench[train]"

Joblib loading executes Python serialization: use only trusted artifacts. The
metadata/output checks below enforce meaning, not safe deserialization.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import platform
import re
from collections.abc import Mapping
from importlib.metadata import PackageNotFoundError, version
from numbers import Integral, Real
from pathlib import Path
from typing import List, Optional, Sequence

from ..local_io import read_regular_file
from ..probability import validate_score
from ..schema import Lure
from .base import Detector

DEFAULT_MODEL = "models/tfidf-logreg-fraud.joblib"
MAX_MODEL_BYTES = 64 * 1024 * 1024
SCORE_CONTRACT = "tfidf-binary-full-row-task-bound-v2"


def _pin(value, name):
    if value is not None and (not isinstance(value, str)
                              or re.fullmatch(r"[0-9a-f]{64}", value) is None):
        raise ValueError(f"{name} must be a lowercase SHA-256 identity")
    return value


def _runtime_versions():
    versions = {"python": platform.python_version(), "implementation": platform.python_implementation()}
    for name in ("scikit-learn", "numpy", "scipy", "joblib"):
        try:
            versions[name] = version(name)
        except PackageNotFoundError:
            versions[name] = None
    return versions


def _task(value):
    if not isinstance(value, str) or value not in ("fraud", "provenance"):
        raise ValueError("trained model task must be fraud or provenance")
    return value


def _class_labels(pipeline):
    classes = getattr(pipeline, "classes_", None)
    try:
        if isinstance(classes, (str, bytes, Mapping)) or len(classes) != 2:
            raise ValueError("trained model requires exactly the integer classes 0 and 1")
        values = (classes[0], classes[1])
    except (TypeError, IndexError, KeyError) as exc:
        raise ValueError("trained model requires exactly the integer classes 0 and 1") from exc
    if any(isinstance(value, bool) or not isinstance(value, Integral) for value in values):
        raise ValueError("trained model requires exactly the integer classes 0 and 1")
    values = tuple(int(value) for value in values)
    if values not in ((0, 1), (1, 0)):
        raise ValueError("trained model requires exactly the integer classes 0 and 1")
    return values


class TfidfLogisticDetector(Detector):
    name = "tfidf-logreg"
    task = "fraud"
    requires = ["scikit-learn", "joblib"]

    def __init__(self, model_path: Optional[str] = None, task: Optional[str] = None,
                 *, expected_sha256: Optional[str] = None,
                 cache_context: Optional[str] = None) -> None:
        _pin(expected_sha256, "expected_sha256")
        _pin(cache_context, "cache_context")
        if task is not None:
            _task(task)  # Reject invalid caller metadata before deserialization.
        self.model_path = model_path or DEFAULT_MODEL
        self._pipe, self.task, self.model_sha256 = self._load(self.model_path, task, expected_sha256)
        self._classes = self._validate_pipeline(self._pipe)
        self.cache_namespace = self._cache_identity(cache_context)

    # --- construction helpers ------------------------------------------------

    @classmethod
    def from_pipeline(cls, pipeline, task: str, *,
                      cache_context: Optional[str] = None) -> "TfidfLogisticDetector":
        _pin(cache_context, "cache_context")
        obj = cls.__new__(cls)
        obj.task = _task(task)
        obj.model_path = None
        obj.model_sha256 = None
        obj._classes = cls._validate_pipeline(pipeline)
        obj._pipe = pipeline
        obj.cache_namespace = obj._cache_identity(cache_context)
        return obj

    def _cache_identity(self, cache_context):
        if self.model_sha256 is None and cache_context is None:
            return None
        identity = {"contract": SCORE_CONTRACT, "task": self.task,
                    "classes": self._classes, "model_sha256": self.model_sha256,
                    "reviewed_context": cache_context, "runtime": _runtime_versions()}
        return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def _validate_pipeline(pipeline):
        classes = _class_labels(pipeline)
        if not callable(getattr(pipeline, "predict_proba", None)):
            raise ValueError("trained pipeline requires predict_proba")
        return classes

    def _check_classes(self):
        if _class_labels(self._pipe) != self._classes:
            raise ValueError("trained model class mapping changed after construction")

    @staticmethod
    def _load(path: str, expected_task: Optional[str] = None,
              expected_sha256: Optional[str] = None):
        try:
            payload = read_regular_file(Path(path), maximum=MAX_MODEL_BYTES, label="trained model")
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"no trained model at {path!r}. Train one first:\n"
                f"  lurebench train --dataset <train.jsonl> --out {path}"
            ) from exc
        digest = hashlib.sha256(payload).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise ValueError("trained model SHA-256 does not match the expected identity")
        try:
            import joblib
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "TfidfLogisticDetector requires the 'train' extra: pip install 'lurebench[train]'"
            ) from exc
        # Hash and deserialize the same captured bytes, never reopen the path.
        # This is still trusted executable input; a digest is not authentication.
        blob = joblib.load(io.BytesIO(payload))
        if not isinstance(blob, dict) or "pipeline" not in blob:
            raise ValueError("trained model artifact requires pipeline and task metadata")
        stored_task = _task(blob.get("task"))
        if expected_task is not None and expected_task != stored_task:
            raise ValueError("requested task does not match trained model artifact task")
        return blob["pipeline"], stored_task, digest

    # --- training ------------------------------------------------------------

    @classmethod
    def train(cls, records: Sequence[Lure], task: str = "fraud", *,
              cache_context: Optional[str] = None) -> "TfidfLogisticDetector":
        _task(task)
        _pin(cache_context, "cache_context")
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
        return cls.from_pipeline(pipeline, task, cache_context=cache_context)

    def save(self, path: str) -> None:
        _task(self.task)
        self._check_classes()
        import joblib

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        joblib.dump({"pipeline": self._pipe, "task": self.task}, path)

    # --- scoring -------------------------------------------------------------

    def score(self, lure: Lure) -> Optional[float]:
        self._check_classes()
        output = self._pipe.predict_proba([lure.text])
        self._check_classes()
        try:
            if isinstance(output, (str, bytes, Mapping)) or len(output) != 1:
                raise ValueError("trained model must return one two-class probability row")
            row = output[0]
            if isinstance(row, (str, bytes, Mapping)) or len(row) != 2:
                raise ValueError("trained model must return one two-class probability row")
            probabilities = [validate_score(row[0]), validate_score(row[1])]
        except (TypeError, IndexError, KeyError) as exc:
            raise ValueError("trained model must return one two-class probability row") from exc
        if any(value is None for value in probabilities) or not math.isclose(
            math.fsum(probabilities), 1., rel_tol=0., abs_tol=1e-6,
        ):
            raise ValueError("trained class probabilities must be finite and sum to one")
        return probabilities[self._classes.index(1)]

    def top_positive_features(self, top_k: int = 25) -> List[str]:
        """The words most predictive of the positive class — the targeted attacker's
        list of terms to avoid. Requires a linear model with named features."""
        self._check_classes()
        try:
            vec = self._pipe.named_steps.get("tfidf") or self._pipe.named_steps.get("vec")
            clf = self._pipe.named_steps.get("clf") or self._pipe.named_steps.get("logreg")
            names = vec.get_feature_names_out()
            if _class_labels(clf) != self._classes or len(clf.coef_) != 1:
                return []
            coef = clf.coef_[0]
            if len(names) != len(coef) or any(
                isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value)
                for value in coef
            ):
                return []
        except (AttributeError, KeyError, IndexError, TypeError, ValueError, OverflowError):
            return []
        # Binary sklearn coefficients point toward classes_[1], not always label 1.
        direction = 1 if self._classes[1] == 1 else -1
        order = sorted(range(len(coef)), key=lambda i: direction * coef[i], reverse=True)
        return [str(names[i]) for i in order[:top_k]]
