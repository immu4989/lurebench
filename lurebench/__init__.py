"""LureBench: a benchmark and evaluation harness for detecting AI-generated fraud lures.

Two evaluation tasks are supported, reflecting the empirical finding that
detectors specialise:

  * ``fraud``      — is this text a fraud lure (label 1) vs. benign (label 0)?
  * ``provenance`` — was this text AI-generated (source ``ai``) vs. human-written?

Import the harness and a baseline detector:

    >>> from lurebench import load_jsonl, run
    >>> from lurebench.detectors import HeuristicDetector
    >>> data = load_jsonl("data/samples/lures.jsonl")
    >>> report = run(HeuristicDetector(), data)
    >>> print(report.metrics.mcc)
"""

from .schema import Lure, load_jsonl, save_jsonl
from .metrics import Metrics, evaluate
from .harness import Report, run

__version__ = "0.1.0"

__all__ = [
    "Lure",
    "load_jsonl",
    "save_jsonl",
    "Metrics",
    "evaluate",
    "Report",
    "run",
    "__version__",
]
