"""Offline installation diagnostics for shipped authority reference evidence."""

from __future__ import annotations

import copy
import hashlib
import importlib
from pathlib import Path
from typing import Any, Dict, Optional

from . import __version__
from .mandate import _read
from .receipts import loads_strict_json

REFERENCE_CASES = (
    ("authority", "mandate", "validate_mandate_evaluation", "luremandate-v1/evaluation.json"),
    (
        "telemetry",
        "mandate_otel",
        "validate_mandate_otel_projection",
        "luremandate-v1/otel-projection.json",
    ),
    (
        "gateway-score",
        "mandate_conformance",
        "validate_mandate_conformance_score",
        "luremandate-v1/conformance-score.json",
    ),
    (
        "pairwise",
        "mandate_pairwise",
        "validate_pairwise_mandate_conformance",
        "luremandate-pairwise-v1/pairwise-assurance.json",
    ),
    (
        "counterfactual",
        "mandate_counterfactual",
        "validate_counterfactual_mandate_conformance",
        "luremandate-counterfactual-v1/counterfactual-assurance.json",
    ),
    (
        "sequence",
        "mandate_sequence",
        "validate_sequence_mandate_conformance",
        "luremandate-sequence-v1/sequence-assurance.json",
    ),
    (
        "shared-state",
        "mandate_conformance",
        "validate_mandate_conformance_score",
        "luremandate-transitions-v1/score.json",
    ),
)


def reference_corpus_root() -> Path:
    package = Path(__file__).resolve().parent
    installed = package / "conformance_data"
    if installed.is_dir():
        return installed
    checkout = package.parent
    if (checkout / "pyproject.toml").is_file() and (checkout / "conformance").is_dir():
        return checkout / "conformance"
    raise FileNotFoundError("installed LureBench authority reference corpus is unavailable")


def _rejection_probes(value: Dict[str, Any], validator: Any) -> Dict[str, bool]:
    """Exercise parser and recomputation failure paths without changing fixtures."""
    probes = {}
    for name in ("boolean-version", "float-version", "unknown-field", "derived-claim"):
        mutated = copy.deepcopy(value)
        if name == "boolean-version":
            mutated["schema_version"] = True
        elif name == "float-version":
            mutated["schema_version"] = 1.0
        elif name == "unknown-field":
            mutated["selftest_unrecognized_field"] = True
        elif "summary" in mutated:
            mutated["summary"]["verdict"] = "fail"
        else:
            digest = mutated["run_sha256"]
            mutated["run_sha256"] = ("1" if digest[0] == "0" else "0") + digest[1:]
        try:
            validator(mutated)
        except ValueError:
            probes[name] = True
        else:
            probes[name] = False
    return probes


def run_mandate_selftest(corpus_root: Optional[Path] = None) -> Dict[str, Any]:
    root = Path(corpus_root) if corpus_root is not None else reference_corpus_root()
    results = []
    for name, module_name, validator_name, relative in REFERENCE_CASES:
        record: Dict[str, Any] = {"profile": name, "artifact": relative, "status": "error"}
        try:
            payload = _read(root / relative, "reference artifact")
            module = importlib.import_module(f"lurebench.{module_name}")
            value = loads_strict_json(payload)
            validator = getattr(module, validator_name)
            result = validator(value)
            if module_name == "mandate_otel":
                passed = len(result["run"]["transactions"]) == 16
            else:
                passed = result.get("summary", {}).get("verdict") == "pass"
            probes = _rejection_probes(value, validator)
            record["rejection_probes"] = probes
            record["status"] = "pass" if passed and all(probes.values()) else "fail"
            record["artifact_sha256"] = hashlib.sha256(payload).hexdigest()
        except (OSError, ValueError, ImportError, KeyError, TypeError) as exc:
            record["error_type"] = type(exc).__name__
        results.append(record)
    passed = sum(item["status"] == "pass" for item in results)
    return {
        "kind": "lurebench-mandate-reference-selftest",
        "package_version": __version__,
        "reference_only": True,
        "summary": {
            "status": "pass" if passed == len(results) else "fail",
            "passed": passed,
            "total": len(results),
        },
        "results": results,
        "boundary": "Checks packaged reference evidence; no deployed gateway is tested.",
    }
