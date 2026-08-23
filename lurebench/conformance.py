"""Executable, language-neutral conformance suite for LureEval v1 semantics."""

from __future__ import annotations

import hashlib
import json
import os
import re
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Optional, Sequence

from . import __version__
from .receipts import (
    loads_strict_json,
    validate_aggregate_statement,
    validate_receipt_statement,
)

SUITE_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureeval-conformance-suite/v1"
REPORT_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureeval-conformance-report/v1"
SUITE_ID = "lureeval-v1-semantic"
SUITE_VERSION = "1.0.0"
MAX_SUITE_BYTES = 256 * 1024
MAX_CASE_BYTES = 8 * 1024 * 1024
MAX_CASES = 64

_IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[a-z0-9._-]*[a-z0-9])?$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_JSON_PATH = re.compile(r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.json$")
_CATEGORIES = {
    "baseline",
    "privacy-boundary",
    "schema-boundary",
    "semantic-integrity",
    "serialization",
    "statistical-consistency",
}
_LIMITATIONS = [
    "suite_tests_protocol_conformance_not_detector_quality",
    "passing_does_not_establish_security_compliance_or_deployment_effectiveness",
    "dsse_authentication_is_outside_the_semantic_v1_profile",
]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _exact_object(
    value: Any,
    field: str,
    *,
    required: Sequence[str],
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    expected = set(required)
    if set(value) != expected:
        raise ValueError(f"{field} must contain exactly: {', '.join(sorted(expected))}")
    return value


def _safe_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) > 96 or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a bounded lowercase identifier")
    return value


def _safe_relative_json(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) > 240:
        raise ValueError(f"{field} must be a bounded relative JSON path")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or parsed.suffix != ".json":
        raise ValueError(f"{field} must stay inside the suite and end in .json")
    if any(not part or part.startswith(".") for part in parsed.parts):
        raise ValueError(f"{field} contains an unsupported path component")
    if not _JSON_PATH.fullmatch(value):
        raise ValueError(f"{field} contains characters outside the portable path profile")
    return value


def validate_suite_manifest(value: Any) -> Dict[str, Any]:
    """Validate the strict suite manifest before reading any referenced artifact."""

    manifest = _exact_object(
        value,
        "suite",
        required=(
            "schema",
            "schema_version",
            "suite_id",
            "suite_version",
            "protocol",
            "description",
            "cases",
        ),
    )
    if manifest["schema"] != SUITE_SCHEMA or manifest["schema_version"] != 1:
        raise ValueError("unsupported LureEval conformance suite schema")
    if manifest["suite_id"] != SUITE_ID or manifest["suite_version"] != SUITE_VERSION:
        raise ValueError("unsupported LureEval conformance suite identity")
    if manifest["protocol"] != "lureeval-v1":
        raise ValueError("suite protocol must be lureeval-v1")
    description = manifest["description"]
    if not isinstance(description, str) or not 20 <= len(description) <= 500:
        raise ValueError("suite description must contain 20 to 500 characters")
    cases = manifest["cases"]
    if not isinstance(cases, list) or not 2 <= len(cases) <= MAX_CASES:
        raise ValueError(f"suite must contain between 2 and {MAX_CASES} cases")

    case_ids: set[str] = set()
    artifact_paths: set[str] = set()
    accepted = rejected = 0
    normalized_cases = []
    for index, item in enumerate(cases):
        case = _exact_object(
            item,
            f"suite.cases[{index}]",
            required=(
                "case_id",
                "artifact",
                "sha256",
                "expected",
                "kind",
                "category",
                "description",
            ),
        )
        case_id = _safe_identifier(case["case_id"], f"suite.cases[{index}].case_id")
        if case_id in case_ids:
            raise ValueError("suite contains a duplicate case_id")
        case_ids.add(case_id)
        artifact = _safe_relative_json(case["artifact"], f"suite.cases[{index}].artifact")
        if artifact in artifact_paths:
            raise ValueError("every conformance case must bind a distinct artifact")
        artifact_paths.add(artifact)
        if not isinstance(case["sha256"], str) or not _DIGEST.fullmatch(case["sha256"]):
            raise ValueError(f"suite.cases[{index}].sha256 is invalid")
        if case["expected"] not in {"accept", "reject"}:
            raise ValueError(f"suite.cases[{index}].expected is unsupported")
        if case["kind"] not in {"receipt", "aggregate"}:
            raise ValueError(f"suite.cases[{index}].kind is unsupported")
        if case["category"] not in _CATEGORIES:
            raise ValueError(f"suite.cases[{index}].category is unsupported")
        item_description = case["description"]
        if not isinstance(item_description, str) or not 12 <= len(item_description) <= 300:
            raise ValueError(f"suite.cases[{index}].description is invalid")
        accepted += case["expected"] == "accept"
        rejected += case["expected"] == "reject"
        normalized_cases.append(dict(case))
    if accepted < 2 or rejected < 4:
        raise ValueError("suite must exercise at least two accept and four reject cases")
    return {**dict(manifest), "cases": normalized_cases}


def _read_external(root: Path, relative: str, maximum: int) -> bytes:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("conformance suite directory must be a regular local directory")
    target = root
    for component in PurePosixPath(relative).parts:
        target = target / component
        if target.is_symlink():
            raise ValueError(f"conformance suite path contains a symbolic link: {relative}")
    if target.is_symlink() or not target.is_file():
        raise ValueError(f"conformance suite artifact must be a regular file: {relative}")
    if target.stat().st_size > maximum:
        raise ValueError(f"conformance suite artifact exceeds its size limit: {relative}")
    return target.read_bytes()


def _read_packaged(relative: str, maximum: int) -> bytes:
    target = resources.files("lurebench").joinpath(
        "conformance_data", "lureeval-v1", *PurePosixPath(relative).parts
    )
    if target.is_file():
        payload = target.read_bytes()
    else:
        # Editable/source checkouts keep the language-neutral vectors at the
        # repository root; wheels install the same bytes as package data.
        source_suite = Path(__file__).resolve().parents[1] / "conformance" / "lureeval-v1"
        try:
            payload = _read_external(source_suite, relative, maximum)
        except ValueError as exc:
            raise ValueError(f"packaged conformance artifact is missing: {relative}") from exc
    if len(payload) > maximum:
        raise ValueError(f"packaged conformance artifact exceeds its size limit: {relative}")
    return payload


def _read(suite_dir: Optional[Path], relative: str, maximum: int) -> bytes:
    return (
        _read_packaged(relative, maximum)
        if suite_dir is None
        else _read_external(Path(suite_dir), relative, maximum)
    )


def _validate_case(payload: bytes, kind: str) -> None:
    artifact = loads_strict_json(payload)
    if not isinstance(artifact, dict):
        raise ValueError("conformance artifact must be a JSON object")
    if kind == "receipt":
        validate_receipt_statement(artifact)
    else:
        validate_aggregate_statement(artifact)


def validate_conformance_report(value: Any) -> None:
    """Strictly validate a machine-readable conformance report."""

    report = _exact_object(
        value,
        "report",
        required=(
            "schema",
            "schema_version",
            "suite",
            "implementation",
            "summary",
            "cases",
            "limitations",
        ),
    )
    if report["schema"] != REPORT_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported conformance report schema")
    suite = _exact_object(
        report["suite"],
        "report.suite",
        required=("suite_id", "suite_version", "manifest_sha256"),
    )
    if suite["suite_id"] != SUITE_ID or suite["suite_version"] != SUITE_VERSION:
        raise ValueError("report binds an unsupported suite")
    if not isinstance(suite["manifest_sha256"], str) or not _DIGEST.fullmatch(
        suite["manifest_sha256"]
    ):
        raise ValueError("report suite digest is invalid")
    implementation = _exact_object(
        report["implementation"],
        "report.implementation",
        required=("name", "version"),
    )
    _safe_identifier(implementation["name"], "report.implementation.name")
    if not isinstance(implementation["version"], str) or not 1 <= len(
        implementation["version"]
    ) <= 64:
        raise ValueError("report implementation version is invalid")
    summary = _exact_object(
        report["summary"],
        "report.summary",
        required=("total", "passed", "failed", "accept_cases", "reject_cases", "verdict"),
    )
    for key in ("total", "passed", "failed", "accept_cases", "reject_cases"):
        if isinstance(summary[key], bool) or not isinstance(summary[key], int) or summary[key] < 0:
            raise ValueError(f"report.summary.{key} must be a non-negative integer")
    if summary["total"] > MAX_CASES:
        raise ValueError(f"report cannot contain more than {MAX_CASES} cases")
    if summary["total"] != summary["passed"] + summary["failed"]:
        raise ValueError("report summary pass/fail counts do not reconcile")
    if summary["total"] != summary["accept_cases"] + summary["reject_cases"]:
        raise ValueError("report summary accept/reject counts do not reconcile")
    expected_verdict = "pass" if summary["failed"] == 0 else "fail"
    if summary["verdict"] != expected_verdict:
        raise ValueError("report verdict does not match its failures")
    cases = report["cases"]
    if not isinstance(cases, list) or len(cases) != summary["total"]:
        raise ValueError("report cases do not match the summary total")
    seen = set()
    passed = accept_cases = reject_cases = 0
    for index, item in enumerate(cases):
        result = _exact_object(
            item,
            f"report.cases[{index}]",
            required=("case_id", "expected", "actual", "passed"),
        )
        case_id = _safe_identifier(result["case_id"], f"report.cases[{index}].case_id")
        if case_id in seen:
            raise ValueError("report contains a duplicate case result")
        seen.add(case_id)
        if result["expected"] not in {"accept", "reject"} or result["actual"] not in {
            "accept",
            "reject",
        }:
            raise ValueError("report contains an unsupported case verdict")
        if not isinstance(result["passed"], bool):
            raise ValueError("report case passed must be boolean")
        if result["passed"] != (result["expected"] == result["actual"]):
            raise ValueError("report case verdict and passed flag disagree")
        passed += result["passed"]
        accept_cases += result["expected"] == "accept"
        reject_cases += result["expected"] == "reject"
    if (passed, accept_cases, reject_cases) != (
        summary["passed"],
        summary["accept_cases"],
        summary["reject_cases"],
    ):
        raise ValueError("report case results do not reconcile with the summary")
    if report["limitations"] != _LIMITATIONS:
        raise ValueError("report limitations are not the conformance v1 boundary")


def run_conformance_suite(suite_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Run the packaged or supplied LureEval semantic suite and return a report."""

    manifest_payload = _read(suite_dir, "suite.json", MAX_SUITE_BYTES)
    manifest = validate_suite_manifest(loads_strict_json(manifest_payload))
    results = []
    for case in manifest["cases"]:
        payload = _read(suite_dir, case["artifact"], MAX_CASE_BYTES)
        if _sha256(payload) != case["sha256"]:
            raise ValueError(f"conformance artifact digest mismatch: {case['case_id']}")
        actual = "accept"
        try:
            _validate_case(payload, case["kind"])
        except ValueError:
            actual = "reject"
        results.append(
            {
                "case_id": case["case_id"],
                "expected": case["expected"],
                "actual": actual,
                "passed": actual == case["expected"],
            }
        )
    passed = sum(item["passed"] for item in results)
    accept_cases = sum(item["expected"] == "accept" for item in results)
    report = {
        "schema": REPORT_SCHEMA,
        "schema_version": 1,
        "suite": {
            "suite_id": manifest["suite_id"],
            "suite_version": manifest["suite_version"],
            "manifest_sha256": _sha256(manifest_payload),
        },
        "implementation": {"name": "lurebench", "version": __version__},
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "accept_cases": accept_cases,
            "reject_cases": len(results) - accept_cases,
            "verdict": "pass" if passed == len(results) else "fail",
        },
        "cases": results,
        "limitations": list(_LIMITATIONS),
    }
    validate_conformance_report(report)
    return report


def dumps_report(report: Mapping[str, Any]) -> str:
    validate_conformance_report(report)
    return json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    """Create a mode-0600 report without overwriting or following links."""

    target = Path(path)
    payload = dumps_report(report).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
