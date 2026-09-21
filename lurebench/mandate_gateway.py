"""Run an explicit trusted adapter through one ordered conformance session.

This is a synchronous integration interface, not a sandbox or a timeout layer.
Adapters own transport timeouts and must target disposable test environments.
"""

from __future__ import annotations

import copy
import importlib
import inspect
import re
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Protocol

from .mandate import DECISIONS, REASON_CODES, _now, _sha256
from .mandate_conformance import (
    CONFORMANCE_LIMITATIONS,
    SUBMISSION_SCHEMA,
    validate_mandate_challenge,
    validate_mandate_submission,
    write_mandate_submission,
)
from .permit import _canonical, _exact


class MandateGatewayAdapter(Protocol):
    def begin(self, plan: Mapping[str, Any], execution: Mapping[str, Any]) -> None:
        """Initialize one isolated test session using the supplied logical time."""

    def decide(self, case: Mapping[str, Any]) -> Mapping[str, str]:
        """Return exactly decision and reason_code, retaining session state."""

    def close(self) -> None:
        """Release the test session, including when initialization or a case fails."""


def _is_synchronous_callable(value: Any) -> bool:
    if not callable(value):
        return False
    return not any(
        predicate(target)
        for target in (value, value.__call__)
        for predicate in (
            inspect.iscoroutinefunction,
            inspect.isasyncgenfunction,
            inspect.isgeneratorfunction,
        )
    )


def _synchronous_result(value: Any) -> Any:
    if inspect.iscoroutine(value):
        value.close()  # Do not leave an unawaited coroutine warning behind.
        raise ValueError("adapter returned an asynchronous result")
    if inspect.isawaitable(value) or inspect.isasyncgen(value):
        raise ValueError("adapter returned an asynchronous result")
    if inspect.isgenerator(value):
        value.close()
        raise ValueError("adapter returned a generator instead of a synchronous result")
    return value


def load_mandate_gateway_adapter(specification: str) -> MandateGatewayAdapter:
    """Import a user-selected, zero-argument adapter factory without using a shell."""
    if not isinstance(specification, str) or not re.fullmatch(
        r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", specification, flags=re.ASCII
    ):
        raise ValueError("adapter must be an importable module:factory")
    module_name, factory_name = specification.split(":")
    factory = getattr(importlib.import_module(module_name), factory_name)
    if not _is_synchronous_callable(factory):
        raise ValueError("adapter factory must be synchronous and callable")
    adapter = _synchronous_result(factory())
    _validate_adapter(adapter)
    return adapter


def _validate_adapter(adapter: MandateGatewayAdapter) -> None:
    for name in ("begin", "decide", "close"):
        method = getattr(adapter, name, None)
        if not _is_synchronous_callable(method):
            raise ValueError("adapter must implement synchronous begin, decide, and close")


def _submission_template(
    challenge: Mapping[str, Any],
    *,
    submission_id: str,
    engine_id: str,
    engine_version: str,
    engine_artifact_sha256: Optional[str] = None,
    submitted_at: Optional[str] = None,
) -> Dict[str, Any]:
    submission = {
        "schema": SUBMISSION_SCHEMA,
        "schema_version": 1,
        "submission_id": submission_id,
        "submitted_at": _now() if submitted_at is None else submitted_at,
        "challenge_id": challenge["challenge_id"],
        "challenge_sha256": _sha256(_canonical(challenge)),
        "engine": {
            "engine_id": engine_id,
            "engine_version": engine_version,
            "engine_artifact_sha256": engine_artifact_sha256,
        },
        "results": [
            {"case_id": case["case_id"], "decision": "block", "reason_code": "policy_unknown"}
            for case in challenge["cases"]
        ],
        "limitations": list(CONFORMANCE_LIMITATIONS),
    }
    return validate_mandate_submission(submission, challenge)


def run_mandate_gateway(
    challenge_value: Mapping[str, Any],
    adapter: MandateGatewayAdapter,
    *,
    submission_id: str,
    engine_id: str,
    engine_version: str,
    engine_artifact_sha256: Optional[str] = None,
    submitted_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Produce an all-or-error submission; the adapter never receives oracle answers.

    Copies isolate the caller's challenge from adapter mutation. There are no
    retries: repeating a stateful decision may consume authority twice.
    """
    challenge = copy.deepcopy(validate_mandate_challenge(challenge_value))
    submission = _submission_template(
        challenge,
        submission_id=submission_id,
        engine_id=engine_id,
        engine_version=engine_version,
        engine_artifact_sha256=engine_artifact_sha256,
        submitted_at=submitted_at,
    )
    _validate_adapter(adapter)
    results = []
    try:
        initialized = _synchronous_result(
            adapter.begin(copy.deepcopy(challenge["plan"]), copy.deepcopy(challenge["execution"]))
        )
        if initialized is not None:
            raise ValueError("adapter begin must return None")
        for case in challenge["cases"]:
            response = _synchronous_result(adapter.decide(copy.deepcopy(case)))
            decision = _exact(response, "adapter decision", ("decision", "reason_code"))
            if (
                not isinstance(decision["decision"], str)
                or not isinstance(decision["reason_code"], str)
                or decision["decision"] not in DECISIONS
                or decision["reason_code"] not in REASON_CODES
            ):
                raise ValueError("adapter returned an unsupported decision or reason code")
            results.append({"case_id": case["case_id"], **copy.deepcopy(decision)})
    finally:
        if _synchronous_result(adapter.close()) is not None:
            raise ValueError("adapter close must return None")
    submission["results"] = results
    if submitted_at is None:
        submission["submitted_at"] = _now()
    return validate_mandate_submission(submission, challenge)


def run_mandate_gateway_to_file(
    challenge_value: Mapping[str, Any],
    adapter_specification: str,
    output_path: Path,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Preflight output, challenge, and metadata before importing adapter code."""
    output = Path(output_path)
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("adapter output parent must be a regular directory")
    challenge = validate_mandate_challenge(challenge_value)
    _submission_template(challenge, **kwargs)
    adapter = load_mandate_gateway_adapter(adapter_specification)
    submission = run_mandate_gateway(challenge, adapter, **kwargs)
    write_mandate_submission(output, submission, challenge)
    return submission
