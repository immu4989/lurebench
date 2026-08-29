from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from lurebench.cli import main
from lurebench.invariant import (
    evaluate_invariants,
    load_invariant_inputs,
    validate_invariant_evaluation,
)

ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples" / "lureinvariant"


def _paths(name: str) -> tuple[Path, Path]:
    return EXAMPLES / f"{name}-plan.json", EXAMPLES / f"{name}-observations.json"


def _write_inputs(tmp_path: Path, plan: dict, observations: dict) -> tuple[Path, Path]:
    plan_path = tmp_path / "plan.json"
    plan_raw = json.dumps(plan, sort_keys=True).encode("utf-8") + b"\n"
    plan_path.write_bytes(plan_raw)
    observations["plan_sha256"] = hashlib.sha256(plan_raw).hexdigest()
    observations_path = tmp_path / "observations.json"
    observations_path.write_text(json.dumps(observations, sort_keys=True) + "\n", encoding="utf-8")
    return plan_path, observations_path


def test_reference_before_finds_cross_layer_and_temporal_violations():
    report = evaluate_invariants(*_paths("before"), generated_at="2026-08-29T14:00:00Z")
    assert report["summary"] == {
        "total_invariants": 4,
        "violated": 4,
        "not_observed_within_declared_boundary": 0,
        "insufficient_evidence": 0,
        "required_sources": 2,
        "complete_required_sources": 2,
        "source_coverage": 1.0,
        "unknown_edges": 0,
        "verdict": "fail",
    }
    egress = report["results"][0]
    assert egress["path_node_ids"] == ["eval-agent", "package-mirror", "public-internet"]
    assert egress["path_edge_ids"] == ["agent-to-mirror", "mirror-to-internet"]
    assert report["results"][2]["observed_delay_ms"] == 7000


def test_reference_after_passes_same_invariants_with_bounded_claim():
    report = evaluate_invariants(*_paths("after"), generated_at="2026-08-29T14:00:00Z")
    assert report["summary"]["verdict"] == "pass"
    assert report["summary"]["violated"] == 0
    assert report["summary"]["not_observed_within_declared_boundary"] == 4
    assert {result["status"] for result in report["results"]} == {
        "not_observed_within_declared_boundary"
    }


def test_unknown_path_and_incomplete_sources_never_turn_green(tmp_path: Path):
    plan = json.loads(_paths("after")[0].read_text(encoding="utf-8"))
    observations = json.loads(_paths("after")[1].read_text(encoding="utf-8"))
    plan["edges"][1]["state"] = "unknown"
    plan_path, observation_path = _write_inputs(tmp_path, plan, observations)
    report = evaluate_invariants(plan_path, observation_path)
    assert report["summary"]["verdict"] == "insufficient_evidence"
    assert report["summary"]["unknown_edges"] == 1
    assert report["results"][0]["reason_code"] == "relevant_path_state_unknown"

    second = tmp_path / "incomplete"
    second.mkdir()
    plan = json.loads(_paths("after")[0].read_text(encoding="utf-8"))
    observations = json.loads(_paths("after")[1].read_text(encoding="utf-8"))
    observations["source_status"][1]["complete"] = False
    plan_path, observation_path = _write_inputs(second, plan, observations)
    report = evaluate_invariants(plan_path, observation_path)
    assert report["summary"]["verdict"] == "insufficient_evidence"
    assert report["summary"]["complete_required_sources"] == 1
    assert report["summary"]["insufficient_evidence"] == 4


def test_v1_is_fail_closed_and_enforces_causal_evidence(tmp_path: Path):
    plan = json.loads(_paths("after")[0].read_text(encoding="utf-8"))
    observations = json.loads(_paths("after")[1].read_text(encoding="utf-8"))
    plan["acceptance"]["allow_insufficient_evidence"] = True
    allow_insufficient = tmp_path / "allow-insufficient"
    allow_insufficient.mkdir()
    plan_path, observations_path = _write_inputs(allow_insufficient, plan, observations)
    with pytest.raises(ValueError, match="never accepts insufficient"):
        evaluate_invariants(plan_path, observations_path)

    overlap = tmp_path / "overlap"
    overlap.mkdir()
    plan = json.loads(_paths("after")[0].read_text(encoding="utf-8"))
    observations = json.loads(_paths("after")[1].read_text(encoding="utf-8"))
    plan["invariants"][1]["mediation_node_ids"] = ["eval-agent"]
    plan_path, observations_path = _write_inputs(overlap, plan, observations)
    with pytest.raises(ValueError, match="distinct from subjects"):
        evaluate_invariants(plan_path, observations_path)

    predates = tmp_path / "predates"
    predates.mkdir()
    plan = json.loads(_paths("after")[0].read_text(encoding="utf-8"))
    observations = json.loads(_paths("after")[1].read_text(encoding="utf-8"))
    observations["captured_at"] = "2026-08-29T00:00:00Z"
    plan_path, observations_path = _write_inputs(predates, plan, observations)
    with pytest.raises(ValueError, match="cannot predate"):
        evaluate_invariants(plan_path, observations_path)

    with pytest.raises(ValueError, match="evaluation cannot predate"):
        evaluate_invariants(
            *_paths("after"), generated_at="2026-08-29T13:00:00Z"
        )


def test_failed_event_cannot_satisfy_response_or_claim_success(tmp_path: Path):
    plan = json.loads(_paths("after")[0].read_text(encoding="utf-8"))
    observations = json.loads(_paths("after")[1].read_text(encoding="utf-8"))
    observations["events"][1]["outcome"] = "failed"
    plan_path, observations_path = _write_inputs(tmp_path, plan, observations)
    report = evaluate_invariants(plan_path, observations_path)
    response = next(
        item
        for item in report["results"]
        if item["invariant_id"] == "shutdown-within-five-seconds"
    )
    assert response["status"] == "violated"
    assert response["response_event_ids"] == []

    mismatch = tmp_path / "mismatch"
    mismatch.mkdir()
    plan = json.loads(_paths("after")[0].read_text(encoding="utf-8"))
    observations = json.loads(_paths("after")[1].read_text(encoding="utf-8"))
    observations["events"].append(
        {
            "event_id": "claimed-success",
            "occurred_ms": 9000,
            "event_type": "tool_call_succeeded",
            "run_id": "run-a",
            "actor_node_id": "eval-agent",
            "target_node_id": "package-mirror",
            "outcome": "failed",
            "evidence_source_id": "telemetry",
        }
    )
    plan_path, observations_path = _write_inputs(mismatch, plan, observations)
    with pytest.raises(ValueError, match="requires a succeeded outcome"):
        evaluate_invariants(plan_path, observations_path)


def test_report_semantics_are_recomputed_from_exact_inputs():
    plan, plan_raw, observations, observations_raw = load_invariant_inputs(*_paths("before"))
    report = evaluate_invariants(*_paths("before"), generated_at="2026-08-29T14:00:00Z")
    changed = json.loads(json.dumps(report))
    changed["summary"]["violated"] = 0
    with pytest.raises(ValueError, match="does not reconcile"):
        validate_invariant_evaluation(
            changed,
            plan=plan,
            plan_raw=plan_raw,
            observations=observations,
            observations_raw=observations_raw,
        )


def test_invariant_cli_exit_codes_and_private_no_overwrite(tmp_path: Path):
    output = tmp_path / "after-report.json"
    after_plan, after_observations = _paths("after")
    assert main(
        [
            "invariant-eval",
            "--plan",
            str(after_plan),
            "--observations",
            str(after_observations),
            "--out",
            str(output),
        ]
    ) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert main(
        [
            "invariant-eval",
            "--plan",
            str(after_plan),
            "--observations",
            str(after_observations),
            "--out",
            str(output),
        ]
    ) == 2
    assert main(
        [
            "invariant-eval",
            "--plan",
            str(_paths("before")[0]),
            "--observations",
            str(_paths("before")[1]),
        ]
    ) == 1
