from __future__ import annotations

import json

import pytest

from lurebench.cli import main
from lurebench.incident_response import (
    evaluate_ir_responses,
    export_ir_tasks,
    reference_ir_responses,
    validate_ir_evaluation,
)


def test_ir_reference_response_passes_and_tasks_withhold_key(tmp_path):
    responses = tmp_path / "responses.json"
    responses.write_text(json.dumps(reference_ir_responses()) + "\n", encoding="utf-8")
    report = evaluate_ir_responses(
        responses,
        responder_id="reference-responder",
        responder_version="1.0.0",
        generated_at="2026-08-29T12:00:00Z",
    )
    assert report["summary"]["verdict"] == "pass"
    assert report["summary"]["fact_recall"] == 1.0
    tasks = export_ir_tasks(created_at="2026-08-29T11:00:00Z")
    serialized = json.dumps(tasks).lower()
    assert all(
        set(case) == {"case_id", "title", "events", "response_contract"} for case in tasks["cases"]
    )
    for withheld in ("safe_actions", "prohibited_actions", "minimum_evidence_ids"):
        assert withheld not in serialized
    assert all(
        set(event) == {"event_id", "sequence", "event_type", "signal_code", "outcome"}
        for case in tasks["cases"]
        for event in case["events"]
    )


def test_ir_unsupported_containment_action_fails(tmp_path):
    artifact = reference_ir_responses()
    artifact["responses"][0]["containment_actions"].append("delete_evidence")
    responses = tmp_path / "unsafe.json"
    responses.write_text(json.dumps(artifact), encoding="utf-8")
    report = evaluate_ir_responses(
        responses, responder_id="unsafe-responder", responder_version="1.0.0"
    )
    assert report["summary"]["verdict"] == "fail"
    assert report["summary"]["unsafe_action_rate"] > 0


def test_ir_requires_complete_evidence_and_useful_containment(tmp_path):
    artifact = reference_ir_responses()
    artifact["responses"][0]["findings"][0]["evidence_ids"] = ["egress-2"]
    artifact["responses"][0]["containment_actions"] = []
    responses = tmp_path / "incomplete.json"
    responses.write_text(json.dumps(artifact), encoding="utf-8")
    report = evaluate_ir_responses(
        responses, responder_id="incomplete-responder", responder_version="1.0.0"
    )
    assert report["summary"]["evidence_support_rate"] < 1.0
    assert report["summary"]["containment_action_recall"] < 1.0
    assert report["summary"]["verdict"] == "fail"


def test_ir_cli_exports_tasks_and_scores(tmp_path):
    tasks = tmp_path / "tasks.json"
    assert main(["ir-tasks", "--out", str(tasks)]) == 0
    responses = tmp_path / "responses.json"
    responses.write_text(json.dumps(reference_ir_responses()), encoding="utf-8")
    report = tmp_path / "report.json"
    assert (
        main(
            [
                "ir-eval",
                "--responses",
                str(responses),
                "--responder-id",
                "reference-responder",
                "--responder-version",
                "1.0.0",
                "--out",
                str(report),
            ]
        )
        == 0
    )


def test_ir_report_rejects_scoring_key_and_summary_rewrites(tmp_path):
    responses = tmp_path / "responses.json"
    responses.write_text(json.dumps(reference_ir_responses()), encoding="utf-8")
    report = evaluate_ir_responses(
        responses, responder_id="reference-responder", responder_version="1.0.0"
    )
    changed = json.loads(json.dumps(report))
    changed["results"][0]["expected_facts"] += 1
    with pytest.raises(ValueError, match="reviewed key"):
        validate_ir_evaluation(changed)
    changed = json.loads(json.dumps(report))
    changed["summary"]["unsafe_action_rate"] = 0.5
    with pytest.raises(ValueError, match="does not reconcile"):
        validate_ir_evaluation(changed)
