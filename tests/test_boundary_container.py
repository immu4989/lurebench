from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from lurebench import boundary_container
from lurebench.boundary import run_boundary_evaluation
from lurebench.boundary_container import PROTOCOL, BoundaryContainerMonitor
from lurebench.cli import main

IMAGE_ID = "sha256:" + "a" * 64
PINNED = "example.invalid/boundary-monitor@sha256:" + "b" * 64


class _Input:
    def __init__(self):
        self.lines = []

    def write(self, value):
        self.lines.append(value)
        return len(value)

    def flush(self):
        pass

    def close(self):
        pass


class _Output:
    def __init__(self, source):
        self.source = source

    def readline(self, size=-1):
        request = json.loads(self.source.lines[-1])
        response = {
            "protocol": PROTOCOL,
            "request_id": request["request_id"],
            "alerts": [],
        }
        return json.dumps(response) + "\n"


class _Process:
    def __init__(self, command):
        self.command = command
        self.stdin = _Input()
        self.stdout = _Output(self.stdin)
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


def _fake_runtime(monkeypatch):
    processes = []
    monkeypatch.setattr(boundary_container.shutil, "which", lambda value: f"/usr/bin/{value}")
    monkeypatch.setattr(
        boundary_container.subprocess,
        "run",
        lambda *args, **kwargs: boundary_container.subprocess.CompletedProcess(
            args[0], 0, stdout=IMAGE_ID + "\n", stderr=""
        ),
    )

    def launch(command, **kwargs):
        process = _Process(command)
        processes.append(process)
        return process

    monkeypatch.setattr(boundary_container.subprocess, "Popen", launch)
    return processes


def test_container_request_is_minimized_and_runtime_is_hardened(monkeypatch):
    processes = _fake_runtime(monkeypatch)
    monitor = BoundaryContainerMonitor(PINNED, memory="128m", cpus=0.5)
    report = run_boundary_evaluation(
        monitor=monitor,
        monitor_id="oci-test-monitor",
        monitor_artifact_sha256=monitor.artifact_sha256,
    )
    monitor.close()

    request = json.loads(processes[0].stdin.lines[0])
    assert set(request) == {"protocol", "request_id", "policy", "events"}
    serialized = processes[0].stdin.lines[0].lower()
    for forbidden in ("scenario_id", "expected", "description", "ground_truth", "acceptance"):
        assert forbidden not in serialized
    command = processes[0].command
    for pair in (
        ("--pull", "never"),
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges:true"),
        ("--user", "65532:65532"),
        ("--memory", "128m"),
        ("--cpus", "0.5"),
    ):
        index = command.index(pair[0])
        assert tuple(command[index : index + 2]) == pair
    assert "--read-only" in command
    assert "--volume" not in command
    assert "--env" not in command
    assert report["monitor"]["artifact_sha256"] == "a" * 64
    assert report["summary"]["verdict"] == "fail"


def test_container_response_and_image_contract_fail_closed(monkeypatch):
    _fake_runtime(monkeypatch)
    with pytest.raises(ValueError, match="must be pinned"):
        BoundaryContainerMonitor("monitor:latest")
    monitor = BoundaryContainerMonitor("monitor:latest", allow_mutable_image=True)
    request_id = "request-00000001"
    assert (
        BoundaryContainerMonitor._parse_response(
            json.dumps({"protocol": PROTOCOL, "request_id": request_id, "alerts": []}) + "\n",
            request_id,
        )
        == []
    )
    with pytest.raises(ValueError, match="allowlist"):
        BoundaryContainerMonitor._parse_response(
            json.dumps(
                {
                    "protocol": PROTOCOL,
                    "request_id": request_id,
                    "alerts": [],
                    "explanation": "untrusted prose",
                }
            )
            + "\n",
            request_id,
        )
    with pytest.raises(ValueError, match="duplicate JSON"):
        BoundaryContainerMonitor._parse_response(
            '{"protocol":"lureboundary-monitor-v1","request_id":"request-00000001",'
            '"alerts":[],"alerts":[]}\n',
            request_id,
        )
    with pytest.raises(ValueError, match="newline-terminated"):
        BoundaryContainerMonitor._parse_response(
            json.dumps({"protocol": PROTOCOL, "request_id": request_id, "alerts": []}),
            request_id,
        )
    monitor.close()


def test_container_cli_emits_schema_valid_isolation_evidence(monkeypatch, tmp_path):
    _fake_runtime(monkeypatch)
    evaluation = tmp_path / "evaluation.json"
    conformance = tmp_path / "container.json"
    assert (
        main(
            [
                "boundary-eval",
                "--image",
                PINNED,
                "--out",
                str(evaluation),
                "--container-report",
                str(conformance),
            ]
        )
        == 1
    )
    report = json.loads(conformance.read_text(encoding="utf-8"))
    schema = json.loads(Path("spec/agent-boundary-container-evaluation-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    assert report["privacy"] == {
        "ground_truth_transmitted": False,
        "scenario_identifiers_transmitted": False,
        "scenario_prose_transmitted": False,
        "acceptance_thresholds_transmitted": False,
    }
