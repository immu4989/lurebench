"""Security and interoperability tests for the isolated detector protocol."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from lurebench.cli import main
from lurebench.detectors import container
from lurebench.detectors.container import PROTOCOL, ContainerDetector
from lurebench.schema import Lure

IMAGE_ID = "sha256:" + "a" * 64
PINNED_IMAGE = "example.invalid/lure-detector@sha256:" + "b" * 64
SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples" / "lures.jsonl"


class _RecordingInput:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.closed = False

    def write(self, value: str) -> int:
        self.lines.append(value)
        return len(value)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _ProtocolOutput:
    def __init__(self, source: _RecordingInput, score: float | None = 0.75) -> None:
        self.source = source
        self.score = score

    def readline(self) -> str:
        request = json.loads(self.source.lines[-1])
        response = {
            "protocol": PROTOCOL,
            "request_id": request["request_id"],
            "score": self.score,
        }
        if self.score is None:
            response["abstain"] = True
        return json.dumps(response) + "\n"


class _FakeProcess:
    def __init__(self, command: list[str], score: float | None = 0.75) -> None:
        self.command = command
        self.stdin = _RecordingInput()
        self.stdout = _ProtocolOutput(self.stdin, score)
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


def _install_fake_runtime(monkeypatch, *, score: float | None = 0.75):
    processes: list[_FakeProcess] = []
    monkeypatch.setattr(container.shutil, "which", lambda runtime: f"/usr/bin/{runtime}")

    def inspect(*args, **kwargs):
        return container.subprocess.CompletedProcess(args[0], 0, stdout=IMAGE_ID + "\n", stderr="")

    def launch(command, **kwargs):
        process = _FakeProcess(command, score)
        processes.append(process)
        return process

    monkeypatch.setattr(container.subprocess, "run", inspect)
    monkeypatch.setattr(container.subprocess, "Popen", launch)
    return processes


def _sensitive_lure() -> Lure:
    return Lure(
        id="secret-record-id",
        text="Please review the attached wire instructions.",
        label=1,
        source="ai",
        typology="bec",
        generator="private-model",
        language="en",
        channel="email",
        persuasion=["authority"],
        meta={"case_id": "CASE-123", "sender": "chief@example.invalid"},
    )


def test_container_receives_only_protocol_allowlist(monkeypatch):
    processes = _install_fake_runtime(monkeypatch)
    detector = ContainerDetector(PINNED_IMAGE)

    assert detector.score(_sensitive_lure()) == pytest.approx(0.75)
    request = json.loads(processes[0].stdin.lines[0])
    assert set(request) == {"protocol", "request_id", "task", "text", "language", "channel"}
    assert request["request_id"] == "request-00000001"
    assert request["protocol"] == PROTOCOL
    assert "secret-record-id" not in processes[0].stdin.lines[0]
    assert "private-model" not in processes[0].stdin.lines[0]
    assert "CASE-123" not in processes[0].stdin.lines[0]


def test_container_runtime_is_hardened_and_never_pulls(monkeypatch):
    processes = _install_fake_runtime(monkeypatch)
    detector = ContainerDetector(PINNED_IMAGE, memory="256m", cpus=0.5)
    detector.score(_sensitive_lure())

    command = processes[0].command
    assert command[:3] == ["docker", "run", "--rm"]
    for expected in (
        ["--pull", "never"],
        ["--network", "none"],
        ["--cap-drop", "ALL"],
        ["--security-opt", "no-new-privileges:true"],
        ["--memory", "256m"],
        ["--cpus", "0.5"],
    ):
        position = command.index(expected[0])
        assert command[position : position + 2] == expected
    assert "--read-only" in command
    assert PINNED_IMAGE == command[-1]
    assert "--volume" not in command
    assert "--env" not in command


def test_mutable_image_requires_explicit_development_override(monkeypatch):
    _install_fake_runtime(monkeypatch)
    with pytest.raises(ValueError, match="must be pinned"):
        ContainerDetector("local-detector:latest")
    detector = ContainerDetector("local-detector:latest", allow_mutable_image=True)
    assert detector.image_id == IMAGE_ID


def test_response_allowlist_and_abstention_are_strict():
    request_id = "request-00000001"
    abstention = json.dumps(
        {"protocol": PROTOCOL, "request_id": request_id, "score": None, "abstain": True}
    )
    assert ContainerDetector._parse_response(abstention, request_id) is None

    with pytest.raises(ValueError, match="allowlist"):
        ContainerDetector._parse_response(
            json.dumps(
                {
                    "protocol": PROTOCOL,
                    "request_id": request_id,
                    "score": 0.5,
                    "explanation": "untrusted extra data",
                }
            ),
            request_id,
        )
    with pytest.raises(ValueError, match="between zero and one"):
        ContainerDetector._parse_response(
            json.dumps({"protocol": PROTOCOL, "request_id": request_id, "score": 1.1}),
            request_id,
        )


def test_container_cli_report_validates_against_published_schema(monkeypatch, tmp_path):
    _install_fake_runtime(monkeypatch)
    output = tmp_path / "evaluation.json"

    result = main(
        [
            "container-eval",
            "--dataset",
            str(SAMPLES),
            "--image",
            PINNED_IMAGE,
            "--out",
            str(output),
        ]
    )

    assert result == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    schema = json.loads(
        Path("spec/container-evaluation-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    assert report["image_id"] == IMAGE_ID
    assert report["dataset"]["record_count"] == 16
    assert report["dataset"]["ground_truth_transmitted"] is False
    assert report["dataset"]["original_record_ids_transmitted"] is False
