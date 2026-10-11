"""Security and interoperability tests for the isolated detector protocol."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from lurebench.cli import main
from lurebench.detectors import container
from lurebench.detectors.container import MAX_RESPONSE_BYTES, PROTOCOL, ContainerDetector
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

    def close(self):
        pass

    def readline(self, size=-1) -> str:
        request = json.loads(self.source.lines[-1])
        response = {
            "protocol": PROTOCOL,
            "request_id": request["request_id"],
            "score": self.score,
        }
        if self.score is None:
            response["abstain"] = True
        line = json.dumps(response) + "\n"
        return line if size < 0 else line[:size]


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
    ) + "\n"
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
            ) + "\n",
            request_id,
        )
    with pytest.raises(ValueError, match="between zero and one"):
        ContainerDetector._parse_response(
            json.dumps({"protocol": PROTOCOL, "request_id": request_id, "score": 1.1}) + "\n",
            request_id,
        )


@pytest.mark.parametrize("fields", [
    '"score":0.95,"score":0.05',
    '"score":0.95,"sc\\u006fre":0.05',
    '"score":null,"abstain":false,"abstain":true',
    '"protocol":"lurebench-detector-v1","score":0.5',
    '"request_id":"request-00000001","score":0.5',
    '"score":NaN',
    '"score":Infinity',
    '"score":-Infinity',
    '"score":1e999',
    '"score":' + '[' * 129 + '0' + ']' * 129,
])
def test_response_rejects_ambiguous_or_nonstandard_json(fields):
    raw = ('{"protocol":"lurebench-detector-v1","request_id":"request-00000001",'
           + fields + '}\n')
    with pytest.raises(ValueError, match="strict JSON"):
        ContainerDetector._parse_response(raw, "request-00000001")


@pytest.mark.parametrize("score", [True, None, "0.5", [], {}, 10**400, -10**400])
def test_response_rejects_invalid_score_types_and_huge_integers(score):
    raw = json.dumps({"protocol": PROTOCOL, "request_id": "r", "score": score}) + "\n"
    with pytest.raises(ValueError, match="numeric|between zero and one"):
        ContainerDetector._parse_response(raw, "r")


@pytest.mark.parametrize("ending", ["", "\r", "\n\n"])
def test_response_requires_one_terminated_record(ending):
    raw = json.dumps({"protocol": PROTOCOL, "request_id": "r", "score": 0.5}) + ending
    with pytest.raises(ValueError, match="newline-terminated"):
        ContainerDetector._parse_response(raw, "r")


def test_response_limit_is_exact_utf8_bytes_including_newline():
    raw = json.dumps({"protocol": PROTOCOL, "request_id": "é", "score": 0.5}, ensure_ascii=False)
    padded = raw + ' ' * (MAX_RESPONSE_BYTES - len(raw.encode()) - 1) + '\n'
    assert ContainerDetector._parse_response(padded, "é") == 0.5
    with pytest.raises(ValueError, match="oversized"):
        ContainerDetector._parse_response(' ' + padded, "é")


def test_reader_bounds_consumption_before_oversize_validation(monkeypatch):
    _install_fake_runtime(monkeypatch)
    detector = ContainerDetector(PINNED_IMAGE)
    process = _FakeProcess([])
    class TrackedOutput(io.StringIO):
        def close(self):
            self.final_position = self.tell()
            super().close()

    process.stdout = TrackedOutput("x" * (4 * MAX_RESPONSE_BYTES))
    detector._process = process
    try:
        with pytest.raises(ValueError, match="oversized"):
            detector.score(_sensitive_lure())
        assert process.stdout.final_position == MAX_RESPONSE_BYTES + 1
        assert detector._process is None
        assert process.stdin.closed
    finally:
        detector.close()


def test_unterminated_live_pipe_is_bounded_without_waiting_for_eof(monkeypatch):
    # A real local pipe, not Docker: the writer stays alive after emitting a line
    # beyond the cap. An unbounded readline would hit the response timeout.
    monkeypatch.setattr(container.shutil, "which", lambda runtime: f"/usr/bin/{runtime}")
    monkeypatch.setattr(ContainerDetector, "_inspect_image", lambda self: IMAGE_ID)
    detector = ContainerDetector(PINNED_IMAGE, timeout_seconds=3)
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys,time; sys.stdout.write('x'*65537); "
         "sys.stdout.flush(); time.sleep(15)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="strict",
    )
    detector._process = process
    try:
        with pytest.raises(ValueError, match="oversized"):
            detector.score(_sensitive_lure())
        assert process.poll() is not None
        assert detector._process is None
    finally:
        detector.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        process.stdout.close()


def test_protocol_failure_is_not_an_abstention_or_a_published_report(monkeypatch, tmp_path, capsys):
    processes = _install_fake_runtime(monkeypatch)

    def ambiguous(self, size=-1):
        request = json.loads(self.source.lines[-1])
        return ('{"protocol":"lurebench-detector-v1","request_id":'
                + json.dumps(request["request_id"]) + ',"score":0.95,"score":0.05}\n')

    monkeypatch.setattr(_ProtocolOutput, "readline", ambiguous)
    output = tmp_path / "must-not-exist.json"
    assert main(["container-eval", "--dataset", str(SAMPLES), "--image", PINNED_IMAGE,
                 "--out", str(output)]) == 1
    assert "strict JSON" in capsys.readouterr().err
    assert not output.exists()
    assert processes[0].stdin.closed


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


def test_cli_does_not_publish_report_when_cleanup_fails(monkeypatch, tmp_path, capsys):
    processes = _install_fake_runtime(monkeypatch)
    original = ContainerDetector.close

    def cleanup_failure(self):
        original(self)
        raise RuntimeError("synthetic incomplete cleanup")

    monkeypatch.setattr(ContainerDetector, "close", cleanup_failure)
    output = tmp_path / "evaluation.json"
    assert main(["container-eval", "--dataset", str(SAMPLES), "--image", PINNED_IMAGE,
                 "--out", str(output)]) == 1
    assert not output.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "incomplete cleanup" in captured.err
    assert processes[0].stdin.closed
