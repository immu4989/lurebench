from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from lurebench.cli import main
from lurebench.mandate_conformance import evaluate_mandate_conformance
from lurebench.mandate_gateway import (
    load_mandate_gateway_adapter,
    run_mandate_gateway,
    run_mandate_gateway_to_file,
)

VECTOR = Path(__file__).parents[1] / "conformance/luremandate-transitions-v1"
KWARGS = {
    "submission_id": "adapter-submission",
    "engine_id": "test-gateway",
    "engine_version": "1.0.0",
    "submitted_at": "2026-09-06T04:01:00Z",
}


def challenge():
    return json.loads((VECTOR / "challenge.json").read_text())


class RecordingAdapter:
    def __init__(self, fail_at=None, malformed=False):
        self.calls = []
        self.fail_at = fail_at
        self.malformed = malformed

    def begin(self, plan, execution):
        self.calls.append("begin")
        assert execution["state_model"] == "single_session_ordered_no_reset"
        plan.clear()
        if self.fail_at == "begin":
            raise RuntimeError("transport credential must not appear in CLI errors")

    def decide(self, case):
        self.calls.append(case["sequence"])
        assert set(case) == {"case_id", "sequence", "transaction"}
        assert "decision" not in case["transaction"]
        if case["sequence"] == self.fail_at:
            raise RuntimeError("transport credential must not appear in CLI errors")
        case["transaction"]["intent"].clear()
        if self.malformed:
            return {"decision": "block", "reason_code": "policy_unknown", "unexpected": 1}
        return {"decision": "block", "reason_code": "policy_unknown"}

    def close(self):
        self.calls.append("close")
        if self.fail_at == "close":
            raise RuntimeError("transport credential must not appear in CLI errors")


def test_one_ordered_session_preserves_input_and_requires_separate_scoring():
    value = challenge()
    original = copy.deepcopy(value)
    adapter = RecordingAdapter()
    result = run_mandate_gateway(value, adapter, **KWARGS)
    assert value == original
    assert adapter.calls == ["begin", *range(1, 42), "close"]
    assert len(result["results"]) == 41
    score = evaluate_mandate_conformance(value, result, evaluated_at="2026-09-06T04:02:00Z")
    assert score["summary"]["verdict"] == "fail"
    assert score["summary"]["collateral_denial_count"] > 0


@pytest.mark.parametrize("fail_at", ["begin", 3, "close"])
def test_failure_closes_session_once_without_retry_or_output(monkeypatch, tmp_path, fail_at):
    adapter = RecordingAdapter(fail_at=fail_at)
    monkeypatch.setattr("lurebench.mandate_gateway.load_mandate_gateway_adapter", lambda _: adapter)
    output = tmp_path / "submission.json"
    with pytest.raises(RuntimeError):
        run_mandate_gateway_to_file(challenge(), "unused:factory", output, **KWARGS)
    assert adapter.calls.count("close") == 1
    assert not output.exists()
    if fail_at == 3:
        assert adapter.calls == ["begin", 1, 2, 3, "close"]


def test_malformed_response_fails_before_next_case():
    adapter = RecordingAdapter(malformed=True)
    with pytest.raises(ValueError):
        run_mandate_gateway(challenge(), adapter, **KWARGS)
    assert adapter.calls == ["begin", 1, "close"]


def test_bad_metadata_does_not_start_session():
    adapter = RecordingAdapter()
    with pytest.raises(ValueError):
        run_mandate_gateway(challenge(), adapter, **{**KWARGS, "engine_id": "invalid ID"})
    assert adapter.calls == []


@pytest.mark.parametrize(
    "metadata",
    [{"engine_id": "invalid ID"}, {"submitted_at": ""}, {"unexpected": True}],
)
def test_bad_metadata_is_rejected_before_adapter_import(monkeypatch, tmp_path, metadata):
    def unexpected_import(_):
        pytest.fail("adapter code must not run for invalid metadata")

    monkeypatch.setattr(
        "lurebench.mandate_gateway.load_mandate_gateway_adapter", unexpected_import
    )
    with pytest.raises((ValueError, TypeError)):
        run_mandate_gateway_to_file(
            challenge(), "unused:factory", tmp_path / "out.json", **{**KWARGS, **metadata}
        )
    assert not (tmp_path / "out.json").exists()


def test_async_adapter_is_rejected_before_session_start():
    class AsyncAdapter(RecordingAdapter):
        async def decide(self, case):
            return {"decision": "block", "reason_code": "policy_unknown"}

    adapter = AsyncAdapter()
    with pytest.raises(ValueError, match="synchronous"):
        run_mandate_gateway(challenge(), adapter, **KWARGS)
    assert adapter.calls == []


def test_async_callable_object_is_rejected_before_session_start():
    class AsyncCallable:
        async def __call__(self, *args):
            return None

    adapter = RecordingAdapter()
    adapter.begin = AsyncCallable()
    with pytest.raises(ValueError, match="synchronous"):
        run_mandate_gateway(challenge(), adapter, **KWARGS)
    assert adapter.calls == []


@pytest.mark.parametrize("hook", ["begin", "decide", "close"])
def test_hidden_coroutine_return_cannot_create_a_submission(hook):
    async def asynchronous_result():
        return None

    returned = []
    adapter = RecordingAdapter()

    def unexpected_async(*args):
        adapter.calls.append(hook)
        result = asynchronous_result()
        returned.append(result)
        return result

    setattr(adapter, hook, unexpected_async)
    with pytest.raises(ValueError, match="asynchronous result"):
        run_mandate_gateway(challenge(), adapter, **KWARGS)
    assert adapter.calls.count("close") == 1
    assert all(result.cr_frame is None for result in returned)


@pytest.mark.parametrize("hook", ["begin", "close"])
def test_lifecycle_hook_return_values_are_not_ignored(hook):
    adapter = RecordingAdapter()

    def unexpected_value(*args):
        adapter.calls.append(hook)
        return {"error": "session unavailable"}

    setattr(adapter, hook, unexpected_value)
    with pytest.raises(ValueError, match=f"{hook} must return None"):
        run_mandate_gateway(challenge(), adapter, **KWARGS)
    assert adapter.calls.count("close") == 1


def test_generator_hook_is_rejected_before_session_start():
    def generator(*args):
        yield None

    adapter = RecordingAdapter()
    adapter.begin = generator
    with pytest.raises(ValueError, match="synchronous"):
        run_mandate_gateway(challenge(), adapter, **KWARGS)
    assert adapter.calls == []


def test_existing_output_is_checked_before_adapter_import(tmp_path):
    output = tmp_path / "existing.json"
    output.write_text("keep")
    with pytest.raises(FileExistsError):
        run_mandate_gateway_to_file(challenge(), "nonexistent:factory", output, **KWARGS)
    assert output.read_text() == "keep"


@pytest.mark.parametrize("specification", ["bad;command", "module:factory()", ":name", "a:b:c"])
def test_factory_specification_is_not_shell_or_expression(specification):
    with pytest.raises(ValueError, match="module:factory"):
        load_mandate_gateway_adapter(specification)


def test_example_cli_exports_private_submission(tmp_path, capsys):
    output = tmp_path / "example.json"
    assert (
        main(
            [
                "mandate-run-gateway",
                str(VECTOR / "challenge.json"),
                "--adapter",
                "lurebench.mandate_gateway_example:create_adapter",
                "--submission-id",
                "example-submission",
                "--engine-id",
                "example-always-block",
                "--engine-version",
                "1.0.0",
                "--submitted-at",
                "2026-09-06T04:01:00Z",
                "--out",
                str(output),
            ]
        )
        == 0
    )
    assert "does not imply a pass" in capsys.readouterr().out
    assert output.stat().st_mode & 0o777 == 0o600
    result = json.loads(output.read_text())
    assert len(result["results"]) == 41


def test_cli_redacts_adapter_exception_text(monkeypatch, tmp_path, capsys):
    adapter = RecordingAdapter(fail_at=1)
    monkeypatch.setattr("lurebench.mandate_gateway.load_mandate_gateway_adapter", lambda _: adapter)
    assert (
        main(
            [
                "mandate-run-gateway",
                str(VECTOR / "challenge.json"),
                "--adapter",
                "unused:factory",
                "--submission-id",
                "test",
                "--engine-id",
                "test",
                "--engine-version",
                "1",
                "--out",
                str(tmp_path / "out.json"),
            ]
        )
        == 2
    )
    output = capsys.readouterr()
    assert "RuntimeError" in output.err
    assert "transport credential" not in output.err
