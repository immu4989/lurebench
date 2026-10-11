"""Real pipe regressions for both OCI adapters, without Docker or image pulls."""

import io
import os
import subprocess
import sys
import threading
import time

import pytest

from lurebench import container_io
from lurebench.boundary_container import BoundaryContainerMonitor
from lurebench.container_io import JsonLineSession
from lurebench.detectors.container import ContainerDetector
from lurebench.schema import Lure


def child(code):
    return subprocess.Popen(
        [sys.executable, "-u", "-c", code], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="strict",
    )


def reap(process):
    if process.poll() is None:
        process.kill()
        process.wait(timeout=2)
    for stream in (process.stdin, process.stdout):
        try:
            stream.close()
        except OSError:
            pass


def adapter(monkeypatch, kind, process, timeout=.2):
    cls = ContainerDetector if kind == "detector" else BoundaryContainerMonitor
    monkeypatch.setattr("shutil.which", lambda name: "/unused/runtime")
    monkeypatch.setattr(cls, "_inspect_image", lambda self: "sha256:" + "a" * 64)
    instance = cls("example.invalid/local@sha256:" + "b" * 64, timeout_seconds=timeout)
    instance._process = process
    return instance


def call(instance, text="Notes"):
    if isinstance(instance, ContainerDetector):
        return instance.score(Lure(id="private-id", text=text, label=0,
                                   source="human", typology="benign"))
    return instance({"events": [{"action": text}]}, {})


@pytest.mark.parametrize("kind", ["detector", "boundary"])
@pytest.mark.parametrize("text", ["Notes", "x" * 1_048_576], ids=["read-stall", "write-stall"])
def test_request_deadline_covers_reads_and_blocked_writes(monkeypatch, kind, text):
    process = child("import time; time.sleep(5)")
    instance = adapter(monkeypatch, kind, process)
    start = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="request/response timeout"):
            call(instance, text)
        assert time.monotonic() - start < 3
        assert process.poll() is not None
        assert process.stdin.closed and process.stdout.closed
        assert instance._process is None
        with pytest.raises(RuntimeError, match="new .* for a new run"):
            call(instance)
    finally:
        reap(process)


@pytest.mark.parametrize("kind", ["detector", "boundary"])
def test_valid_sequential_roundtrips_reuse_one_process(monkeypatch, kind):
    process = child(
        "import sys,json\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line)\n"
        " assert 'private-id' not in line\n"
        " value={'score':0.25} if r['protocol']=='lurebench-detector-v1' else {'alerts':[]}\n"
        " print(json.dumps(dict(protocol=r['protocol'],request_id=r['request_id'],**value)),flush=True)\n"
    )
    instance = adapter(monkeypatch, kind, process, timeout=2)
    try:
        for _ in range(3):
            assert call(instance) == (.25 if kind == "detector" else [])
        assert instance._counter == 3
        assert instance._process is process
        instance.close()
        instance.close()
        assert process.poll() is not None
        assert process.stdin.closed and process.stdout.closed
    finally:
        reap(process)


@pytest.mark.parametrize("kind", ["detector", "boundary"])
def test_invalid_utf8_is_terminal_and_closes_pipes(monkeypatch, kind):
    process = child("import sys,time; sys.stdout.buffer.write(b'\\xff\\n'); "
                    "sys.stdout.flush(); time.sleep(5)")
    instance = adapter(monkeypatch, kind, process, timeout=2)
    try:
        with pytest.raises(RuntimeError, match="pipe exchange failed") as error:
            call(instance)
        assert isinstance(error.value.__cause__, UnicodeDecodeError)
        assert process.poll() is not None
        assert process.stdin.closed and process.stdout.closed
        with pytest.raises(RuntimeError, match="new .* for a new run"):
            call(instance)
    finally:
        reap(process)


@pytest.mark.parametrize("kind", ["detector", "boundary"])
def test_keyboard_interrupt_still_cleans_up(monkeypatch, kind):
    process = child("import time; time.sleep(5)")
    instance = adapter(monkeypatch, kind, process)

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(container_io.queue.Queue, "get", interrupt)
    try:
        with pytest.raises(KeyboardInterrupt):
            call(instance)
        assert process.poll() is not None
        assert process.stdin.closed and process.stdout.closed
    finally:
        reap(process)


@pytest.mark.skipif(os.name == "nt", reason="POSIX SIGTERM escalation test")
def test_cleanup_escalates_to_kill_when_child_ignores_termination():
    process = child("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                    "print('ready',flush=True); time.sleep(5)")
    try:
        assert process.stdout.readline() == "ready\n"
        session = JsonLineSession(process, label="local test")
        start = time.monotonic()
        session.close()
        assert time.monotonic() - start < 3
        assert process.returncode == -9
        assert process.stdin.closed and process.stdout.closed
    finally:
        reap(process)


class FakeProcess:
    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin if stdin is not None else io.StringIO()
        self.stdout = stdout if stdout is not None else io.StringIO("response\n")
        self.returncode = None
        self.events = []

    def poll(self):
        return self.returncode

    def terminate(self):
        self.events.append("terminate")

    def kill(self):
        self.events.append("kill")

    def wait(self, timeout):
        self.events.append(("wait", timeout))
        self.returncode = 0
        return 0


def test_one_deadline_is_shared_by_write_flush_and_read():
    class SlowInput(io.StringIO):
        def write(self, value):
            time.sleep(.15)
            return super().write(value)

        def flush(self):
            time.sleep(.15)

    process = FakeProcess(stdin=SlowInput())
    session = JsonLineSession(process, label="local test")
    try:
        with pytest.raises(TimeoutError):
            session.exchange("request\n", timeout=.2, max_chars=100)
    finally:
        session.close()


def test_unreaped_process_keeps_streams_open_and_reports_cleanup_failure():
    class Unreaped(FakeProcess):
        def wait(self, timeout):
            self.events.append(("wait", timeout))
            raise subprocess.TimeoutExpired("local-test", timeout)

    process = Unreaped()
    session = JsonLineSession(process, label="local test")
    with pytest.raises(RuntimeError, match="could not be reaped"):
        session.close()
    assert process.events == ["terminate", ("wait", 1), "kill", ("wait", 1)]
    assert not process.stdin.closed and not process.stdout.closed
    with pytest.raises(RuntimeError, match="closed"):
        session.exchange("retry\n", timeout=1, max_chars=100)
    process.stdin.close()
    process.stdout.close()


def test_blocked_worker_never_causes_a_second_block_on_stream_close():
    release = threading.Event()

    class BlockedOutput(io.StringIO):
        def readline(self, size):
            release.wait(5)
            return "response\n"

    process = FakeProcess(stdout=BlockedOutput())
    session = JsonLineSession(process, label="local test")
    try:
        with pytest.raises(TimeoutError):
            session.exchange("request\n", timeout=.1, max_chars=100)
        with pytest.raises(RuntimeError, match="external cleanup required"):
            session.close()
        assert not process.stdin.closed and not process.stdout.closed
        with pytest.raises(RuntimeError, match="closed"):
            session.exchange("retry\n", timeout=1, max_chars=100)
    finally:
        release.set()
        session.close()
    assert process.stdin.closed and process.stdout.closed


def test_second_concurrent_exchange_is_rejected():
    entered, release = threading.Event(), threading.Event()

    class BlockedOutput(io.StringIO):
        def readline(self, size):
            entered.set()
            release.wait(5)
            return "response\n"

    process = FakeProcess(stdout=BlockedOutput())
    session = JsonLineSession(process, label="local test")
    results = []
    worker = threading.Thread(target=lambda: results.append(
        session.exchange("first\n", timeout=3, max_chars=100)))
    worker.start()
    try:
        assert entered.wait(1)
        with pytest.raises(RuntimeError, match="outstanding exchange"):
            session.exchange("second\n", timeout=1, max_chars=100)
    finally:
        release.set()
        worker.join(timeout=2)
        session.close()
    assert results == ["response\n"]


@pytest.mark.parametrize("trajectory", [{}, {"events": [float("nan")]}, {"events": [object()]}])
def test_request_preflight_does_not_start_a_runtime(monkeypatch, trajectory):
    instance = adapter(monkeypatch, "boundary", None)

    def forbidden():
        pytest.fail("malformed request must be rejected before runtime startup")

    monkeypatch.setattr(instance, "_start", forbidden)
    with pytest.raises((KeyError, ValueError, TypeError)):
        instance(trajectory, {})
    assert instance._counter == 0
    assert instance._process is None


@pytest.mark.parametrize("kind", ["detector", "boundary"])
def test_incomplete_cleanup_retains_handle_without_allowing_reuse(monkeypatch, kind):
    process = FakeProcess()
    instance = adapter(monkeypatch, kind, process)
    instance._session = JsonLineSession(process, label="local test")
    original_close = instance._session.close

    def incomplete():
        raise RuntimeError("external cleanup required")

    monkeypatch.setattr(instance._session, "close", incomplete)
    with pytest.raises(RuntimeError, match="external cleanup"):
        instance.close()
    assert instance._process is process
    with pytest.raises(RuntimeError, match="new .* for a new run"):
        call(instance)
    monkeypatch.setattr(instance._session, "close", original_close)
    instance.close()
    assert instance._process is None
    with pytest.raises(RuntimeError, match="new .* for a new run"):
        call(instance)


@pytest.mark.parametrize("kind", ["detector", "boundary"])
def test_invalid_protocol_cannot_restart_implicitly(monkeypatch, kind):
    process = child("import time; print('{}',flush=True); time.sleep(5)")
    instance = adapter(monkeypatch, kind, process, timeout=2)
    try:
        with pytest.raises(ValueError):
            call(instance)
        assert process.poll() is not None
        with pytest.raises(RuntimeError, match="new .* for a new run"):
            call(instance)
    finally:
        reap(process)
