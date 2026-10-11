"""Bounded sequential JSONL exchanges with a local runtime subprocess.

This controls the runtime CLI's pipes and lifetime, not the OCI daemon or kernel.
Process creation and serialization remain outside the exchange deadline.
"""

from __future__ import annotations

import queue
import subprocess
import threading
import time


class JsonLineSession:
    """One process, one outstanding exchange, no reuse after a failed exchange."""

    def __init__(self, process: subprocess.Popen[str], *, label: str):
        self.process = process
        self.label = label
        self._closed = False
        self._worker: threading.Thread | None = None
        self._busy = threading.Lock()

    def exchange(self, request: str, *, timeout: float, max_chars: int) -> str:
        if not self._busy.acquire(blocking=False):
            raise RuntimeError(f"{self.label} already has an outstanding exchange")
        try:
            if self._closed:
                raise RuntimeError(f"{self.label} session is closed")
            process = self.process
            if process.stdin is None or process.stdout is None:
                raise RuntimeError(f"{self.label} requires stdin and stdout pipes")
            output: queue.Queue[object] = queue.Queue(maxsize=1)
            deadline = time.monotonic() + timeout

            def transfer() -> None:
                try:
                    process.stdin.write(request)
                    process.stdin.flush()
                    output.put(process.stdout.readline(max_chars))
                except Exception as exc:
                    output.put(exc)

            self._worker = threading.Thread(target=transfer, daemon=True)
            self._worker.start()
            try:
                value = output.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty as exc:
                self._closed = True
                raise TimeoutError(f"{self.label} exceeded its request/response timeout") from exc
            if isinstance(value, Exception):
                self._closed = True
                raise RuntimeError(f"{self.label} pipe exchange failed") from value
            if not isinstance(value, str):
                self._closed = True
                raise RuntimeError(f"{self.label} returned non-text pipe output")
            return value
        finally:
            self._busy.release()

    def close(self) -> None:
        """Stop the CLI before flushing/closing streams; bound each wait.

        A descendant retaining a pipe can outlive the CLI. If the worker remains
        blocked after termination, do not block again on that pipe's I/O lock.
        Keep the session closed and surface incomplete cleanup to the caller.
        """
        self._closed = True
        process = self.process
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass  # Exited between poll and terminate.
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"{self.label} runtime process could not be reaped") from exc
        if self._worker is not None:
            self._worker.join(timeout=1)
            if self._worker.is_alive():
                raise RuntimeError(f"{self.label} pipe cleanup incomplete; external cleanup required")
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass  # A stopped peer can make an otherwise-complete close fail.
