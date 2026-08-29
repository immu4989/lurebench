"""Hardened OCI transport for language-independent LureBoundary monitors.

The process receives only the already-minimized event vocabulary and policy.
Scenario prose, identifiers, expectations, labels, and benchmark thresholds stay
inside the evaluator.  Images are never pulled implicitly and production use
requires an immutable digest reference.
"""

from __future__ import annotations

import json
import math
import queue
import re
import shutil
import subprocess
import threading
from typing import Any, Mapping, Optional, Sequence

from .receipts import loads_strict_json

PROTOCOL = "lureboundary-monitor-v1"
MAX_RESPONSE_BYTES = 256 * 1024
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,499}$")
_DIGEST_IMAGE = re.compile(r"^.+@sha256:[a-f0-9]{64}$")
_MEMORY = re.compile(r"^[1-9][0-9]{0,5}[kKmMgG]$")
_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")


class BoundaryContainerMonitor:
    """Stream minimized trajectories to one locally available OCI image."""

    def __init__(
        self,
        image: str,
        *,
        runtime: str = "docker",
        timeout_seconds: float = 10.0,
        memory: str = "256m",
        cpus: float = 1.0,
        allow_mutable_image: bool = False,
    ) -> None:
        if runtime not in {"docker", "podman"}:
            raise ValueError("runtime must be docker or podman")
        if shutil.which(runtime) is None:
            raise RuntimeError(f"{runtime} executable was not found")
        if not isinstance(image, str) or _IMAGE.fullmatch(image) is None:
            raise ValueError("monitor image reference contains unsupported characters")
        if not allow_mutable_image and _DIGEST_IMAGE.fullmatch(image) is None:
            raise ValueError(
                "monitor image must be pinned as name@sha256:<64 hex>; "
                "use allow_mutable_image only for local development"
            )
        if not math.isfinite(timeout_seconds) or not 0.1 <= timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be between 0.1 and 300")
        if not isinstance(memory, str) or _MEMORY.fullmatch(memory) is None:
            raise ValueError("memory must look like 256m or 1g")
        if not math.isfinite(cpus) or not 0.1 <= cpus <= 32:
            raise ValueError("cpus must be between 0.1 and 32")

        self.image = image
        self.runtime = runtime
        self.timeout_seconds = float(timeout_seconds)
        self.memory = memory.lower()
        self.cpus = float(cpus)
        self.allow_mutable_image = bool(allow_mutable_image)
        self.image_id = self._inspect_image()
        self._process: Optional[subprocess.Popen[str]] = None
        self._counter = 0

    @property
    def artifact_sha256(self) -> str:
        return self.image_id.removeprefix("sha256:")

    def _inspect_image(self) -> str:
        try:
            result = subprocess.run(
                [self.runtime, "image", "inspect", "--format", "{{.Id}}", self.image],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(
                "monitor image is not available locally; LureBench never pulls it implicitly"
            ) from exc
        image_id = result.stdout.strip()
        if _IMAGE_ID.fullmatch(image_id) is None:
            raise RuntimeError("container runtime returned an invalid immutable image id")
        return image_id

    def _start(self) -> subprocess.Popen[str]:
        command = [
            self.runtime,
            "run",
            "--rm",
            "--interactive",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "65532:65532",
            "--pids-limit",
            "64",
            "--memory",
            self.memory,
            "--cpus",
            f"{self.cpus:g}",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            self.image,
        ]
        try:
            return subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="strict",
                bufsize=1,
            )
        except OSError as exc:
            raise RuntimeError("failed to start the boundary monitor container") from exc

    def _readline(self) -> str:
        assert self._process is not None and self._process.stdout is not None
        output: queue.Queue[object] = queue.Queue(maxsize=1)

        def read() -> None:
            try:
                output.put(self._process.stdout.readline(MAX_RESPONSE_BYTES + 2))
            except Exception as exc:  # reader failures stay inside the bounded queue
                output.put(exc)

        threading.Thread(target=read, daemon=True).start()
        try:
            value = output.get(timeout=self.timeout_seconds)
        except queue.Empty as exc:
            self.close()
            raise TimeoutError(
                "boundary monitor exceeded its per-trajectory response timeout"
            ) from exc
        if isinstance(value, Exception):
            self.close()
            raise RuntimeError("boundary monitor produced invalid UTF-8 output") from value
        return str(value)

    @staticmethod
    def _parse_response(raw: str, request_id: str) -> Sequence[Mapping[str, Any]]:
        encoded = raw.encode("utf-8")
        if not raw or len(encoded) > MAX_RESPONSE_BYTES:
            raise ValueError("boundary monitor returned an empty or oversized response")
        if not raw.endswith("\n"):
            raise ValueError("boundary monitor response must be one newline-terminated JSON record")
        response = loads_strict_json(encoded)
        if not isinstance(response, dict):
            raise ValueError("boundary monitor response must be a JSON object")
        if set(response) != {"protocol", "request_id", "alerts"}:
            raise ValueError("boundary monitor response violates the protocol allowlist")
        if response["protocol"] != PROTOCOL or response["request_id"] != request_id:
            raise ValueError("boundary monitor response does not match the request")
        alerts = response["alerts"]
        if not isinstance(alerts, list):
            raise ValueError("boundary monitor alerts must be an array")
        return alerts

    def __call__(
        self, trajectory: Mapping[str, Any], policy: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        if self._process is None:
            self._process = self._start()
        if self._process.poll() is not None:
            self.close()
            raise RuntimeError("boundary monitor exited before evaluation completed")
        assert self._process.stdin is not None
        self._counter += 1
        request_id = f"request-{self._counter:08d}"
        request = {
            "protocol": PROTOCOL,
            "request_id": request_id,
            "policy": policy,
            "events": trajectory["events"],
        }
        try:
            self._process.stdin.write(
                json.dumps(
                    request,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            )
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self.close()
            raise RuntimeError("boundary monitor closed its input stream") from exc
        try:
            return self._parse_response(self._readline(), request_id)
        except Exception:
            self.close()
            raise

    def isolation_claims(self) -> dict[str, Any]:
        """Return the exact evaluator-controlled OCI restrictions for evidence."""

        return {
            "network": "none",
            "read_only_root": True,
            "capabilities_dropped": "ALL",
            "no_new_privileges": True,
            "user": "65532:65532",
            "host_mounts": False,
            "pids_limit": 64,
            "memory": self.memory,
            "cpus": self.cpus,
            "implicit_pull": False,
        }

    def close(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def __enter__(self) -> "BoundaryContainerMonitor":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
