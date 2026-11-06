"""Isolated JSONL protocol for proprietary or non-Python fraud detectors.

Only the text and declared language/channel cross the container boundary. Ground
truth, source provenance, typology, generator, persuasion tags, metadata, and the
original record id are deliberately withheld. The runtime receives no network,
host mounts, Linux capabilities, or writable root filesystem.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
from typing import Any, Dict, Optional

from ..container_image import inspect_local_image
from ..container_io import JsonLineSession
from ..container_lifecycle import (
    OwnedContainer,
    cleanup_after_failure,
    close_adapter,
    exclusive_operation,
)
from ..receipts import loads_strict_json
from ..schema import Lure
from .base import Detector

PROTOCOL = "lurebench-detector-v1"
MAX_RESPONSE_BYTES = 64 * 1024
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,499}$")
_DIGEST_IMAGE = re.compile(r"^.+@sha256:[a-f0-9]{64}$")
_MEMORY = re.compile(r"^[1-9][0-9]{0,5}[kKmMgG]$")


class ContainerDetector(Detector):
    """Stream benchmark records to one hardened local OCI container."""

    requires = ["Docker or Podman"]

    def __init__(
        self,
        image: str,
        *,
        task: str = "fraud",
        runtime: str = "docker",
        timeout_seconds: float = 10.0,
        memory: str = "512m",
        cpus: float = 1.0,
        allow_mutable_image: bool = False,
    ) -> None:
        if runtime not in {"docker", "podman"}:
            raise ValueError("runtime must be docker or podman")
        if shutil.which(runtime) is None:
            raise RuntimeError(f"{runtime} executable was not found")
        if not isinstance(image, str) or not _IMAGE.fullmatch(image):
            raise ValueError("container image reference contains unsupported characters")
        if not isinstance(allow_mutable_image, bool):
            raise ValueError("allow_mutable_image must be a boolean")
        if not allow_mutable_image and not _DIGEST_IMAGE.fullmatch(image):
            raise ValueError(
                "container image must be pinned as name@sha256:<64 hex>; "
                "use allow_mutable_image only for local development"
            )
        if task not in {"fraud", "provenance"}:
            raise ValueError("task must be fraud or provenance")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not 0.1 <= timeout_seconds <= 300):
            raise ValueError("timeout_seconds must be between 0.1 and 300")
        if not isinstance(memory, str) or not _MEMORY.fullmatch(memory):
            raise ValueError("memory must look like 512m or 1g")
        if isinstance(cpus, bool) or not isinstance(cpus, (int, float)) or not 0.1 <= cpus <= 32:
            raise ValueError("cpus must be between 0.1 and 32")

        self.image = image
        self.task = task
        self.runtime = runtime
        self.timeout_seconds = float(timeout_seconds)
        self.memory = memory.lower()
        self.cpus = float(cpus)
        self.allow_mutable_image = allow_mutable_image
        self._process: Optional[subprocess.Popen[str]] = None
        self._session: Optional[JsonLineSession] = None
        self._failed = False
        self._counter = 0
        self._operation_lock = threading.RLock()
        self._container = None
        self.image_id = self._inspect_image()
        self.name = f"container:{self.image_id}"

    def _inspect_image(self) -> str:
        return inspect_local_image(self.runtime, self.image)

    def _start(self) -> subprocess.Popen[str]:
        if self._container is not None:
            raise RuntimeError('container cleanup must complete before another start')
        self._container = OwnedContainer(self.runtime, self.image_id)
        command = self._container.create([
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
            "--pids-limit",
            "64",
            "--memory",
            self.memory,
            "--cpus",
            f"{self.cpus:g}",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
        ])
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
            raise RuntimeError("failed to start the detector container") from exc

    @staticmethod
    def _parse_response(raw: str, request_id: str) -> Optional[float]:
        encoded = raw.encode("utf-8")
        if not raw or len(encoded) > MAX_RESPONSE_BYTES:
            raise ValueError("detector container returned an empty or oversized response")
        if not raw.endswith("\n") or raw.count("\n") != 1:
            raise ValueError("detector container response must be one newline-terminated JSON record")
        try:
            response = loads_strict_json(encoded)
        except ValueError as exc:
            raise ValueError("detector container response is not strict JSON") from exc
        if not isinstance(response, dict):
            raise ValueError("detector container response must be a JSON object")
        if response.get("protocol") != PROTOCOL or response.get("request_id") != request_id:
            raise ValueError("detector container response does not match the request")
        if set(response) == {"protocol", "request_id", "score"}:
            score = response["score"]
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise ValueError("detector score must be numeric")
            if not 0 <= score <= 1:
                raise ValueError("detector score must be finite and between zero and one")
            return float(score)
        if set(response) == {"protocol", "request_id", "score", "abstain"}:
            if response["score"] is not None or response["abstain"] is not True:
                raise ValueError("abstention must use score=null and abstain=true")
            return None
        raise ValueError("detector container response violates the v1 allowlist")

    @exclusive_operation
    def score(self, lure: Lure) -> Optional[float]:
        if self._failed:
            raise RuntimeError("detector container failed; create a new detector for a new run")
        request_id = f"request-{self._counter + 1:08d}"
        request: Dict[str, Any] = {
            "protocol": PROTOCOL,
            "request_id": request_id,
            "task": self.task,
            "text": lure.text,
            "language": lure.language,
            "channel": lure.channel,
        }
        encoded = json.dumps(request, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
        try:
            if self._process is None:
                self._process = self._start()
            if self._process.poll() is not None:
                raise RuntimeError("detector container exited before scoring completed")
            self._counter += 1
            if self._session is None:
                self._session = JsonLineSession(self._process, label="detector container")
            raw = self._session.exchange(
                encoded,
                timeout=self.timeout_seconds, max_chars=MAX_RESPONSE_BYTES + 1,
            )
            return self._parse_response(raw, request_id)
        except BaseException as failure:
            cleanup_after_failure(self, failure)
            raise

    @exclusive_operation
    def close(self) -> None:
        close_adapter(self, 'detector container')

    def __enter__(self) -> "ContainerDetector":
        return self

    def __exit__(self, _kind, failure, _traceback) -> None:
        if failure is None:
            self.close()
        else:
            cleanup_after_failure(self, failure)
