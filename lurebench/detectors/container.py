"""Isolated JSONL protocol for proprietary or non-Python fraud detectors.

Only the text and declared language/channel cross the container boundary. Ground
truth, source provenance, typology, generator, persuasion tags, metadata, and the
original record id are deliberately withheld. The runtime receives no network,
host mounts, Linux capabilities, or writable root filesystem.
"""

from __future__ import annotations

import json
import math
import queue
import re
import shutil
import subprocess
import threading
from typing import Any, Dict, Optional

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
        if not allow_mutable_image and not _DIGEST_IMAGE.fullmatch(image):
            raise ValueError(
                "container image must be pinned as name@sha256:<64 hex>; "
                "use allow_mutable_image only for local development"
            )
        if task not in {"fraud", "provenance"}:
            raise ValueError("task must be fraud or provenance")
        if not math.isfinite(timeout_seconds) or not 0.1 <= timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be between 0.1 and 300")
        if not isinstance(memory, str) or not _MEMORY.fullmatch(memory):
            raise ValueError("memory must look like 512m or 1g")
        if not math.isfinite(cpus) or not 0.1 <= cpus <= 32:
            raise ValueError("cpus must be between 0.1 and 32")

        self.image = image
        self.task = task
        self.runtime = runtime
        self.timeout_seconds = float(timeout_seconds)
        self.memory = memory.lower()
        self.cpus = float(cpus)
        self.allow_mutable_image = allow_mutable_image
        self._process: Optional[subprocess.Popen[str]] = None
        self._counter = 0
        self.image_id = self._inspect_image()
        self.name = f"container:{self.image_id}"

    def _inspect_image(self) -> str:
        try:
            result = subprocess.run(
                [self.runtime, "image", "inspect", "--format", "{{.Id}}", self.image],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            raise RuntimeError(
                "container image is not available locally; LureBench never pulls it implicitly"
            ) from exc
        image_id = result.stdout.strip()
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
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
            raise RuntimeError("failed to start the detector container") from exc

    def _readline(self) -> str:
        assert self._process is not None and self._process.stdout is not None
        output: queue.Queue[object] = queue.Queue(maxsize=1)

        def read() -> None:
            try:
                output.put(self._process.stdout.readline())
            except Exception as exc:  # keep reader failures inside the bounded queue
                output.put(exc)

        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        try:
            value = output.get(timeout=self.timeout_seconds)
        except queue.Empty as exc:
            self.close()
            raise TimeoutError(
                "detector container exceeded its per-record response timeout"
            ) from exc
        if isinstance(value, Exception):
            self.close()
            raise RuntimeError("detector container produced invalid UTF-8 output") from value
        return str(value)

    @staticmethod
    def _parse_response(raw: str, request_id: str) -> Optional[float]:
        encoded = raw.encode("utf-8")
        if not raw or len(encoded) > MAX_RESPONSE_BYTES:
            raise ValueError("detector container returned an empty or oversized response")
        try:
            response = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("detector container response is not one JSON object per line") from exc
        if not isinstance(response, dict):
            raise ValueError("detector container response must be a JSON object")
        if response.get("protocol") != PROTOCOL or response.get("request_id") != request_id:
            raise ValueError("detector container response does not match the request")
        if set(response) == {"protocol", "request_id", "score"}:
            score = response["score"]
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise ValueError("detector score must be numeric")
            result = float(score)
            if not math.isfinite(result) or not 0 <= result <= 1:
                raise ValueError("detector score must be finite and between zero and one")
            return result
        if set(response) == {"protocol", "request_id", "score", "abstain"}:
            if response["score"] is not None or response["abstain"] is not True:
                raise ValueError("abstention must use score=null and abstain=true")
            return None
        raise ValueError("detector container response violates the v1 allowlist")

    def score(self, lure: Lure) -> Optional[float]:
        if self._process is None:
            self._process = self._start()
        if self._process.poll() is not None:
            self.close()
            raise RuntimeError("detector container exited before scoring completed")
        assert self._process.stdin is not None
        self._counter += 1
        request_id = f"request-{self._counter:08d}"
        request: Dict[str, Any] = {
            "protocol": PROTOCOL,
            "request_id": request_id,
            "task": self.task,
            "text": lure.text,
            "language": lure.language,
            "channel": lure.channel,
        }
        try:
            self._process.stdin.write(
                json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self.close()
            raise RuntimeError("detector container closed its input stream") from exc
        try:
            return self._parse_response(self._readline(), request_id)
        except Exception:
            self.close()
            raise

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

    def __enter__(self) -> "ContainerDetector":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
