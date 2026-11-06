"""Resolve local OCI image identity once; never re-resolve a tag at launch.

The runtime and its image store remain trusted. A local image ID is not a
publisher signature or a portable registry manifest/index digest.
"""

from __future__ import annotations

import re
import subprocess

_IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}")
_PODMAN_ID = re.compile(r"[a-f0-9]{64}")


def inspect_local_image(runtime: str, reference: str) -> str:
    try:
        result = subprocess.run(
            [runtime, "image", "inspect", "--format", "{{.Id}}", reference],
            check=True, capture_output=True, text=True, timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError(
            "container image is not available locally; LureBench never pulls it implicitly"
        ) from exc
    identity = result.stdout.strip()
    # Podman documents .Id as a full bare SHA-256 hex string. Preserve the
    # existing evidence format while accepting its native inspection output.
    if runtime == "podman" and _PODMAN_ID.fullmatch(identity):
        identity = "sha256:" + identity
    if _IMAGE_ID.fullmatch(identity) is None:
        raise RuntimeError("container runtime returned an invalid immutable image id")
    return identity


def execution_image(runtime: str, identity: str) -> str:
    if _IMAGE_ID.fullmatch(identity) is None:
        raise ValueError("execution requires a full immutable image id")
    # Full IDs avoid short-ID ambiguity and tag lookup; no fallback or pull is
    # allowed when the admitted image is no longer present in the runtime store.
    return identity.removeprefix("sha256:") if runtime == "podman" else identity
