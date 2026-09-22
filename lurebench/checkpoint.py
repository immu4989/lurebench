"""Offline, non-executing checkpoint preflight for a bounded Safetensors profile.

This reads and hashes opaque tensor bytes; it never imports a model framework,
loads tensor values, follows shard links, or downloads artifacts. Inspection is
not an atomic guarantee about a later loader or a claim of benign model behavior.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .receipts import loads_strict_json

SCHEMA = "https://github.com/immu4989/lurebench/spec/checkpoint-preflight/v1"
INDEX_NAME = "model.safetensors.index.json"
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 8 * 1024 * 1024
MAX_SHARDS = 1024
MAX_TENSORS = 100_000
DEFAULT_MAX_TOTAL_BYTES = 32 * 1024**3
DTYPE_BYTES = {
    "BOOL": 1, "U8": 1, "I8": 1, "U16": 2, "I16": 2,
    "F16": 2, "BF16": 2, "U32": 4, "I32": 4, "F32": 4,
    "U64": 8, "I64": 8, "F64": 8, "F8_E4M3": 1, "F8_E5M2": 1,
}
LIMITATIONS = [
    "bounded_sharded_safetensors_profile_not_all_valid_safetensors_encodings",
    "tensor_bytes_hashed_not_interpreted_or_checked_for_model_behavior",
    "config_tokenizer_code_provenance_and_unreferenced_files_not_inspected",
    "inspection_does_not_authenticate_a_publisher_or_patch_model_loading_libraries",
    "mutable_directories_and_later_loaders_require_separate_integrity_controls",
    "passing_is_not_model_safety_compliance_or_deployment_authorization",
]


def _filename(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,180}\.safetensors", value, flags=re.ASCII
    ) is None:
        raise ValueError("shard names must be bounded portable Safetensors basenames")
    if ".." in value or value.split(".")[0].upper() in {
        "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        raise ValueError("ambiguous or reserved shard basename")
    return value


def _tensor_name(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 1024:
        raise ValueError("tensor names must be bounded nonempty UTF-8 strings")
    if value == "__metadata__":
        raise ValueError("reserved metadata key cannot be a tensor name")
    return value


def _identity(metadata: os.stat_result) -> tuple:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


@contextmanager
def _regular(root_fd: int, name: str, maximum: int) -> Iterator[tuple[Any, os.stat_result]]:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise ValueError("checkpoint source must be a bounded nonempty regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            yield stream, before
            if _identity(os.fstat(stream.fileno())) != _identity(before):
                raise ValueError("checkpoint source changed during inspection")
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if _identity(current) != _identity(before):
                raise ValueError("checkpoint source path changed during inspection")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _header_tensors(payload: bytes, data_size: int) -> set[str]:
    if not payload.startswith(b"{"):
        raise ValueError("Safetensors header must start with an object")
    header = loads_strict_json(payload)
    if not isinstance(header, dict) or not 1 <= len(header) <= MAX_TENSORS + 1:
        raise ValueError("Safetensors header must contain a bounded tensor map")
    metadata = header.pop("__metadata__", {})
    if not isinstance(metadata, dict) or any(not isinstance(v, str) for v in metadata.values()):
        raise ValueError("Safetensors metadata must map strings to strings")
    for key, value in metadata.items():
        key.encode("utf-8")
        value.encode("utf-8")
    if not 1 <= len(header) <= MAX_TENSORS:
        raise ValueError("checkpoint shards must contain at least one tensor")
    ranges = []
    for name, tensor in header.items():
        _tensor_name(name)
        if not isinstance(tensor, dict) or set(tensor) != {"dtype", "shape", "data_offsets"}:
            raise ValueError("tensor header fields violate the supported profile")
        dtype = tensor["dtype"]
        if not isinstance(dtype, str) or dtype not in DTYPE_BYTES:
            raise ValueError("unsupported tensor dtype in checkpoint profile")
        shape = tensor["shape"]
        if not isinstance(shape, list) or len(shape) > 32:
            raise ValueError("tensor rank exceeds the supported profile")
        elements = 1
        for dimension in shape:
            if type(dimension) is not int or not 0 <= dimension <= 2**31 - 1:
                raise ValueError("tensor dimensions must be bounded nonnegative integers")
            elements *= dimension
            if elements > 2**63 - 1:
                raise ValueError("tensor element count exceeds the supported profile")
        offsets = tensor["data_offsets"]
        if (
            not isinstance(offsets, list) or len(offsets) != 2
            or any(type(value) is not int for value in offsets)
            or not 0 <= offsets[0] <= offsets[1] <= data_size
            or offsets[1] - offsets[0] != elements * DTYPE_BYTES[dtype]
        ):
            raise ValueError("tensor shape, dtype, and data offsets disagree")
        ranges.append(tuple(offsets))
    cursor = 0
    for begin, end in sorted(ranges):
        if begin != cursor:
            raise ValueError("tensor data has an overlap or an unindexed gap")
        cursor = end
    if cursor != data_size:
        raise ValueError("tensor data has an unindexed suffix")
    return set(header)


def inspect_checkpoint(
    directory: Path, *, max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
) -> dict[str, Any]:
    """Hash and inspect indexed shards under one opened POSIX directory.

    The caller must control parent directories and prevent concurrent mutation.
    Index filenames are never accepted as paths or opened before validation.
    """
    if type(max_total_bytes) is not int or not 1 <= max_total_bytes <= 1024**4:
        raise ValueError("total byte budget must be an integer between 1 and 1 TiB")
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("checkpoint preflight requires POSIX directory-relative no-follow opens")
    root = Path(directory)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with _regular(root_fd, INDEX_NAME, MAX_INDEX_BYTES) as (stream, metadata):
            payload = stream.read(MAX_INDEX_BYTES + 1)
            if len(payload) != metadata.st_size or len(payload) > MAX_INDEX_BYTES:
                raise ValueError("checkpoint index changed or exceeds its bound")
            index = loads_strict_json(payload)
            identities = {INDEX_NAME: _identity(metadata)}
        if (
            not isinstance(index, dict) or set(index) != {"metadata", "weight_map"}
            or not isinstance(index["metadata"], dict)
            or not isinstance(index["weight_map"], dict)
            or not 1 <= len(index["weight_map"]) <= MAX_TENSORS
        ):
            raise ValueError("checkpoint index violates the bounded sharded profile")
        expected: dict[str, set[str]] = {}
        for tensor, shard in index["weight_map"].items():
            expected.setdefault(_filename(shard), set()).add(_tensor_name(tensor))
        if len(expected) > MAX_SHARDS:
            raise ValueError("checkpoint has too many shards")
        if len({name.casefold() for name in expected}) != len(expected):
            raise ValueError("checkpoint shard names collide on case-insensitive filesystems")
        results = []
        total_bytes = 0
        tensor_bytes = 0
        for name in sorted(expected):
            with _regular(root_fd, name, max_total_bytes - total_bytes) as (stream, metadata):
                prefix = stream.read(8)
                if len(prefix) != 8:
                    raise ValueError("Safetensors length prefix is truncated")
                header_size = int.from_bytes(prefix, "little")
                if not 2 <= header_size <= min(MAX_HEADER_BYTES, metadata.st_size - 8):
                    raise ValueError("Safetensors header length exceeds file or profile bounds")
                header = stream.read(header_size)
                if len(header) != header_size:
                    raise ValueError("Safetensors header is truncated")
                data_size = metadata.st_size - 8 - header_size
                if _header_tensors(header, data_size) != expected[name]:
                    raise ValueError("index-to-shard tensor membership is not exact")
                digest = hashlib.sha256(prefix + header)
                remaining = data_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("tensor data was truncated during inspection")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if stream.read(1):
                    raise ValueError("checkpoint shard grew during inspection")
                results.append({
                    "name": name, "file_bytes": metadata.st_size,
                    "file_sha256": digest.hexdigest(), "header_bytes": header_size,
                    "header_sha256": hashlib.sha256(header).hexdigest(),
                    "tensor_count": len(expected[name]), "tensor_bytes": data_size,
                })
                total_bytes += metadata.st_size
                tensor_bytes += data_size
                identities[name] = _identity(metadata)
        declared_size = index["metadata"].get("total_size")
        if "total_size" in index["metadata"] and (
            type(declared_size) is not int or declared_size != tensor_bytes
        ):
            raise ValueError("index total_size does not match tensor data bytes")
        for name, identity in identities.items():
            if _identity(os.stat(name, dir_fd=root_fd, follow_symlinks=False)) != identity:
                raise ValueError("checkpoint source changed before inspection completed")
        return {
            "schema": SCHEMA, "schema_version": 1,
            "profile": "sharded-safetensors-byte-aligned-v1",
            "index": {"name": INDEX_NAME, "file_sha256": hashlib.sha256(payload).hexdigest()},
            "shards": results,
            "summary": {"status": "pass", "shard_count": len(results),
                        "tensor_count": len(index["weight_map"]), "file_bytes": total_bytes,
                        "tensor_bytes": tensor_bytes},
            "limits": {"maximum_total_shard_bytes": max_total_bytes,
                       "maximum_header_bytes": MAX_HEADER_BYTES, "maximum_shards": MAX_SHARDS},
            "limitations": list(LIMITATIONS),
        }
    finally:
        os.close(root_fd)
