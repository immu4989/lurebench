"""Optional differential checks against the independent Rust Safetensors reader."""

import importlib.util
import json
import random
from pathlib import Path

import pytest

from lurebench.checkpoint import DTYPE_BYTES, _header_tensors

REFERENCE_AVAILABLE = importlib.util.find_spec("safetensors") is not None
pytestmark = pytest.mark.skipif(not REFERENCE_AVAILABLE, reason="optional Safetensors reference reader")


def encoded_header(value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    return payload + b" " * (-len(payload) % 8)


@pytest.mark.parametrize("dtype,width", sorted(DTYPE_BYTES.items()))
def test_supported_dtype_layouts_match_reference(tmp_path, dtype, width):
    from safetensors import safe_open

    header = encoded_header({"x": {"dtype": dtype, "shape": [2], "data_offsets": [0, width * 2]}})
    path = tmp_path / "weights.safetensors"
    path.write_bytes(len(header).to_bytes(8, "little") + header + b"\x00" * width * 2)
    assert _header_tensors(header, width * 2) == {"x"}
    with safe_open(str(path), framework="numpy") as value:
        assert value.keys() == ["x"]


@pytest.mark.parametrize("seed", range(20))
def test_seeded_tensor_layouts_agree_with_reference(tmp_path, seed):
    from safetensors import safe_open

    rng = random.Random(seed)
    header = {}
    offset = 0
    for index in range(rng.randint(1, 12)):
        dtype = rng.choice(sorted(DTYPE_BYTES))
        shape = [rng.randint(0, 4) for _ in range(rng.randint(0, 4))]
        count = 1
        for dimension in shape:
            count *= dimension
        size = count * DTYPE_BYTES[dtype]
        header[f"x{index}"] = {"dtype": dtype, "shape": shape, "data_offsets": [offset, offset + size]}
        offset += size
    payload = encoded_header(header)
    path = tmp_path / "weights.safetensors"
    path.write_bytes(len(payload).to_bytes(8, "little") + payload + b"\x00" * offset)
    assert _header_tensors(payload, offset) == set(header)
    with safe_open(str(path), framework="numpy") as value:
        assert set(value.keys()) == set(header)


def test_shape_offset_mismatch_is_rejected_by_both(tmp_path):
    from safetensors import SafetensorError, safe_open

    header = encoded_header({"x": {"dtype": "F32", "shape": [2], "data_offsets": [0, 4]}})
    path = Path(tmp_path) / "bad.safetensors"
    path.write_bytes(len(header).to_bytes(8, "little") + header + b"\x00" * 4)
    with pytest.raises(ValueError):
        _header_tensors(header, 4)
    with pytest.raises(SafetensorError):
        safe_open(str(path), framework="numpy")
