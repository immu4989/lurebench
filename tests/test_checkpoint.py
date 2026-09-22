import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from lurebench import checkpoint
from lurebench.cli import main

pytestmark = pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"),
    reason="checkpoint profile requires POSIX directory-relative no-follow opens",
)


def tensor(dtype="F32", shape=None, offsets=None):
    return {"dtype": dtype, "shape": [1] if shape is None else shape,
            "data_offsets": [0, 4] if offsets is None else offsets}


def write_shard(path, header, data):
    encoded = json.dumps(header, separators=(",", ":")).encode()
    encoded += b" " * (-len(encoded) % 8)
    payload = len(encoded).to_bytes(8, "little") + encoded + data
    path.write_bytes(payload)
    return payload


def sample(root, *, header=None, data=b"\x00" * 4):
    root.mkdir(exist_ok=True)
    header = header if header is not None else {"private.tensor.name": tensor()}
    names = [name for name in header if name != "__metadata__"]
    payload = write_shard(root / "model-00001.safetensors", header, data)
    index = {"metadata": {"total_size": len(data)},
             "weight_map": {name: "model-00001.safetensors" for name in names}}
    (root / checkpoint.INDEX_NAME).write_text(json.dumps(index))
    return payload, index


def test_exact_hashes_membership_and_private_names(tmp_path):
    payload, _ = sample(tmp_path)
    report = checkpoint.inspect_checkpoint(tmp_path)
    assert report["summary"] == {
        "status": "pass", "shard_count": 1, "tensor_count": 1,
        "file_bytes": len(payload), "tensor_bytes": 4,
    }
    assert report["shards"][0]["file_sha256"] == hashlib.sha256(payload).hexdigest()
    assert report["index"]["file_sha256"] == hashlib.sha256(
        (tmp_path / checkpoint.INDEX_NAME).read_bytes()
    ).hexdigest()
    assert "private.tensor.name" not in json.dumps(report)
    assert "model_safety" in " ".join(report["limitations"])


def test_report_matches_published_schema(tmp_path):
    from jsonschema import Draft202012Validator

    sample(tmp_path)
    schema_path = Path(__file__).parents[1] / "spec/checkpoint-preflight-v1.schema.json"
    schema = json.loads(schema_path.read_bytes())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(checkpoint.inspect_checkpoint(tmp_path))


@pytest.mark.parametrize("shape,data", [([], b"\x00" * 4), ([0], b""), ([2, 0], b"")])
def test_scalar_and_empty_tensors_are_structurally_valid(tmp_path, shape, data):
    sample(tmp_path, header={"value": tensor(shape=shape, offsets=[0, len(data)])}, data=data)
    assert checkpoint.inspect_checkpoint(tmp_path)["summary"]["tensor_bytes"] == len(data)


@pytest.mark.parametrize("name", [
    "../outside.safetensors", "/tmp/outside.safetensors", "sub/file.safetensors",
    "sub\\file.safetensors", "C:weights.safetensors", "%2e%2e.safetensors",
    "model..safetensors", "CON.safetensors", "com1.safetensors", ".hidden.safetensors",
    "méta.safetensors", "model.bin", "file.safetensors\n", "a" * 200 + ".safetensors",
])
def test_unsafe_shard_names_rejected_before_any_shard_open(tmp_path, monkeypatch, name):
    _, index = sample(tmp_path)
    index["weight_map"]["private.tensor.name"] = name
    (tmp_path / checkpoint.INDEX_NAME).write_text(json.dumps(index))
    opened = []
    original = checkpoint._regular

    def track(root_fd, filename, maximum):
        opened.append(filename)
        return original(root_fd, filename, maximum)

    monkeypatch.setattr(checkpoint, "_regular", track)
    with pytest.raises(ValueError):
        checkpoint.inspect_checkpoint(tmp_path)
    assert opened == [checkpoint.INDEX_NAME]


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_nonregular_shard_fails_without_loading(tmp_path, kind):
    sample(tmp_path)
    path = tmp_path / "model-00001.safetensors"
    path.unlink()
    if kind == "symlink":
        (tmp_path / "other").write_bytes(b"sensitive")
        path.symlink_to(tmp_path / "other")
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises((OSError, ValueError)):
        checkpoint.inspect_checkpoint(tmp_path)


@pytest.mark.parametrize("mutation", [
    "shape-bool", "shape-float", "negative-dimension", "huge-dimension", "huge-product",
    "offset-bool", "offset-float", "negative-offset", "unknown-dtype", "size-mismatch",
    "unknown-field", "overlap", "gap", "unindexed-suffix", "invalid-metadata",
    "surrogate-metadata", "missing-tensor", "extra-tensor",
])
def test_malformed_tensor_headers_fail_closed(tmp_path, mutation):
    value = tensor()
    header = {"private.tensor.name": value}
    if mutation.startswith("shape-"):
        value["shape"] = [True if mutation == "shape-bool" else 1.0]
    elif mutation == "negative-dimension":
        value["shape"] = [-1]
    elif mutation == "huge-dimension":
        value["shape"] = [2**32]
    elif mutation == "huge-product":
        value["shape"] = [2**31 - 1] * 4
    elif mutation.startswith("offset-"):
        value["data_offsets"] = [False if mutation == "offset-bool" else 0.0, 4]
    elif mutation == "negative-offset":
        value["data_offsets"] = [-1, 3]
    elif mutation == "unknown-dtype":
        value["dtype"] = "PICKLE"
    elif mutation == "size-mismatch":
        value["shape"] = [2]
    elif mutation == "unknown-field":
        value["loader"] = "module:execute"
    elif mutation == "overlap":
        header["other"] = copy.deepcopy(value)
    elif mutation == "gap":
        value.update(dtype="U8", data_offsets=[1, 2])
    elif mutation == "unindexed-suffix":
        value.update(dtype="U8", data_offsets=[0, 1])
    elif mutation == "invalid-metadata":
        header["__metadata__"] = {"format": 1}
    elif mutation == "surrogate-metadata":
        header["__metadata__"] = {"format": "\ud800"}
    sample(tmp_path, header=header)
    if mutation == "missing-tensor":
        write_shard(tmp_path / "model-00001.safetensors", {"different": value}, b"\x00" * 4)
    elif mutation == "extra-tensor":
        write_shard(tmp_path / "model-00001.safetensors",
                    {**header, "extra": tensor(shape=[0], offsets=[4, 4])}, b"\x00" * 4)
    with pytest.raises(ValueError):
        checkpoint.inspect_checkpoint(tmp_path)


@pytest.mark.parametrize("total", [None, True, 4.0, 3, -1])
def test_declared_total_must_be_exact_integer_byte_count(tmp_path, total):
    _, index = sample(tmp_path)
    index["metadata"]["total_size"] = total
    (tmp_path / checkpoint.INDEX_NAME).write_text(json.dumps(index))
    with pytest.raises(ValueError, match="total_size"):
        checkpoint.inspect_checkpoint(tmp_path)


def test_resource_bounds_precede_header_allocation(tmp_path):
    sample(tmp_path)
    path = tmp_path / "model-00001.safetensors"
    path.write_bytes((2**63).to_bytes(8, "little") + b"{}")
    with pytest.raises(ValueError, match="header length"):
        checkpoint.inspect_checkpoint(tmp_path)


def test_total_budget_applies_to_actual_files(tmp_path):
    payload, _ = sample(tmp_path)
    assert checkpoint.inspect_checkpoint(tmp_path, max_total_bytes=len(payload))
    with pytest.raises(ValueError):
        checkpoint.inspect_checkpoint(tmp_path, max_total_bytes=len(payload) - 1)


def test_duplicate_index_keys_are_rejected(tmp_path):
    sample(tmp_path)
    (tmp_path / checkpoint.INDEX_NAME).write_text('{"metadata":{},"metadata":{},"weight_map":{}}')
    with pytest.raises(ValueError, match="duplicate"):
        checkpoint.inspect_checkpoint(tmp_path)


def test_multiple_shards_have_exact_membership_and_aggregate_budget(tmp_path):
    first, index = sample(tmp_path)
    second = write_shard(tmp_path / "model-00002.safetensors", {"second": tensor()}, b"1234")
    index["weight_map"]["second"] = "model-00002.safetensors"
    index["metadata"]["total_size"] = 8
    (tmp_path / checkpoint.INDEX_NAME).write_text(json.dumps(index))
    report = checkpoint.inspect_checkpoint(tmp_path, max_total_bytes=len(first) + len(second))
    assert report["summary"]["shard_count"] == 2
    assert report["summary"]["file_bytes"] == len(first) + len(second)
    with pytest.raises(ValueError):
        checkpoint.inspect_checkpoint(tmp_path, max_total_bytes=len(first) + len(second) - 1)
    index["weight_map"] = {"second": "model-00001.safetensors",
                           "private.tensor.name": "model-00002.safetensors"}
    (tmp_path / checkpoint.INDEX_NAME).write_text(json.dumps(index))
    with pytest.raises(ValueError, match="membership"):
        checkpoint.inspect_checkpoint(tmp_path)


def test_case_aliases_rejected_before_open(tmp_path):
    _, index = sample(tmp_path)
    index["weight_map"]["alias"] = "MODEL-00001.safetensors"
    (tmp_path / checkpoint.INDEX_NAME).write_text(json.dumps(index))
    with pytest.raises(ValueError, match="case-insensitive"):
        checkpoint.inspect_checkpoint(tmp_path)


@pytest.mark.parametrize("target", ["index", "root"])
def test_index_and_root_symlinks_rejected(tmp_path, target):
    root = tmp_path / "actual"
    sample(root)
    if target == "root":
        link = tmp_path / "link"
        link.symlink_to(root, target_is_directory=True)
        root = link
    else:
        path = root / checkpoint.INDEX_NAME
        path.rename(root / "actual-index.json")
        path.symlink_to(root / "actual-index.json")
    with pytest.raises(OSError):
        checkpoint.inspect_checkpoint(root)


def test_opaque_tensor_changes_change_digest_not_structure(tmp_path):
    sample(tmp_path)
    before = checkpoint.inspect_checkpoint(tmp_path)
    sample(tmp_path, data=b"1234")
    after = checkpoint.inspect_checkpoint(tmp_path)
    assert before["summary"] == after["summary"]
    assert before["shards"][0]["header_sha256"] == after["shards"][0]["header_sha256"]
    assert before["shards"][0]["file_sha256"] != after["shards"][0]["file_sha256"]


def test_mutation_after_file_read_rejected(tmp_path, monkeypatch):
    from contextlib import contextmanager

    sample(tmp_path)
    original = checkpoint._regular

    @contextmanager
    def mutate_after_read(root_fd, name, maximum):
        with original(root_fd, name, maximum) as opened:
            yield opened
        if name.endswith(".safetensors"):
            (tmp_path / name).write_bytes(b"changed")

    monkeypatch.setattr(checkpoint, "_regular", mutate_after_read)
    with pytest.raises(ValueError, match="changed"):
        checkpoint.inspect_checkpoint(tmp_path)


@pytest.mark.parametrize("payload", [b"short", b"\x08" + b"\x00" * 7 + b"{}"])
def test_truncated_shard_rejected(tmp_path, payload):
    sample(tmp_path)
    (tmp_path / "model-00001.safetensors").write_bytes(payload)
    with pytest.raises(ValueError):
        checkpoint.inspect_checkpoint(tmp_path)


def test_duplicate_tensor_header_keys_rejected():
    entry = '"x":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}'
    with pytest.raises(ValueError, match="duplicate"):
        checkpoint._header_tensors(("{" + entry + "," + entry + "}").encode(), 1)


def test_cli_private_output_no_overwrite_and_redacted_rejections(tmp_path, capsys):
    directory = tmp_path / "checkpoint"
    sample(directory)
    output = tmp_path / "inspection.json"
    args = ["checkpoint-inspect", str(directory), "--out", str(output), "--json"]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out) == json.loads(output.read_bytes())
    assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == original
    assert "private.tensor.name" not in capsys.readouterr().err
