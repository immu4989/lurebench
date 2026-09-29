"""Dataset parsing must fail before ambiguous labels reach model evaluation."""

import json
import os

import pytest

from lurebench.schema import Lure, iter_jsonl, load_jsonl, save_jsonl


def value(**changes):
    result = dict(id="synthetic-1", text="synthetic message", label=1,
                  source="human", typology="phishing")
    result.update(changes)
    return result


@pytest.mark.parametrize("changes", [
    {"label": True}, {"label": False}, {"label": 1.0}, {"label": "1"},
    {"id": None}, {"id": ""}, {"id": "line\nbreak"}, {"id": "x" * 513},
    {"text": None}, {"text": []}, {"text": "\ud800"}, {"source": []},
    {"typology": []}, {"channel": {}}, {"language": ""}, {"meta": []},
    {"meta": None}, {"persuasion": "urgency"}, {"persuasion": [True]},
    {"generator": []}, {"generator": ""},
])
def test_record_field_types_are_not_silently_coerced(changes):
    with pytest.raises(ValueError):
        Lure.from_dict(value(**changes))


@pytest.mark.parametrize("payload", [
    b'[]', b'null', b'42', b'{"label":0,"label":1}',
    json.dumps(value(meta={"PRIVATE_SENTINEL": float("nan")})).encode(),
    json.dumps(value(meta={"PRIVATE_SENTINEL": float("inf")})).encode(),
    json.dumps(value(meta={"ok": 1})).replace('"ok": 1', '"ok": 1e999').encode(),
    json.dumps(value()).replace('"human"', '"human", "source":"ai"').encode(),
    b'{"meta":' + b'[' * 130 + b'0' + b']' * 130 + b'}',
    b'\xff',
])
def test_both_loaders_reject_ambiguous_json_with_redacted_line_errors(tmp_path, payload):
    path = tmp_path / "input.jsonl"
    path.write_bytes(b"// comment\n\n" + payload + b"\n")
    for loader in (load_jsonl, lambda p: list(iter_jsonl(p))):
        with pytest.raises(ValueError, match="line 3") as caught:
            loader(path)
        assert "PRIVATE_SENTINEL" not in str(caught.value)
        assert caught.value.__suppress_context__


def test_unicode_comments_extension_fields_and_exact_byte_limits(tmp_path):
    path = tmp_path / "input.jsonl"
    payload = json.dumps(value(text="café 東京", future_extension=True), ensure_ascii=False).encode() + b"\r\n"
    path.write_bytes(payload)
    loaded = load_jsonl(path, max_bytes=len(payload), max_record_bytes=len(payload))
    assert loaded[0].text == "café 東京"
    with pytest.raises(ValueError):
        load_jsonl(path, max_record_bytes=len(payload) - 1)
    with pytest.raises(ValueError):
        load_jsonl(path, max_bytes=len(payload) - 1)


@pytest.mark.parametrize("bad", [True, False, 0, -1, "10", 1.0])
def test_limits_are_strict_positive_integers(tmp_path, bad):
    with pytest.raises(ValueError):
        load_jsonl(tmp_path / "missing", max_bytes=bad)
    with pytest.raises(ValueError):
        save_jsonl([], tmp_path / "output", max_record_bytes=bad)


def test_hub_style_symlinks_to_regular_files_are_supported(tmp_path):
    blob = tmp_path / "blob"
    save_jsonl([Lure.from_dict(value())], blob)
    link = tmp_path / "snapshot.jsonl"
    link.symlink_to(blob)
    assert load_jsonl(link) == load_jsonl(blob)
    with pytest.raises(ValueError, match="symlink"):
        save_jsonl([], link)
    assert load_jsonl(blob)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO")
def test_fifo_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular"):
        load_jsonl(fifo)


def test_stream_detects_growth_before_successful_completion(tmp_path):
    path = tmp_path / "input.jsonl"
    save_jsonl([Lure.from_dict(value())], path)
    stream = iter_jsonl(path)
    assert next(stream).id == "synthetic-1"
    with path.open("ab") as handle:
        handle.write(b"\n")
    with pytest.raises(ValueError, match="changed"):
        list(stream)


@pytest.mark.parametrize("failure", ["mutated", "nonfinite", "ambiguous_keys", "too_large", "iterator"])
def test_failed_save_preserves_existing_bytes_and_cleans_temporary(tmp_path, failure):
    path = tmp_path / "output.jsonl"
    save_jsonl([Lure.from_dict(value())], path)
    before = path.read_bytes()
    bad = Lure.from_dict(value(id="second"))
    if failure == "mutated":
        bad.label = True
    elif failure == "nonfinite":
        bad.meta = {"number": float("nan")}
    elif failure == "ambiguous_keys":
        bad.meta = {1: "one", "1": "different"}
    elif failure == "too_large":
        bad.text = "x" * 1000

    def records():
        yield Lure.from_dict(value())
        if failure == "iterator":
            raise RuntimeError("synthetic input failure")
        yield bad

    with pytest.raises((ValueError, RuntimeError)):
        save_jsonl(records(), path, max_record_bytes=500)
    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".lure-dataset-*"))


def test_empty_files_remain_supported(tmp_path):
    path = tmp_path / "empty.jsonl"
    save_jsonl([], path)
    assert load_jsonl(path) == []
