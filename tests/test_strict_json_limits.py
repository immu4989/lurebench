import json
import math

import pytest

from lurebench.receipts import loads_strict_json


def parse(payload):
    return loads_strict_json(payload)


@pytest.mark.parametrize("token", [b"1e9999", b"-1e9999", b"NaN", b"Infinity", b"-Infinity"])
def test_nonfinite_numbers_are_rejected_in_nested_json(token):
    with pytest.raises(ValueError):
        parse(b'{"nested":[{"number":' + token + b"}]}")


def test_excessively_nested_json_is_a_controlled_validation_failure():
    payload = b"[" * 2000 + b"0" + b"]" * 2000
    with pytest.raises(ValueError, match="nesting"):
        parse(payload)


def test_depth_boundary_and_brackets_inside_strings():
    assert parse(b"[" * 128 + b"0" + b"]" * 128) is not None
    with pytest.raises(ValueError, match="nesting"):
        parse(b"[" * 129 + b"0" + b"]" * 129)
    value = {"quoted": '[{\\\"' * 1000}
    assert parse(json.dumps(value).encode("utf-8")) == value


def test_finite_numeric_values_preserve_existing_types():
    value = parse(b'{"a":1,"b":1.0,"c":1e308,"d":-1e308,"e":true}')
    assert type(value["a"]) is int
    assert type(value["b"]) is float
    assert type(value["e"]) is bool
    assert all(math.isfinite(value[key]) for key in ("c", "d"))


def test_duplicate_keys_remain_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        parse(b'{"a":1,"a":2}')
