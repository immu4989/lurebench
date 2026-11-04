"""Reject allocation-heavy JSON before the standard decoder is entered."""

import json

import pytest

from lurebench.receipts import loads_strict_json


def limited_parse(payload, nodes):
    return loads_strict_json(payload, max_nodes=nodes)


@pytest.mark.parametrize("payload,nodes", [
    (b'null', 1), (b'true', 1), (b'-1.25e+2', 1), (b'{}', 1), (b'[]', 1),
    (b'{"a":0}', 3), (b'[{"a":[true,null,"x"]},{}]', 8),
    (b'{"a\\u0062":"[,{}]","escaped":"\\\\\\\"","n":1}', 7),
])
def test_exact_node_boundary(payload, nodes):
    expected = json.loads(payload)
    assert limited_parse(payload, nodes) == expected
    if nodes > 1:
        with pytest.raises(ValueError, match="node"):
            limited_parse(payload, nodes - 1)


@pytest.mark.parametrize("limit", [True, False, 0, -1, 1.5, "2", None])
def test_invalid_node_budgets(limit):
    with pytest.raises(ValueError, match="node limit"):
        limited_parse(b'0', limit)


def test_numeric_token_boundary_and_long_strings():
    token = b'0.' + b'0' * 4093 + b'1'
    assert len(token) == 4096
    assert limited_parse(token, 1) == 0.
    with pytest.raises(ValueError, match="token"):
        limited_parse(token + b'1', 1)
    # Strings are byte/field bounded by callers, not numeric token length.
    value = '[{,:"\\\\\\\"' * 10000
    assert limited_parse(json.dumps(value).encode(), 1) == value


def test_seeded_structures_preserve_types_and_exact_node_count():
    import random

    rng = random.Random(4989)

    def make(depth):
        if depth == 0 or rng.random() < .5:
            return rng.choice([None, True, False, -123, 1.25, "", "é", '\\\\"[{,}'])
        if rng.random() < .5:
            return [make(depth - 1) for _ in range(rng.randrange(6))]
        return {str(i) + rng.choice(["", "\\", "é", '"']): make(depth - 1)
                for i in range(rng.randrange(6))}

    def count(value):
        if isinstance(value, dict):
            return 1 + len(value) + sum(count(item) for item in value.values())
        if isinstance(value, list):
            return 1 + sum(count(item) for item in value)
        return 1

    for _ in range(400):
        value = make(5)
        payload = json.dumps(value, ensure_ascii=rng.choice([True, False])).encode()
        nodes = count(value)
        assert limited_parse(payload, nodes) == value
        if nodes > 1:
            with pytest.raises(ValueError, match="node"):
                limited_parse(payload, nodes - 1)


@pytest.mark.parametrize("payload", [
    b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'[NaN]', b'{"a":1e999}',
    b'{"a":[}', b'0 0', b'{"a":}', b'"unterminated', b'[] garbage', b'\xff',
])
def test_structure_scan_does_not_replace_strict_syntax_validation(payload):
    with pytest.raises(ValueError):
        limited_parse(payload, 100)


def test_wide_document_is_rejected_before_decoding(monkeypatch):
    payload = b'[' + b'{},' * 1000000 + b'{}]'
    monkeypatch.setattr(json, "loads", lambda *a, **kw: pytest.fail("decoder entered"))
    with pytest.raises(ValueError, match="node"):
        loads_strict_json(payload)


def test_long_numeric_token_is_rejected_before_decoding(monkeypatch):
    payload = b'[0.' + b'0' * 5000 + b'1]'
    monkeypatch.setattr(json, "loads", lambda *a, **kw: pytest.fail("decoder entered"))
    with pytest.raises(ValueError, match="token"):
        loads_strict_json(payload)


def test_runtime_rejects_complexity_before_decision_or_receipt(tmp_path, monkeypatch):
    from lurebench.runtime import RuntimePDP, default_runtime_profile
    from lurebench.runtime_service import RuntimeDecisionApplication

    pdp = RuntimePDP(default_runtime_profile())
    monkeypatch.setattr(pdp, "decide", lambda *a: pytest.fail("decision evaluated"))
    log = tmp_path / "receipt.jsonl"
    application = RuntimeDecisionApplication(pdp, log)
    with pytest.raises(ValueError, match="node"):
        application.decide(b'[' + b'0,' * 4096 + b'0]')
    assert log.read_bytes() == b''


def test_safetensors_large_header_keeps_its_specialized_budget():
    from lurebench.checkpoint import MAX_HEADER_BYTES, _header_tensors

    # 25,000 rank-32 tensors exceed the generic million-node budget while
    # remaining well inside the supported tensor count and 8 MiB header limit.
    tensors = {f"weight.{i}": {"dtype": "U8", "shape": [1] * 32,
                               "data_offsets": [i, i + 1]} for i in range(25000)}
    payload = json.dumps(tensors, separators=(",", ":")).encode()
    assert len(payload) < MAX_HEADER_BYTES
    with pytest.raises(ValueError, match="node"):
        loads_strict_json(payload)
    assert _header_tensors(payload, 25000) == set(tensors)
