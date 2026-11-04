"""Session ceilings must precede state mutation, without evicting replay history."""

import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from lurebench import runtime
from lurebench import runtime_service as service
from lurebench.permit import build_permit_request

NOW = '2026-11-04T00:00:01Z'


def request(pdp, index=1, **changes):
    return runtime.build_runtime_request(build_permit_request(sequence=1), profile=pdp.profile,
        correlation_id=f'lifetime-{index}', nonce=f'nonce-{index}', requested_at=NOW, **changes)


def snapshot(pdp):
    return (pdp._receipt_sequence, pdp._previous_receipt_sha256, frozenset(pdp._used_nonces),
            dict(pdp._last_request_sequence), frozenset(pdp._stopped_runs))


def test_protocol_ceiling_never_advances_state_for_the_513th_request():
    pdp = runtime.RuntimePDP()
    previous = None
    for index in range(1, 513):
        value = request(pdp, index)
        _, receipt = pdp.decide(value, decided_at=NOW)
        runtime.validate_runtime_receipt(receipt, value, expected_sequence=index,
                                        previous_receipt_sha256=previous)
        previous = runtime._sha256(runtime._canonical(receipt))
    before = snapshot(pdp)
    for _ in range(3):
        with pytest.raises(runtime.RuntimeCapacityExceeded):
            pdp.decide(request(pdp, 513), decided_at=NOW)
    assert snapshot(pdp) == before
    assert pdp.receipt_count == len(pdp._used_nonces) == 512


def test_rejected_receipt_timestamp_never_consumes_replay_state():
    pdp = runtime.RuntimePDP()
    before = snapshot(pdp)
    with pytest.raises(ValueError, match='predate'):
        pdp.decide(request(pdp), decided_at='2026-11-04T00:00:00Z')
    assert snapshot(pdp) == before
    decision, receipt = pdp.decide(request(pdp), decided_at=NOW)
    assert decision['decision'] == 'allow'
    assert receipt['chain']['sequence'] == 1


def test_service_exhaustion_is_planned_not_an_uncertain_storage_failure(monkeypatch):
    app = service.RuntimeDecisionApplication(runtime.RuntimePDP())
    monkeypatch.setattr(runtime, '_now', lambda: NOW)
    for index in range(1, 513):
        app.decide(json.dumps(request(app.pdp, index)).encode())
    assert app.readiness()['ready'] is False
    assert app.readiness()['reason'] == 'decision_limit_reached'
    assert app.readiness()['decision_budget'] == {'limit': 512, 'evaluated': 512, 'remaining': 0}
    before = snapshot(app.pdp)
    monkeypatch.setattr(app.pdp, 'decide', lambda *a: pytest.fail('exhausted engine entered'))
    with pytest.raises(service.RuntimeDecisionExhausted):
        app.decide(json.dumps(request(app.pdp, 513)).encode())
    assert snapshot(app.pdp) == before


@pytest.mark.parametrize('stage', ['validate_runtime_receipt', '_canonical', '_RuntimeState'])
def test_prepublication_fault_keeps_snapshot_and_allows_direct_retry(stage):
    pdp = runtime.RuntimePDP()
    value = request(pdp)
    old = pdp._state
    with patch.object(runtime, stage, side_effect=ValueError('synthetic preparation failure')):
        with pytest.raises(ValueError, match='synthetic'):
            pdp.decide(value, decided_at=NOW)
    assert pdp._state is old
    decision, receipt = pdp.decide(value, decided_at=NOW)
    assert decision['decision'] == 'allow'
    assert receipt['chain']['sequence'] == 1


def test_old_history_is_immutable_and_earliest_nonce_is_not_evicted():
    pdp = runtime.RuntimePDP()
    first = request(pdp)
    pdp.decide(first, decided_at=NOW)
    old = pdp._state
    with pytest.raises(TypeError):
        old.last_request_sequence['other-run'] = 1
    for index in range(2, 20):
        pdp.decide(request(pdp, index), decided_at=NOW)
    decision, _ = pdp.decide(first, decided_at=NOW)
    assert decision['reason_code'] == 'request_replay_denied'
    assert old.receipt_sequence == 1 and old.used_nonces == frozenset({'nonce-1'})
    assert pdp.receipt_count == 20


def test_direct_concurrent_decisions_keep_one_complete_chain():
    pdp = runtime.RuntimePDP()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda i: pdp.decide(request(pdp, i), decided_at=NOW), range(1, 33)))
    receipts = sorted((receipt for _, receipt in results), key=lambda r: r['chain']['sequence'])
    previous = None
    for index, receipt in enumerate(receipts, 1):
        assert receipt['chain'] == {'sequence': index, 'previous_receipt_sha256': previous}
        previous = runtime._sha256(runtime._canonical(receipt))
    assert pdp.receipt_count == len(pdp._used_nonces) == 32
    assert pdp._previous_receipt_sha256 == previous


@pytest.mark.parametrize('logged', [False, True])
def test_small_budget_returns_last_receipt_then_stays_exhausted(tmp_path, monkeypatch, logged):
    log = tmp_path / 'receipts.jsonl' if logged else None
    app = service.RuntimeDecisionApplication(runtime.RuntimePDP(), log, max_decisions=2)
    monkeypatch.setattr(runtime, '_now', lambda: NOW)
    for bad in (b'{}', b'not-json'):
        with pytest.raises(ValueError):
            app.decide(bad)
    assert app.readiness()['decision_budget']['remaining'] == 2
    for index in (1, 2):
        result = app.decide(json.dumps(request(app.pdp, index)).encode())
        assert result['receipt']['chain']['sequence'] == index
    assert app.readiness()['reason'] == 'decision_limit_reached'
    before = snapshot(app.pdp)
    for _ in range(2):
        with pytest.raises(service.RuntimeDecisionExhausted):
            app.decide(json.dumps(request(app.pdp, 3)).encode())
    assert snapshot(app.pdp) == before
    if log:
        assert len(log.read_bytes().splitlines()) == 2


@pytest.mark.parametrize('limit', [True, False, 0, -1, 513, 1.0, '2', None])
def test_invalid_budget_fails_before_file_creation_or_socket_binding(tmp_path, monkeypatch, limit):
    log = tmp_path / 'receipts.jsonl'
    with pytest.raises(ValueError, match='max_decisions'):
        service.RuntimeDecisionApplication(runtime.RuntimePDP(), log, max_decisions=limit)
    monkeypatch.setattr(service, '_TCPHTTPServer', lambda *a, **kw: pytest.fail('socket bound'))
    with pytest.raises(ValueError, match='max_decisions'):
        service.serve_runtime(receipt_log=log, max_decisions=limit)
    assert not log.exists()


def test_concurrent_callers_cannot_overrun_last_budget_slot(tmp_path, monkeypatch):
    log = tmp_path / 'receipts.jsonl'
    app = service.RuntimeDecisionApplication(runtime.RuntimePDP(), log, max_decisions=1)
    monkeypatch.setattr(runtime, '_now', lambda: NOW)

    def run(index):
        try:
            return app.decide(json.dumps(request(app.pdp, index)).encode())
        except service.RuntimeDecisionExhausted:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, range(1, 9)))
    assert sum(result is not None for result in results) == 1
    assert app.pdp.receipt_count == 1
    assert len(log.read_bytes().splitlines()) == 1


def test_final_receipt_persistence_failure_takes_precedence_over_exhaustion(tmp_path, monkeypatch):
    app = service.RuntimeDecisionApplication(runtime.RuntimePDP(), tmp_path / 'log', max_decisions=1)
    monkeypatch.setattr(runtime, '_now', lambda: NOW)
    payload = json.dumps(request(app.pdp)).encode()
    with patch.object(service.os, 'fsync', side_effect=OSError('synthetic storage failure')):
        with pytest.raises(service.RuntimeDecisionUnavailable):
            app.decide(payload)
    assert app.readiness()['reason'] == 'receipt_log_failed'
    assert app.readiness()['decision_budget']['remaining'] == 0
    with pytest.raises(service.RuntimeDecisionUnavailable):
        app.decide(payload)


def test_used_engine_cannot_create_a_fresh_memory_only_application():
    pdp = runtime.RuntimePDP()
    pdp.decide(request(pdp), decided_at=NOW)
    with pytest.raises(ValueError, match='unused'):
        service.RuntimeDecisionApplication(pdp)
