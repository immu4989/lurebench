from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.receipts import (
    aggregate_receipts,
    create_receipt_statement,
    derive_metrics,
    dumps_artifact,
    load_verified_artifact,
    sha256_bytes,
    sign_statement,
    validate_aggregate_statement,
    validate_receipt_statement,
)


def _receipt(
    cohort_marker: str,
    *,
    threshold: float = 0.5,
    receipt_id: str = "11111111-1111-4111-8111-111111111111",
    generated_at: str = "2026-08-20T12:00:00-05:00",
) -> dict:
    confidence = 0.95
    confusion = {
        "true_positive": 18,
        "false_positive": 2,
        "true_negative": 18,
        "false_negative": 2,
    }
    control = {
        "detector": "tfidf-logreg",
        "detector_artifact_sha256": "a" * 64,
        "threshold": threshold,
        "policy_id": "tfidf-production-v1",
        "policy_sha256": "b" * 64,
    }
    cohort = {
        "source_type": "shadow_inbox",
        "run_generated_at": "2026-08-20T10:00:00-05:00",
        "processed_count": 40,
        "failed_count": 0,
        "latest_label_count": 40,
        "uncertain_label_count": 0,
        "evaluated_count": 40,
        "manifest_sha256": sha256_bytes(f"manifest-{cohort_marker}".encode()),
        "labels_sha256": sha256_bytes(f"labels-{cohort_marker}".encode()),
        "plan_id": "private-pilot",
        "plan_sha256": "c" * 64,
        "gate_sha256": sha256_bytes(f"gate-{cohort_marker}".encode()),
    }
    outcome = {
        "confusion": confusion,
        "metrics": derive_metrics(confusion, confidence),
        "routing": {"routed_count": 20, "routed_rate": 0.5},
        "resilience": {
            "eligible_attack_count": 80,
            "evasion_count": 8,
            "defense_recovery_count": 6,
            "evasion_rate": 0.1,
            "recovery_rate_among_evasions": 0.75,
        },
        "pilot_gate": {"verdict": "pass", "failed_checks": []},
    }
    return create_receipt_statement(
        producer_name="lurescope",
        producer_version="0.9.0",
        issuer="Example SOC",
        sampling="consecutive_sample",
        labeling_protocol="full_blinded_review",
        confidence=confidence,
        minimum_slice_count=20,
        control=control,
        cohort=cohort,
        outcome=outcome,
        slices=[
            {"dimension": "risk_tier", "value": "high", "count": 20},
            {"dimension": "source_type", "value": "eml", "count": 40},
        ],
        suppressed_slice_count=2,
        cohort_sha256=sha256_bytes(f"cohort-{cohort_marker}".encode()),
        receipt_id=receipt_id,
        generated_at=generated_at,
    )


def test_receipt_recomputes_metrics_and_enforces_privacy_boundary():
    receipt = _receipt("alpha")
    validate_receipt_statement(receipt)

    tampered = copy.deepcopy(receipt)
    tampered["predicate"]["outcome"]["metrics"]["recall_estimate"] = 1.0
    with pytest.raises(ValueError, match="does not match"):
        validate_receipt_statement(tampered)

    extra = copy.deepcopy(receipt)
    extra["predicate"]["cohort"]["message_id"] = "forbidden"
    with pytest.raises(ValueError, match="unsupported fields"):
        validate_receipt_statement(extra)


def test_receipt_refuses_small_published_slice():
    receipt = _receipt("alpha")
    receipt["predicate"]["slices"][0]["count"] = 19
    with pytest.raises(ValueError, match="minimum_slice_count"):
        validate_receipt_statement(receipt)


def test_aggregate_pools_only_compatible_distinct_cohorts(tmp_path: Path):
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first_path.write_text(dumps_artifact(_receipt("alpha")), encoding="utf-8")
    second_path.write_text(
        dumps_artifact(
            _receipt(
                "beta",
                receipt_id="22222222-2222-4222-8222-222222222222",
                generated_at="2026-08-21T12:00:00-05:00",
            )
        ),
        encoding="utf-8",
    )
    receipts = [load_verified_artifact(first_path), load_verified_artifact(second_path)]
    aggregate = aggregate_receipts(
        receipts,
        producer_version="1.0.0",
        aggregate_id="33333333-3333-4333-8333-333333333333",
        generated_at="2026-08-22T12:00:00-05:00",
    )
    validate_aggregate_statement(aggregate)
    pooled = aggregate["predicate"]["pooled"]
    assert pooled["processed_count"] == 80
    assert pooled["confusion"] == {
        "true_positive": 36,
        "false_positive": 4,
        "true_negative": 36,
        "false_negative": 4,
    }
    assert pooled["metrics"]["recall_estimate"] == 0.9
    assert pooled["routing"] == {"routed_count": 40, "routed_rate": 0.5}
    assert aggregate["predicate"]["source_receipt_count"] == 2
    assert aggregate["predicate"]["authenticated_source_count"] == 0


def test_aggregate_refuses_duplicates_and_incompatible_controls(tmp_path: Path):
    path = tmp_path / "receipt.json"
    path.write_text(dumps_artifact(_receipt("alpha")), encoding="utf-8")
    verified = load_verified_artifact(path)
    with pytest.raises(ValueError, match="duplicate private cohort|duplicate receipt"):
        aggregate_receipts([verified, verified], producer_version="1.0.0")

    incompatible_path = tmp_path / "other.json"
    incompatible_path.write_text(
        dumps_artifact(
            _receipt(
                "beta",
                threshold=0.6,
                receipt_id="22222222-2222-4222-8222-222222222222",
            )
        ),
        encoding="utf-8",
    )
    incompatible = load_verified_artifact(incompatible_path)
    with pytest.raises(ValueError, match="incompatible"):
        aggregate_receipts([verified, incompatible], producer_version="1.0.0")


def test_dsse_authentication_and_tamper_detection(tmp_path: Path):
    cryptography = pytest.importorskip("cryptography")
    assert cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    envelope = sign_statement(_receipt("alpha"), private_pem)
    path = tmp_path / "receipt.dsse.json"
    path.write_text(dumps_artifact(envelope), encoding="utf-8")
    verified = load_verified_artifact(path, public_key_pem=public_pem, require_signature=True)
    assert verified.signed is True
    assert verified.authenticated is True
    assert len(verified.key_ids) == 1

    envelope["signatures"][0]["sig"] = "AAAA"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="no DSSE signature"):
        load_verified_artifact(path, public_key_pem=public_pem, require_signature=True)


def test_receipt_and_aggregate_match_published_json_schemas(tmp_path: Path):
    receipt_schema = json.loads(
        Path("spec/lureeval-receipt-v1.schema.json").read_text(encoding="utf-8")
    )
    aggregate_schema = json.loads(
        Path("spec/lureeval-aggregate-v1.schema.json").read_text(encoding="utf-8")
    )
    registry = Registry().with_resources(
        [
            (receipt_schema["$id"], Resource.from_contents(receipt_schema)),
            (aggregate_schema["$id"], Resource.from_contents(aggregate_schema)),
        ]
    )
    receipt = _receipt("alpha")
    Draft202012Validator(
        receipt_schema,
        registry=registry,
        format_checker=FormatChecker(),
    ).validate(receipt)

    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first_path.write_text(dumps_artifact(receipt), encoding="utf-8")
    second_path.write_text(
        dumps_artifact(
            _receipt(
                "beta",
                receipt_id="22222222-2222-4222-8222-222222222222",
                generated_at="2026-08-21T12:00:00-05:00",
            )
        ),
        encoding="utf-8",
    )
    aggregate = aggregate_receipts(
        [load_verified_artifact(first_path), load_verified_artifact(second_path)],
        producer_version="1.0.0",
        aggregate_id="33333333-3333-4333-8333-333333333333",
        generated_at="2026-08-22T12:00:00-05:00",
    )
    Draft202012Validator(
        aggregate_schema,
        registry=registry,
        format_checker=FormatChecker(),
    ).validate(aggregate)
