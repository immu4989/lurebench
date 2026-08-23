"""Rebuild the deterministic, public LureEval v1 semantic conformance vectors."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from lurebench.conformance import SUITE_ID, SUITE_SCHEMA, SUITE_VERSION
from lurebench.receipts import (
    VerifiedReceipt,
    aggregate_receipts,
    canonical_json,
    create_receipt_statement,
    derive_metrics,
    dumps_artifact,
    sha256_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance" / "lureeval-v1"


def _receipt(marker: str, receipt_id: str, generated_at: str) -> Dict[str, Any]:
    confidence = 0.95
    confusion = {
        "true_positive": 18,
        "false_positive": 2,
        "true_negative": 18,
        "false_negative": 2,
    }
    return create_receipt_statement(
        producer_name="conformance-reference",
        producer_version="1.0.0",
        issuer="synthetic-conformance-fixture",
        sampling="consecutive_sample",
        labeling_protocol="full_blinded_review",
        confidence=confidence,
        minimum_slice_count=20,
        control={
            "detector": "reference-detector",
            "detector_artifact_sha256": "a" * 64,
            "threshold": 0.5,
            "policy_id": "reference-policy-v1",
            "policy_sha256": "b" * 64,
        },
        cohort={
            "source_type": "shadow_inbox",
            "run_generated_at": "2026-08-20T10:00:00-05:00",
            "processed_count": 40,
            "failed_count": 0,
            "latest_label_count": 40,
            "uncertain_label_count": 0,
            "evaluated_count": 40,
            "manifest_sha256": sha256_bytes(f"manifest-{marker}".encode()),
            "labels_sha256": sha256_bytes(f"labels-{marker}".encode()),
            "plan_id": "reference-plan-v1",
            "plan_sha256": "c" * 64,
            "gate_sha256": sha256_bytes(f"gate-{marker}".encode()),
        },
        outcome={
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
        },
        slices=[
            {"dimension": "risk_tier", "value": "high", "count": 20},
            {"dimension": "source_type", "value": "synthetic", "count": 40},
        ],
        suppressed_slice_count=1,
        cohort_sha256=sha256_bytes(f"cohort-{marker}".encode()),
        receipt_id=receipt_id,
        generated_at=generated_at,
    )


def _verified(statement: Dict[str, Any]) -> VerifiedReceipt:
    return VerifiedReceipt(
        statement=statement,
        statement_sha256=sha256_bytes(canonical_json(statement)),
        signed=False,
        authenticated=False,
        key_ids=(),
    )


def _render(value: Dict[str, Any]) -> bytes:
    return dumps_artifact(value).encode("utf-8")


def build() -> None:
    valid = OUTPUT / "valid"
    invalid = OUTPUT / "invalid"
    valid.mkdir(parents=True, exist_ok=True)
    invalid.mkdir(parents=True, exist_ok=True)

    site_a = _receipt(
        "site-a",
        "11111111-1111-4111-8111-111111111111",
        "2026-08-20T12:00:00-05:00",
    )
    site_b = _receipt(
        "site-b",
        "22222222-2222-4222-8222-222222222222",
        "2026-08-21T12:00:00-05:00",
    )
    aggregate = aggregate_receipts(
        [_verified(site_a), _verified(site_b)],
        producer_version="1.0.0",
        issuer="synthetic-conformance-aggregator",
        aggregate_id="33333333-3333-4333-8333-333333333333",
        generated_at="2026-08-22T12:00:00-05:00",
    )

    artifacts: Dict[str, bytes] = {
        "valid/receipt-site-a.json": _render(site_a),
        "valid/receipt-site-b.json": _render(site_b),
        "valid/aggregate.json": _render(aggregate),
    }

    metric_tamper = copy.deepcopy(site_a)
    metric_tamper["predicate"]["outcome"]["metrics"]["recall_estimate"] = 1.0
    artifacts["invalid/receipt-metric-tamper.json"] = _render(metric_tamper)

    privacy_field = copy.deepcopy(site_a)
    privacy_field["predicate"]["cohort"]["message_id"] = "forbidden"
    artifacts["invalid/receipt-privacy-field.json"] = _render(privacy_field)

    small_slice = copy.deepcopy(site_a)
    small_slice["predicate"]["slices"][0]["count"] = 19
    artifacts["invalid/receipt-small-slice.json"] = _render(small_slice)

    unknown_field = copy.deepcopy(site_a)
    unknown_field["predicate"]["notes"] = "free text is outside the protocol allowlist"
    artifacts["invalid/receipt-unknown-field.json"] = _render(unknown_field)

    wrong_predicate = copy.deepcopy(site_a)
    wrong_predicate["predicateType"] = "https://example.invalid/unsupported"
    artifacts["invalid/receipt-wrong-predicate.json"] = _render(wrong_predicate)

    pooled_metric = copy.deepcopy(aggregate)
    pooled_metric["predicate"]["pooled"]["metrics"]["false_positive_rate_estimate"] = 0.0
    artifacts["invalid/aggregate-metric-tamper.json"] = _render(pooled_metric)

    duplicate_point = copy.deepcopy(aggregate)
    duplicate_point["predicate"]["receipt_points"][1]["receipt_sha256"] = (
        duplicate_point["predicate"]["receipt_points"][0]["receipt_sha256"]
    )
    artifacts["invalid/aggregate-duplicate-point.json"] = _render(duplicate_point)

    valid_text = artifacts["valid/receipt-site-a.json"].decode("utf-8")
    duplicate_json = valid_text.replace(
        '  "_type": "https://in-toto.io/Statement/v1",',
        '  "_type": "https://in-toto.io/Statement/v1",\n'
        '  "_type": "https://in-toto.io/Statement/v1",',
        1,
    )
    artifacts["invalid/receipt-duplicate-json-key.json"] = duplicate_json.encode("utf-8")

    nonfinite = valid_text.replace('"threshold": 0.5', '"threshold": NaN', 1)
    artifacts["invalid/receipt-nonfinite-json.json"] = nonfinite.encode("utf-8")

    definitions = [
        ("valid-receipt-site-a", "valid/receipt-site-a.json", "accept", "receipt", "baseline", "Accept a valid privacy-minimized receipt."),
        ("valid-receipt-site-b", "valid/receipt-site-b.json", "accept", "receipt", "baseline", "Accept a second compatible private cohort."),
        ("valid-aggregate", "valid/aggregate.json", "accept", "aggregate", "baseline", "Accept a valid aggregate over two distinct compatible cohorts."),
        ("reject-receipt-metric-tamper", "invalid/receipt-metric-tamper.json", "reject", "receipt", "statistical-consistency", "Reject a recall estimate that does not match its confusion counts."),
        ("reject-receipt-privacy-field", "invalid/receipt-privacy-field.json", "reject", "receipt", "privacy-boundary", "Reject a message identifier outside the aggregate-only cohort allowlist."),
        ("reject-receipt-small-slice", "invalid/receipt-small-slice.json", "reject", "receipt", "privacy-boundary", "Reject a published slice below the declared minimum count."),
        ("reject-receipt-unknown-field", "invalid/receipt-unknown-field.json", "reject", "receipt", "schema-boundary", "Reject unregistered free text in the strict predicate."),
        ("reject-receipt-wrong-predicate", "invalid/receipt-wrong-predicate.json", "reject", "receipt", "schema-boundary", "Reject an artifact with an unsupported predicate type."),
        ("reject-aggregate-metric-tamper", "invalid/aggregate-metric-tamper.json", "reject", "aggregate", "statistical-consistency", "Reject pooled metrics inconsistent with pooled confusion counts."),
        ("reject-aggregate-duplicate-point", "invalid/aggregate-duplicate-point.json", "reject", "aggregate", "semantic-integrity", "Reject duplicate source receipt points in an aggregate."),
        ("reject-duplicate-json-key", "invalid/receipt-duplicate-json-key.json", "reject", "receipt", "serialization", "Reject ambiguous JSON containing a duplicate object key."),
        ("reject-nonfinite-json", "invalid/receipt-nonfinite-json.json", "reject", "receipt", "serialization", "Reject the non-standard NaN JSON constant."),
    ]

    for relative, payload in artifacts.items():
        target = OUTPUT / relative
        target.write_bytes(payload)

    cases = [
        {
            "case_id": case_id,
            "artifact": relative,
            "sha256": hashlib.sha256(artifacts[relative]).hexdigest(),
            "expected": expected,
            "kind": kind,
            "category": category,
            "description": description,
        }
        for case_id, relative, expected, kind, category, description in definitions
    ]
    suite = {
        "schema": SUITE_SCHEMA,
        "schema_version": 1,
        "suite_id": SUITE_ID,
        "suite_version": SUITE_VERSION,
        "protocol": "lureeval-v1",
        "description": (
            "Language-neutral semantic vectors for accepting valid LureEval v1 receipts and "
            "aggregates while rejecting privacy, schema, serialization, and metric tampering."
        ),
        "cases": cases,
    }
    (OUTPUT / "suite.json").write_text(
        json.dumps(suite, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    build()
