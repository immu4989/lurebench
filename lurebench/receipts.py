"""LureEval: privacy-minimized operational evaluation receipts.

The protocol moves aggregate detector measurements between organizations without
moving messages, case identifiers, or per-message scores.  A receipt is an
in-toto Statement and may be authenticated with a standard DSSE envelope.  The
aggregator fails closed unless every source uses the same detector artifact,
decision policy, threshold, review protocol, and confidence contract.

Signatures prove possession of the supplied private key.  Trust in the person or
organization behind that key remains an external verifier decision.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .calibration import clopper_pearson_upper

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/immu4989/lurebench/spec/lureeval-receipt/v1"
AGGREGATE_PREDICATE_TYPE = "https://github.com/immu4989/lurebench/spec/lureeval-aggregate/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
PROTOCOL_ID = "lureeval-private-operational-evaluation"
PROTOCOL_VERSION = "1.0"
METRICS_METHOD = "exact_binomial_one_sided_v1"
CONFIDENCE_SCOPE = "per_metric_one_sided_not_simultaneous"
MAX_RECEIPTS = 1_000
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_SLICES = 256

_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")
_SLICE_VALUE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,99}$")
_EXCLUDED_FIELDS = (
    "source_paths",
    "subjects",
    "addresses",
    "message_ids",
    "case_ids",
    "url_values",
    "attachment_names",
    "message_content",
    "raw_message_hashes",
    "per_message_scores",
)
_LIMITATIONS = (
    "representative_iid_sample_required",
    "label_quality_not_verified",
    "labeling_protocol_not_verified",
    "distribution_shift_not_covered",
    "per_metric_confidence_not_simultaneous_confidence",
    "cohort_overlap_not_detectable_across_distinct_commitments",
    "aggregate_receipts_are_not_differential_privacy",
    "signature_key_identity_requires_external_trust",
    "receipt_is_not_certification_or_authorization",
)


@dataclass(frozen=True)
class VerifiedReceipt:
    """A semantically verified receipt plus its authentication result."""

    statement: Dict[str, Any]
    statement_sha256: str
    signed: bool
    authenticated: bool
    key_ids: Tuple[str, ...]


def loads_strict_json(payload: bytes) -> Any:
    """Decode UTF-8 JSON while rejecting duplicate keys and non-finite constants."""

    def object_no_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    try:
        text = payload.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=object_no_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("artifact is not strict UTF-8 JSON") from exc


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return the deterministic JSON encoding committed to by LureEval."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, max_bytes: int = MAX_ARTIFACT_BYTES) -> str:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link artifact: {path}")
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path.name} exceeds the {max_bytes} byte safety limit")
    return sha256_bytes(path.read_bytes())


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed


def _object(
    value: Any,
    field: str,
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    required_set, optional_set = set(required), set(optional)
    keys = set(value)
    missing = required_set - keys
    extra = keys - required_set - optional_set
    if missing:
        raise ValueError(f"{field} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"{field} has unsupported fields: {', '.join(sorted(extra))}")
    return value


def _integer(value: Any, field: str, *, minimum: int = 0, maximum: int = 10**9) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}")
    return value


def _probability(value: Any, field: str, *, nullable: bool = False) -> Optional[float]:
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a probability")
    result = float(value)
    if not math.isfinite(result) or result < 0 or result > 1:
        raise ValueError(f"{field} must be finite and between zero and one")
    return result


def _digest(value: Any, field: str, *, nullable: bool = False) -> Optional[str]:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return value


def _safe_identifier(value: Any, field: str, *, nullable: bool = False) -> Optional[str]:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"{field} is not a safe identifier")
    return value


def _safe_label(value: Any, field: str, *, nullable: bool = False) -> Optional[str]:
    if value is None and nullable:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or any(character in value for character in "\r\n\t")
    ):
        raise ValueError(f"{field} must be 1-200 characters without control whitespace")
    return value


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 8) if denominator else None


def _clopper_pearson_lower(events: int, trials: int, confidence: float) -> Optional[float]:
    if not trials:
        return None
    if events == 0:
        return 0.0
    return round(1.0 - clopper_pearson_upper(trials - events, trials, confidence), 8)


def _clopper_pearson_upper_or_none(events: int, trials: int, confidence: float) -> Optional[float]:
    if not trials:
        return None
    return round(clopper_pearson_upper(events, trials, confidence), 8)


def derive_metrics(confusion: Mapping[str, int], confidence: float) -> Dict[str, Any]:
    """Derive all published metrics from four confusion counts."""

    tp = int(confusion["true_positive"])
    fp = int(confusion["false_positive"])
    tn = int(confusion["true_negative"])
    fn = int(confusion["false_negative"])
    fraud, benign, routed = tp + fn, fp + tn, tp + fp
    return {
        "recall_estimate": _ratio(tp, fraud),
        "recall_lower_bound": _clopper_pearson_lower(tp, fraud, confidence),
        "false_positive_rate_estimate": _ratio(fp, benign),
        "false_positive_rate_upper_bound": _clopper_pearson_upper_or_none(fp, benign, confidence),
        "precision_estimate": _ratio(tp, routed),
    }


def _validate_confusion(value: Any, field: str) -> Dict[str, int]:
    result = _object(
        value,
        field,
        required=("true_positive", "false_positive", "true_negative", "false_negative"),
    )
    for key in result:
        _integer(result[key], f"{field}.{key}")
    return {key: int(result[key]) for key in result}


def _validate_metrics(
    value: Any, field: str, confusion: Mapping[str, int], confidence: float
) -> None:
    metrics = _object(
        value,
        field,
        required=(
            "recall_estimate",
            "recall_lower_bound",
            "false_positive_rate_estimate",
            "false_positive_rate_upper_bound",
            "precision_estimate",
        ),
    )
    for key, item in metrics.items():
        _probability(item, f"{field}.{key}", nullable=True)
    if metrics != derive_metrics(confusion, confidence):
        raise ValueError(f"{field} does not match its confusion counts and confidence")


def _validate_subjects(value: Any, *, maximum: int = 4) -> None:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise ValueError(f"subject must contain between one and {maximum} entries")
    names: set[str] = set()
    for index, subject in enumerate(value):
        item = _object(subject, f"subject[{index}]", required=("name", "digest"))
        name = _safe_identifier(item["name"], f"subject[{index}].name")
        if name in names:
            raise ValueError("subject names must be unique")
        names.add(str(name))
        digests = _object(item["digest"], f"subject[{index}].digest", required=("sha256",))
        _digest(digests["sha256"], f"subject[{index}].digest.sha256")


def _validate_protocol(value: Any) -> Tuple[float, int]:
    protocol = _object(
        value,
        "predicate.protocol",
        required=(
            "id",
            "version",
            "sampling",
            "labeling_protocol",
            "metrics_method",
            "confidence",
            "confidence_scope",
            "minimum_slice_count",
        ),
    )
    if protocol["id"] != PROTOCOL_ID or protocol["version"] != PROTOCOL_VERSION:
        raise ValueError("unsupported LureEval protocol")
    if protocol["metrics_method"] != METRICS_METHOD:
        raise ValueError("unsupported LureEval metrics method")
    if protocol["confidence_scope"] != CONFIDENCE_SCOPE:
        raise ValueError("unsupported LureEval confidence scope")
    if protocol["sampling"] not in {
        "complete_population",
        "consecutive_sample",
        "random_sample",
        "operator_declared_other",
    }:
        raise ValueError("unsupported sampling declaration")
    _safe_identifier(protocol["labeling_protocol"], "predicate.protocol.labeling_protocol")
    confidence = _probability(protocol["confidence"], "predicate.protocol.confidence")
    assert confidence is not None
    if confidence < 0.8 or confidence > 0.999:
        raise ValueError("confidence must be between 0.8 and 0.999")
    minimum = _integer(
        protocol["minimum_slice_count"],
        "predicate.protocol.minimum_slice_count",
        minimum=10,
        maximum=10_000,
    )
    return confidence, minimum


def _validate_control(value: Any) -> None:
    control = _object(
        value,
        "predicate.control",
        required=(
            "detector",
            "detector_artifact_sha256",
            "threshold",
            "policy_id",
            "policy_sha256",
        ),
    )
    _safe_identifier(control["detector"], "predicate.control.detector")
    _digest(
        control["detector_artifact_sha256"],
        "predicate.control.detector_artifact_sha256",
        nullable=True,
    )
    _probability(control["threshold"], "predicate.control.threshold")
    _safe_identifier(control["policy_id"], "predicate.control.policy_id", nullable=True)
    _digest(control["policy_sha256"], "predicate.control.policy_sha256", nullable=True)
    if (control["policy_id"] is None) != (control["policy_sha256"] is None):
        raise ValueError("policy_id and policy_sha256 must both be present or both be null")


def _validate_cohort(value: Any) -> None:
    cohort = _object(
        value,
        "predicate.cohort",
        required=(
            "source_type",
            "run_generated_at",
            "processed_count",
            "failed_count",
            "latest_label_count",
            "uncertain_label_count",
            "evaluated_count",
            "manifest_sha256",
            "labels_sha256",
            "plan_id",
            "plan_sha256",
            "gate_sha256",
        ),
    )
    if cohort["source_type"] not in {"shadow_inbox", "microsoft_defender_export"}:
        raise ValueError("unsupported cohort source_type")
    _parse_timestamp(cohort["run_generated_at"], "predicate.cohort.run_generated_at")
    processed = _integer(
        cohort["processed_count"], "predicate.cohort.processed_count", maximum=10**7
    )
    _integer(cohort["failed_count"], "predicate.cohort.failed_count", maximum=10**7)
    labels = _integer(
        cohort["latest_label_count"],
        "predicate.cohort.latest_label_count",
        maximum=processed,
    )
    uncertain = _integer(
        cohort["uncertain_label_count"],
        "predicate.cohort.uncertain_label_count",
        maximum=labels,
    )
    evaluated = _integer(
        cohort["evaluated_count"], "predicate.cohort.evaluated_count", maximum=labels
    )
    if evaluated + uncertain != labels:
        raise ValueError("cohort evaluated and uncertain counts must equal latest labels")
    for key in ("manifest_sha256", "labels_sha256", "plan_sha256", "gate_sha256"):
        _digest(cohort[key], f"predicate.cohort.{key}")
    _safe_identifier(cohort["plan_id"], "predicate.cohort.plan_id")


def _validate_outcome(value: Any, confidence: float, cohort: Mapping[str, Any]) -> None:
    outcome = _object(
        value,
        "predicate.outcome",
        required=("confusion", "metrics", "routing", "resilience", "pilot_gate"),
    )
    confusion = _validate_confusion(outcome["confusion"], "predicate.outcome.confusion")
    if sum(confusion.values()) != cohort["evaluated_count"]:
        raise ValueError("confusion counts must equal cohort evaluated_count")
    _validate_metrics(outcome["metrics"], "predicate.outcome.metrics", confusion, confidence)
    routing = _object(
        outcome["routing"],
        "predicate.outcome.routing",
        required=("routed_count", "routed_rate"),
    )
    routed = _integer(
        routing["routed_count"],
        "predicate.outcome.routing.routed_count",
        maximum=cohort["processed_count"],
    )
    _probability(routing["routed_rate"], "predicate.outcome.routing.routed_rate", nullable=True)
    if routing["routed_rate"] != _ratio(routed, cohort["processed_count"]):
        raise ValueError("routing rate does not match routed and processed counts")
    resilience = _object(
        outcome["resilience"],
        "predicate.outcome.resilience",
        required=(
            "eligible_attack_count",
            "evasion_count",
            "defense_recovery_count",
            "evasion_rate",
            "recovery_rate_among_evasions",
        ),
    )
    eligible = _integer(
        resilience["eligible_attack_count"],
        "predicate.outcome.resilience.eligible_attack_count",
    )
    evasions = _integer(
        resilience["evasion_count"],
        "predicate.outcome.resilience.evasion_count",
        maximum=eligible,
    )
    recoveries = _integer(
        resilience["defense_recovery_count"],
        "predicate.outcome.resilience.defense_recovery_count",
        maximum=evasions,
    )
    if resilience["evasion_rate"] != _ratio(evasions, eligible):
        raise ValueError("resilience evasion_rate is inconsistent")
    if resilience["recovery_rate_among_evasions"] != _ratio(recoveries, evasions):
        raise ValueError("resilience recovery rate is inconsistent")
    gate = _object(
        outcome["pilot_gate"],
        "predicate.outcome.pilot_gate",
        required=("verdict", "failed_checks"),
    )
    if gate["verdict"] not in {"pass", "fail", "insufficient_evidence"}:
        raise ValueError("unsupported Pilot Gate verdict")
    if not isinstance(gate["failed_checks"], list) or any(
        not isinstance(item, str) or not _SAFE_ID.fullmatch(item) for item in gate["failed_checks"]
    ):
        raise ValueError("pilot_gate.failed_checks must contain safe identifiers")
    if len(gate["failed_checks"]) != len(set(gate["failed_checks"])):
        raise ValueError("pilot_gate.failed_checks must be unique")


def _validate_slices(value: Any, minimum: int, suppressed_count: int) -> None:
    if not isinstance(value, list) or len(value) > MAX_SLICES:
        raise ValueError(f"predicate.slices must contain at most {MAX_SLICES} entries")
    identities: set[Tuple[str, str]] = set()
    for index, raw in enumerate(value):
        item = _object(raw, f"predicate.slices[{index}]", required=("dimension", "value", "count"))
        if item["dimension"] not in {"source_type", "risk_tier", "evidence_code"}:
            raise ValueError("unsupported slice dimension")
        if not isinstance(item["value"], str) or not _SLICE_VALUE.fullmatch(item["value"]):
            raise ValueError(f"predicate.slices[{index}].value is not allowlisted text")
        count = _integer(item["count"], f"predicate.slices[{index}].count")
        if count < minimum:
            raise ValueError("published slice counts must meet minimum_slice_count")
        identity = (item["dimension"], item["value"])
        if identity in identities:
            raise ValueError("slice dimension/value pairs must be unique")
        identities.add(identity)
    if suppressed_count < 0:
        raise ValueError("suppressed_slice_count cannot be negative")


def validate_receipt_statement(statement: Mapping[str, Any]) -> None:
    """Strictly validate one LureEval receipt statement and all derived values."""

    root = _object(
        statement,
        "statement",
        required=("_type", "subject", "predicateType", "predicate"),
    )
    if root["_type"] != STATEMENT_TYPE or root["predicateType"] != PREDICATE_TYPE:
        raise ValueError("artifact is not a LureEval receipt v1 statement")
    _validate_subjects(root["subject"])
    predicate = _object(
        root["predicate"],
        "predicate",
        required=(
            "spec",
            "spec_version",
            "receipt_id",
            "generated_at",
            "producer",
            "privacy",
            "protocol",
            "control",
            "cohort",
            "outcome",
            "slices",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if predicate["spec"] != "lureeval" or predicate["spec_version"] != PROTOCOL_VERSION:
        raise ValueError("unsupported receipt spec")
    try:
        parsed_id = uuid.UUID(str(predicate["receipt_id"]))
    except ValueError as exc:
        raise ValueError("predicate.receipt_id must be a UUID") from exc
    if str(parsed_id) != predicate["receipt_id"]:
        raise ValueError("predicate.receipt_id must use canonical lowercase UUID syntax")
    generated_at = _parse_timestamp(predicate["generated_at"], "predicate.generated_at")
    producer = _object(
        predicate["producer"],
        "predicate.producer",
        required=("name", "version", "issuer"),
    )
    _safe_identifier(producer["name"], "predicate.producer.name")
    _safe_identifier(producer["version"], "predicate.producer.version")
    _safe_label(producer["issuer"], "predicate.producer.issuer", nullable=True)
    privacy = _object(
        predicate["privacy"],
        "predicate.privacy",
        required=("aggregate_only", "excluded_fields", "suppressed_slice_count"),
    )
    if privacy["aggregate_only"] is not True or privacy["excluded_fields"] != list(
        _EXCLUDED_FIELDS
    ):
        raise ValueError("receipt privacy boundary is not the LureEval v1 allowlist")
    suppressed = _integer(
        privacy["suppressed_slice_count"], "predicate.privacy.suppressed_slice_count"
    )
    confidence, minimum = _validate_protocol(predicate["protocol"])
    _validate_control(predicate["control"])
    _validate_cohort(predicate["cohort"])
    if generated_at < _parse_timestamp(
        predicate["cohort"]["run_generated_at"], "predicate.cohort.run_generated_at"
    ):
        raise ValueError("receipt cannot predate its source run")
    _validate_outcome(predicate["outcome"], confidence, predicate["cohort"])
    _validate_slices(predicate["slices"], minimum, suppressed)
    if predicate["limitations"] != list(_LIMITATIONS):
        raise ValueError("receipt limitations are not the LureEval v1 boundary")
    boundary = predicate["interpretation_boundary"]
    if not isinstance(boundary, str) or not 20 <= len(boundary) <= 500:
        raise ValueError("interpretation_boundary must be 20-500 characters")


def create_receipt_statement(
    *,
    producer_name: str,
    producer_version: str,
    issuer: Optional[str],
    sampling: str,
    labeling_protocol: str,
    confidence: float,
    minimum_slice_count: int,
    control: Mapping[str, Any],
    cohort: Mapping[str, Any],
    outcome: Mapping[str, Any],
    slices: Sequence[Mapping[str, Any]],
    suppressed_slice_count: int,
    cohort_sha256: str,
    receipt_id: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Create and semantically verify one deterministic-shape receipt statement."""

    statement: Dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "private-evaluation-cohort", "digest": {"sha256": cohort_sha256}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "spec": "lureeval",
            "spec_version": PROTOCOL_VERSION,
            "receipt_id": receipt_id or str(uuid.uuid4()),
            "generated_at": generated_at or _timestamp(),
            "producer": {
                "name": producer_name,
                "version": producer_version,
                "issuer": issuer,
            },
            "privacy": {
                "aggregate_only": True,
                "excluded_fields": list(_EXCLUDED_FIELDS),
                "suppressed_slice_count": suppressed_slice_count,
            },
            "protocol": {
                "id": PROTOCOL_ID,
                "version": PROTOCOL_VERSION,
                "sampling": sampling,
                "labeling_protocol": labeling_protocol,
                "metrics_method": METRICS_METHOD,
                "confidence": confidence,
                "confidence_scope": CONFIDENCE_SCOPE,
                "minimum_slice_count": minimum_slice_count,
            },
            "control": dict(control),
            "cohort": dict(cohort),
            "outcome": dict(outcome),
            "slices": [dict(item) for item in slices],
            "limitations": list(_LIMITATIONS),
            "interpretation_boundary": (
                "This receipt reports aggregate measurements for one declared cohort. "
                "It is not certification, proof of safety, or authorization for enforcement."
            ),
        },
    }
    validate_receipt_statement(statement)
    return statement


def _pae(payload_type: bytes, payload: bytes) -> bytes:
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _cryptography():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:
        raise RuntimeError(
            "signed LureEval artifacts require: pip install 'lurebench[receipts]'"
        ) from exc
    return InvalidSignature, hashes, serialization, ec


def sign_statement(statement: Mapping[str, Any], private_key_pem: bytes) -> Dict[str, Any]:
    """Wrap a verified receipt or aggregate statement in a P-256 DSSE envelope."""

    if statement.get("predicateType") == PREDICATE_TYPE:
        validate_receipt_statement(statement)
    else:
        validate_aggregate_statement(statement)
    _, hashes, serialization, ec = _cryptography()
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("LureEval signing requires an ECDSA P-256 private key")
    payload = canonical_json(statement)
    payload_type = DSSE_PAYLOAD_TYPE.encode("utf-8")
    signature = key.sign(_pae(payload_type, payload), ec.ECDSA(hashes.SHA256()))
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": sha256_bytes(public_der),
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }


def _decode_envelope(value: Mapping[str, Any]) -> Tuple[bytes, List[Dict[str, str]]]:
    envelope = _object(
        value,
        "DSSE envelope",
        required=("payloadType", "payload", "signatures"),
    )
    if envelope["payloadType"] != DSSE_PAYLOAD_TYPE:
        raise ValueError("unsupported DSSE payloadType")
    if not isinstance(envelope["signatures"], list) or not 1 <= len(envelope["signatures"]) <= 16:
        raise ValueError("DSSE signatures must contain between one and sixteen entries")
    signatures: List[Dict[str, str]] = []
    for index, raw in enumerate(envelope["signatures"]):
        item = _object(raw, f"signatures[{index}]", required=("keyid", "sig"))
        _digest(item["keyid"], f"signatures[{index}].keyid")
        if not isinstance(item["sig"], str) or len(item["sig"]) > 1024:
            raise ValueError(f"signatures[{index}].sig is invalid")
        signatures.append({"keyid": item["keyid"], "sig": item["sig"]})
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("DSSE payload must be valid base64") from exc
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ValueError("decoded DSSE payload exceeds the safety limit")
    return payload, signatures


def _verify_signatures(
    payload: bytes, signatures: Sequence[Mapping[str, str]], public_key_pem: bytes
) -> Tuple[str, ...]:
    InvalidSignature, hashes, serialization, ec = _cryptography()
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("LureEval verification requires an ECDSA P-256 public key")
    public_der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected_keyid = sha256_bytes(public_der)
    verified: List[str] = []
    message = _pae(DSSE_PAYLOAD_TYPE.encode("utf-8"), payload)
    for item in signatures:
        if not secrets.compare_digest(item["keyid"], expected_keyid):
            continue
        try:
            signature = base64.b64decode(item["sig"], validate=True)
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except (ValueError, binascii.Error, InvalidSignature):
            continue
        verified.append(item["keyid"])
    if not verified:
        raise ValueError("no DSSE signature verifies with the supplied public key")
    return tuple(sorted(set(verified)))


def load_verified_artifact(
    path: Path,
    *,
    public_key_pem: Optional[bytes] = None,
    require_signature: bool = False,
) -> VerifiedReceipt:
    """Load a bounded receipt/aggregate, validate it, and optionally authenticate it."""

    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link LureEval artifact: {path}")
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("LureEval artifact exceeds the 8 MiB safety limit")
    artifact = loads_strict_json(path.read_bytes())
    if not isinstance(artifact, dict):
        raise ValueError("LureEval artifact must contain a JSON object")

    signed = set(artifact) == {"payloadType", "payload", "signatures"}
    key_ids: Tuple[str, ...] = ()
    if signed:
        payload, signatures = _decode_envelope(artifact)
        statement = loads_strict_json(payload)
        if canonical_json(statement) != payload:
            raise ValueError("DSSE payload is not canonical LureEval JSON")
        if public_key_pem is not None:
            key_ids = _verify_signatures(payload, signatures, public_key_pem)
    else:
        statement = artifact
    if require_signature and not signed:
        raise ValueError("a signed DSSE artifact is required")
    if require_signature and public_key_pem is None:
        raise ValueError("--require-signature requires a trusted public key")
    if not isinstance(statement, dict):
        raise ValueError("LureEval statement must be a JSON object")
    if statement.get("predicateType") == PREDICATE_TYPE:
        validate_receipt_statement(statement)
    elif statement.get("predicateType") == AGGREGATE_PREDICATE_TYPE:
        validate_aggregate_statement(statement)
    else:
        raise ValueError("unsupported LureEval predicate type")
    canonical = canonical_json(statement)
    return VerifiedReceipt(
        statement=statement,
        statement_sha256=sha256_bytes(canonical),
        signed=signed,
        authenticated=bool(key_ids),
        key_ids=key_ids,
    )


def _compatibility_key(statement: Mapping[str, Any]) -> bytes:
    predicate = statement["predicate"]
    protocol = predicate["protocol"]
    return canonical_json(
        {
            "protocol": {
                key: protocol[key]
                for key in (
                    "id",
                    "version",
                    "sampling",
                    "labeling_protocol",
                    "metrics_method",
                    "confidence",
                    "confidence_scope",
                    "minimum_slice_count",
                )
            },
            "control": predicate["control"],
            "decision_boundary": predicate["interpretation_boundary"],
        }
    )


def _pooled_slices(
    receipts: Sequence[VerifiedReceipt], minimum: int
) -> Tuple[List[Dict[str, Any]], int]:
    counts: Dict[Tuple[str, str], int] = {}
    for receipt in receipts:
        for item in receipt.statement["predicate"]["slices"]:
            key = (item["dimension"], item["value"])
            counts[key] = counts.get(key, 0) + int(item["count"])
    published = [
        {"dimension": key[0], "value": key[1], "count": count}
        for key, count in sorted(counts.items())
        if count >= minimum
    ]
    suppressed = sum(count < minimum for count in counts.values())
    return published, suppressed


def aggregate_receipts(
    receipts: Sequence[VerifiedReceipt],
    *,
    producer_version: str,
    issuer: Optional[str] = None,
    require_authenticated_sources: bool = False,
    aggregate_id: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Pool compatible receipt counts and emit a separately verifiable statement."""

    if not 2 <= len(receipts) <= MAX_RECEIPTS:
        raise ValueError(f"aggregation requires between 2 and {MAX_RECEIPTS} receipts")
    for receipt in receipts:
        validate_receipt_statement(receipt.statement)
        if require_authenticated_sources and not receipt.authenticated:
            raise ValueError("every source receipt must authenticate with its trusted public key")
    compatibility = _compatibility_key(receipts[0].statement)
    if any(_compatibility_key(item.statement) != compatibility for item in receipts[1:]):
        raise ValueError(
            "receipts are incompatible: protocol, sampling, review, confidence, control, "
            "or decision boundary differs"
        )
    cohort_digests = [item.statement["subject"][0]["digest"]["sha256"] for item in receipts]
    if len(cohort_digests) != len(set(cohort_digests)):
        raise ValueError("duplicate private cohort commitment; refusing to double count")
    receipt_digests = [item.statement_sha256 for item in receipts]
    if len(receipt_digests) != len(set(receipt_digests)):
        raise ValueError("duplicate receipt statement; refusing to double count")

    first = receipts[0].statement["predicate"]
    confusion = {
        key: sum(int(item.statement["predicate"]["outcome"]["confusion"][key]) for item in receipts)
        for key in ("true_positive", "false_positive", "true_negative", "false_negative")
    }
    confidence = float(first["protocol"]["confidence"])
    processed = sum(
        int(item.statement["predicate"]["cohort"]["processed_count"]) for item in receipts
    )
    routed = sum(
        int(item.statement["predicate"]["outcome"]["routing"]["routed_count"]) for item in receipts
    )
    resilience_counts = {
        key: sum(
            int(item.statement["predicate"]["outcome"]["resilience"][key]) for item in receipts
        )
        for key in ("eligible_attack_count", "evasion_count", "defense_recovery_count")
    }
    slices, suppressed = _pooled_slices(receipts, int(first["protocol"]["minimum_slice_count"]))
    receipt_points = [
        {
            "receipt_sha256": item.statement_sha256,
            "recall_estimate": item.statement["predicate"]["outcome"]["metrics"]["recall_estimate"],
            "false_positive_rate_estimate": item.statement["predicate"]["outcome"]["metrics"][
                "false_positive_rate_estimate"
            ],
        }
        for item in receipts
    ]
    statement: Dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": f"lureeval-receipt-{index + 1}", "digest": {"sha256": digest}}
            for index, digest in enumerate(sorted(receipt_digests))
        ],
        "predicateType": AGGREGATE_PREDICATE_TYPE,
        "predicate": {
            "spec": "lureeval-aggregate",
            "spec_version": PROTOCOL_VERSION,
            "aggregate_id": aggregate_id or str(uuid.uuid4()),
            "generated_at": generated_at or _timestamp(),
            "producer": {
                "name": "lurebench",
                "version": producer_version,
                "issuer": issuer,
            },
            "source_receipt_count": len(receipts),
            "authenticated_source_count": sum(item.authenticated for item in receipts),
            "source_authentication_required": require_authenticated_sources,
            "protocol": dict(first["protocol"]),
            "control": dict(first["control"]),
            "pooled": {
                "processed_count": processed,
                "confusion": confusion,
                "metrics": derive_metrics(confusion, confidence),
                "routing": {
                    "routed_count": routed,
                    "routed_rate": _ratio(routed, processed),
                },
                "resilience": {
                    **resilience_counts,
                    "evasion_rate": _ratio(
                        resilience_counts["evasion_count"],
                        resilience_counts["eligible_attack_count"],
                    ),
                    "recovery_rate_among_evasions": _ratio(
                        resilience_counts["defense_recovery_count"],
                        resilience_counts["evasion_count"],
                    ),
                },
            },
            "slices": slices,
            "suppressed_slice_count": suppressed,
            "receipt_points": receipt_points,
            "limitations": list(_LIMITATIONS),
            "interpretation_boundary": (
                "Pooled counts summarize compatible declared cohorts. They do not prove "
                "representativeness, independence, issuer identity, or future performance."
            ),
        },
    }
    validate_aggregate_statement(statement)
    return statement


def validate_aggregate_statement(statement: Mapping[str, Any]) -> None:
    """Strictly validate a LureEval aggregate and recompute all pooled metrics."""

    root = _object(
        statement,
        "statement",
        required=("_type", "subject", "predicateType", "predicate"),
    )
    if root["_type"] != STATEMENT_TYPE or root["predicateType"] != AGGREGATE_PREDICATE_TYPE:
        raise ValueError("artifact is not a LureEval aggregate v1 statement")
    _validate_subjects(root["subject"], maximum=MAX_RECEIPTS)
    predicate = _object(
        root["predicate"],
        "predicate",
        required=(
            "spec",
            "spec_version",
            "aggregate_id",
            "generated_at",
            "producer",
            "source_receipt_count",
            "authenticated_source_count",
            "source_authentication_required",
            "protocol",
            "control",
            "pooled",
            "slices",
            "suppressed_slice_count",
            "receipt_points",
            "limitations",
            "interpretation_boundary",
        ),
    )
    if predicate["spec"] != "lureeval-aggregate" or predicate["spec_version"] != PROTOCOL_VERSION:
        raise ValueError("unsupported aggregate spec")
    try:
        parsed_id = uuid.UUID(str(predicate["aggregate_id"]))
    except ValueError as exc:
        raise ValueError("predicate.aggregate_id must be a UUID") from exc
    if str(parsed_id) != predicate["aggregate_id"]:
        raise ValueError("predicate.aggregate_id must use canonical lowercase UUID syntax")
    _parse_timestamp(predicate["generated_at"], "predicate.generated_at")
    producer = _object(
        predicate["producer"],
        "predicate.producer",
        required=("name", "version", "issuer"),
    )
    if producer["name"] != "lurebench":
        raise ValueError("aggregate producer must be lurebench")
    _safe_identifier(producer["version"], "predicate.producer.version")
    _safe_label(producer["issuer"], "predicate.producer.issuer", nullable=True)
    source_count = _integer(
        predicate["source_receipt_count"],
        "predicate.source_receipt_count",
        minimum=2,
        maximum=MAX_RECEIPTS,
    )
    if len(root["subject"]) != source_count:
        raise ValueError("aggregate subjects must bind every source receipt")
    authenticated = _integer(
        predicate["authenticated_source_count"],
        "predicate.authenticated_source_count",
        maximum=source_count,
    )
    if not isinstance(predicate["source_authentication_required"], bool):
        raise ValueError("source_authentication_required must be boolean")
    if predicate["source_authentication_required"] and authenticated != source_count:
        raise ValueError("required source authentication is incomplete")
    confidence, minimum = _validate_protocol(predicate["protocol"])
    _validate_control(predicate["control"])
    pooled = _object(
        predicate["pooled"],
        "predicate.pooled",
        required=("processed_count", "confusion", "metrics", "routing", "resilience"),
    )
    processed = _integer(pooled["processed_count"], "predicate.pooled.processed_count")
    confusion = _validate_confusion(pooled["confusion"], "predicate.pooled.confusion")
    if sum(confusion.values()) > processed:
        raise ValueError("pooled evaluated count cannot exceed processed_count")
    _validate_metrics(pooled["metrics"], "predicate.pooled.metrics", confusion, confidence)
    routing = _object(
        pooled["routing"],
        "predicate.pooled.routing",
        required=("routed_count", "routed_rate"),
    )
    routed = _integer(
        routing["routed_count"], "predicate.pooled.routing.routed_count", maximum=processed
    )
    if routing["routed_rate"] != _ratio(routed, processed):
        raise ValueError("pooled routed_rate is inconsistent")
    resilience = _object(
        pooled["resilience"],
        "predicate.pooled.resilience",
        required=(
            "eligible_attack_count",
            "evasion_count",
            "defense_recovery_count",
            "evasion_rate",
            "recovery_rate_among_evasions",
        ),
    )
    eligible = _integer(
        resilience["eligible_attack_count"],
        "predicate.pooled.resilience.eligible_attack_count",
    )
    evasions = _integer(
        resilience["evasion_count"],
        "predicate.pooled.resilience.evasion_count",
        maximum=eligible,
    )
    recoveries = _integer(
        resilience["defense_recovery_count"],
        "predicate.pooled.resilience.defense_recovery_count",
        maximum=evasions,
    )
    if resilience["evasion_rate"] != _ratio(evasions, eligible):
        raise ValueError("pooled evasion_rate is inconsistent")
    if resilience["recovery_rate_among_evasions"] != _ratio(recoveries, evasions):
        raise ValueError("pooled recovery rate is inconsistent")
    suppressed = _integer(predicate["suppressed_slice_count"], "predicate.suppressed_slice_count")
    _validate_slices(predicate["slices"], minimum, suppressed)
    points = predicate["receipt_points"]
    if not isinstance(points, list) or len(points) != source_count:
        raise ValueError("receipt_points must contain one entry per source receipt")
    point_digests: set[str] = set()
    for index, raw in enumerate(points):
        point = _object(
            raw,
            f"predicate.receipt_points[{index}]",
            required=(
                "receipt_sha256",
                "recall_estimate",
                "false_positive_rate_estimate",
            ),
        )
        digest = _digest(
            point["receipt_sha256"], f"predicate.receipt_points[{index}].receipt_sha256"
        )
        if digest in point_digests:
            raise ValueError("receipt_points contains a duplicate receipt")
        point_digests.add(str(digest))
        _probability(
            point["recall_estimate"],
            f"predicate.receipt_points[{index}].recall_estimate",
            nullable=True,
        )
        _probability(
            point["false_positive_rate_estimate"],
            f"predicate.receipt_points[{index}].false_positive_rate_estimate",
            nullable=True,
        )
    subject_digests = {item["digest"]["sha256"] for item in root["subject"]}
    if point_digests != subject_digests:
        raise ValueError("receipt_points and aggregate subjects bind different receipts")
    if predicate["limitations"] != list(_LIMITATIONS):
        raise ValueError("aggregate limitations are not the LureEval v1 boundary")
    boundary = predicate["interpretation_boundary"]
    if not isinstance(boundary, str) or not 20 <= len(boundary) <= 500:
        raise ValueError("interpretation_boundary must be 20-500 characters")


def dumps_artifact(value: Mapping[str, Any], *, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    return canonical_json(value).decode("utf-8")
