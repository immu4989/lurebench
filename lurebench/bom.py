"""Cross-standard AI-BOM reconciliation for deployed LureArtifact workloads.

LureBOM Twin projects a deliberately small common denominator from one
CycloneDX 1.7 JSON BOM and one SPDX 3.0.1 JSON-LD BOM.  It compares explicit
component mappings, SHA-256 values, Package URLs, and directed dependency
edges.  Every ignored field is surfaced as projection loss; this module is not
a general-purpose conformance validator for either source standard.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .artifact import validate_artifact_plan
from .permit import _canonical, _exact, _identifier, _timestamp
from .receipts import loads_strict_json

MANIFEST_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurebom-manifest-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurebom-evaluation-v1"
CYCLONEDX_FORMAT = "cyclonedx-1.7"
SPDX_FORMAT = "spdx-3.0.1"
SPDX_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
VERSION = "1.0.0"

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_COMPONENTS = 8192
MAX_RELATIONSHIPS = 32768
MAX_IGNORED_FIELDS = 65536
MAX_FINDINGS = 65536

KINDS = {"container", "dataset", "model", "package", "policy", "runtime"}
ROLE_KIND = {
    "container_image": "container",
    "model_weights": "model",
    "policy_bundle": "policy",
}
SPDX_PACKAGE_TYPES = {"ai_AIPackage", "dataset_DatasetPackage", "software_Package"}
CYCLONEDX_COMPONENT_TYPES = {
    "application",
    "container",
    "cryptographic-asset",
    "data",
    "device",
    "device-driver",
    "file",
    "firmware",
    "framework",
    "library",
    "machine-learning-model",
    "operating-system",
    "platform",
}
PROJECTION_COVERAGE = {
    "component_fields": ["source_class", "source_ref", "sha256", "package_url"],
    "relationship_types": ["depends_on"],
}
POLICY = {
    "require_all_components_mapped": True,
    "require_artifact_subject_coverage": True,
    "require_sha256_parity": True,
    "require_package_url_parity": True,
    "require_dependency_parity": True,
}
MANIFEST_LIMITATIONS = [
    "component_identity_is_explicitly_reviewed_and_never_inferred_from_names_or_versions",
    "only_sha256_package_url_component_class_and_directed_dependson_edges_are_compared",
    "the_primary_bom_digest_is_bound_to_lureartifact_while_the_mirror_digest_is_manifest_bound",
    "the_manifest_does_not_authenticate_bom_issuers_or_establish_source_document_conformance",
]
EVALUATION_LIMITATIONS = [
    "projection_loss_lists_ignored_fields_but_does_not_interpret_their_semantics",
    "source_documents_are_strictly_parsed_but_not_fully_validated_against_official_schemas",
    "matching_metadata_does_not_establish_bom_completeness_authenticity_freshness_or_truth",
    "no_artifact_model_container_policy_dataset_package_or_external_reference_is_opened",
    "a_pass_is_not_vulnerability_license_safety_compliance_procurement_or_deployment_approval",
]


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _bounded_list(value: Any, field: str, maximum: int, *, allow_empty: bool = False) -> list[Any]:
    minimum = 0 if allow_empty else 1
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        qualifier = "bounded" if allow_empty else "non-empty bounded"
        raise ValueError(f"{field} must be a {qualifier} array")
    return value


def _source_ref(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 2048
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{field} must be a bounded reference without whitespace or controls")
    return value


def _package_url(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not 5 <= len(value) <= 2048
        or not value.startswith("pkg:")
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{field} must be null or a bounded Package URL")
    return value


def _kind(value: Any, field: str) -> str:
    if not isinstance(value, str) or value not in KINDS:
        raise ValueError(f"{field} is unsupported")
    return value


def _ignored_add(paths: set[str], path: str) -> None:
    paths.add(path)
    if len(paths) > MAX_IGNORED_FIELDS:
        raise ValueError("source document has too many ignored field paths")


def _unknown_keys(paths: set[str], value: Mapping[str, Any], used: set[str], path: str) -> None:
    for key in value:
        if key not in used:
            _ignored_add(paths, f"{path}.{key}")


def _sha256_from_hashes(
    value: Any,
    field: str,
    *,
    cyclonedx: bool,
    ignored: Optional[set[str]] = None,
) -> str:
    hashes = _bounded_list(value, field, 32)
    matches: list[str] = []
    for index, raw in enumerate(hashes):
        if not isinstance(raw, dict):
            raise ValueError(f"{field}[{index}] must be an object")
        algorithm_key = "alg" if cyclonedx else "algorithm"
        digest_key = "content" if cyclonedx else "hashValue"
        algorithm = raw.get(algorithm_key)
        expected_algorithm = "SHA-256" if cyclonedx else "sha256"
        if algorithm == expected_algorithm:
            if raw.get("type", "Hash") != "Hash":
                raise ValueError(f"{field}[{index}] SHA-256 entry must be a Hash")
            matches.append(_digest(raw.get(digest_key), f"{field}[{index}].{digest_key}"))
            if ignored is not None:
                used = (
                    {algorithm_key, digest_key}
                    if cyclonedx
                    else {
                        "type",
                        algorithm_key,
                        digest_key,
                    }
                )
                _unknown_keys(ignored, raw, used, f"{field}[{index}]")
        elif ignored is not None:
            _ignored_add(ignored, f"{field}[{index}]")
    if len(matches) != 1:
        raise ValueError(f"{field} must contain exactly one {expected_algorithm} digest")
    return matches[0]


def _cyclonedx_projection(payload: bytes) -> Dict[str, Any]:
    value = loads_strict_json(payload)
    if not isinstance(value, dict):
        raise ValueError("CycloneDX document must be an object")
    if value.get("bomFormat") != "CycloneDX" or value.get("specVersion") != "1.7":
        raise ValueError("CycloneDX document must declare CycloneDX 1.7")
    schema = value.get("$schema")
    if schema not in (
        None,
        "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "https://cyclonedx.org/schema/bom-1.7.schema.json",
    ):
        raise ValueError("CycloneDX document declares an unsupported JSON schema")

    ignored: set[str] = set()
    _unknown_keys(
        ignored,
        value,
        {"$schema", "bomFormat", "specVersion", "components", "dependencies"},
        "$",
    )
    components: list[Dict[str, Any]] = []
    refs: set[str] = set()
    for index, raw in enumerate(
        _bounded_list(value.get("components"), "CycloneDX components", MAX_COMPONENTS)
    ):
        if not isinstance(raw, dict):
            raise ValueError(f"CycloneDX components[{index}] must be an object")
        path = f"$.components[{index}]"
        source_ref = _source_ref(raw.get("bom-ref"), f"{path}.bom-ref")
        if source_ref in refs:
            raise ValueError("CycloneDX document contains duplicate bom-ref values")
        refs.add(source_ref)
        source_class = raw.get("type")
        if source_class not in CYCLONEDX_COMPONENT_TYPES:
            raise ValueError(f"{path}.type is unsupported by the bounded profile")
        package_url = _package_url(raw.get("purl"), f"{path}.purl")
        digest = _sha256_from_hashes(
            raw.get("hashes"), f"{path}.hashes", cyclonedx=True, ignored=ignored
        )
        _unknown_keys(ignored, raw, {"bom-ref", "type", "purl", "hashes"}, path)
        components.append(
            {
                "source_ref": source_ref,
                "source_class": source_class,
                "sha256": digest,
                "package_url": package_url,
            }
        )

    dependencies: set[tuple[str, str]] = set()
    for index, raw in enumerate(
        _bounded_list(
            value.get("dependencies", []),
            "CycloneDX dependencies",
            MAX_RELATIONSHIPS,
            allow_empty=True,
        )
    ):
        if not isinstance(raw, dict):
            raise ValueError(f"CycloneDX dependencies[{index}] must be an object")
        path = f"$.dependencies[{index}]"
        dependent = _source_ref(raw.get("ref"), f"{path}.ref")
        if dependent not in refs:
            raise ValueError("CycloneDX dependency references an unknown dependent component")
        targets = _bounded_list(
            raw.get("dependsOn", []), f"{path}.dependsOn", MAX_COMPONENTS, allow_empty=True
        )
        seen_targets: set[str] = set()
        for target_index, target_value in enumerate(targets):
            target = _source_ref(target_value, f"{path}.dependsOn[{target_index}]")
            if target not in refs:
                raise ValueError("CycloneDX dependency references an unknown dependency component")
            if target == dependent:
                raise ValueError("CycloneDX dependency graph contains a self edge")
            if target in seen_targets:
                raise ValueError("CycloneDX dependency entry contains duplicate targets")
            seen_targets.add(target)
            pair = (dependent, target)
            if pair in dependencies:
                raise ValueError("CycloneDX dependency graph contains a duplicate edge")
            dependencies.add(pair)
        _unknown_keys(ignored, raw, {"ref", "dependsOn"}, path)

    return {
        "format": CYCLONEDX_FORMAT,
        "document_sha256": _sha256(payload),
        "components": sorted(components, key=lambda item: item["source_ref"]),
        "dependencies": [
            {"dependent_ref": dependent, "dependency_ref": dependency}
            for dependent, dependency in sorted(dependencies)
        ],
        "ignored_field_paths": sorted(ignored),
        "coverage": PROJECTION_COVERAGE,
    }


def _spdx_package_url(raw: Mapping[str, Any], field: str) -> Optional[str]:
    present = [key for key in ("packageUrl", "software_packageUrl") if key in raw]
    if len(present) > 1:
        raise ValueError(f"{field} declares both compact Package URL aliases")
    return _package_url(raw[present[0]] if present else None, f"{field}.packageUrl")


def _spdx_projection(payload: bytes) -> Dict[str, Any]:
    value = loads_strict_json(payload)
    if not isinstance(value, dict):
        raise ValueError("SPDX document must be an object")
    if value.get("@context") != SPDX_CONTEXT:
        raise ValueError("SPDX document must use the SPDX 3.0.1 JSON-LD context")
    graph = _bounded_list(value.get("@graph"), "SPDX @graph", MAX_RELATIONSHIPS)
    ignored: set[str] = set()
    _unknown_keys(ignored, value, {"@context", "@graph"}, "$")

    components: list[Dict[str, Any]] = []
    refs: set[str] = set()
    creation_info_count = 0
    relationship_values: list[tuple[int, Mapping[str, Any]]] = []
    for index, raw in enumerate(graph):
        if not isinstance(raw, dict):
            raise ValueError(f"SPDX @graph[{index}] must be an object")
        source_class = raw.get("type")
        path = f"$.@graph[{index}]"
        if source_class == "CreationInfo":
            creation_info_count += 1
            if raw.get("specVersion") != "3.0.1":
                raise ValueError("every SPDX CreationInfo must declare specVersion 3.0.1")
            _unknown_keys(ignored, raw, {"@id", "type", "specVersion"}, path)
            continue
        if source_class == "Relationship":
            relationship_values.append((index, raw))
            continue
        if source_class not in SPDX_PACKAGE_TYPES:
            _ignored_add(ignored, path)
            continue
        source_ref = _source_ref(raw.get("spdxId"), f"{path}.spdxId")
        if source_ref in refs:
            raise ValueError("SPDX document contains duplicate package spdxId values")
        refs.add(source_ref)
        package_url = _spdx_package_url(raw, path)
        digest = _sha256_from_hashes(
            raw.get("verifiedUsing"),
            f"{path}.verifiedUsing",
            cyclonedx=False,
            ignored=ignored,
        )
        _unknown_keys(
            ignored,
            raw,
            {
                "type",
                "spdxId",
                "packageUrl",
                "software_packageUrl",
                "verifiedUsing",
            },
            path,
        )
        components.append(
            {
                "source_ref": source_ref,
                "source_class": source_class,
                "sha256": digest,
                "package_url": package_url,
            }
        )
    if creation_info_count == 0:
        raise ValueError("SPDX document must contain CreationInfo for specVersion 3.0.1")
    if not components:
        raise ValueError("SPDX document has no package components in the bounded profile")

    dependencies: set[tuple[str, str]] = set()
    for index, raw in relationship_values:
        path = f"$.@graph[{index}]"
        if raw.get("relationshipType") != "dependsOn":
            _ignored_add(ignored, path)
            continue
        dependent = _source_ref(raw.get("from"), f"{path}.from")
        targets = _bounded_list(raw.get("to"), f"{path}.to", MAX_COMPONENTS)
        if dependent not in refs:
            raise ValueError("SPDX dependsOn relationship has an unknown source component")
        seen_targets: set[str] = set()
        for target_index, target_value in enumerate(targets):
            target = _source_ref(target_value, f"{path}.to[{target_index}]")
            if target not in refs:
                raise ValueError("SPDX dependsOn relationship has an unknown target component")
            if target == dependent:
                raise ValueError("SPDX dependency graph contains a self edge")
            if target in seen_targets:
                raise ValueError("SPDX dependsOn relationship contains duplicate targets")
            seen_targets.add(target)
            pair = (dependent, target)
            if pair in dependencies:
                raise ValueError("SPDX dependency graph contains a duplicate edge")
            dependencies.add(pair)
        _unknown_keys(
            ignored,
            raw,
            {"type", "spdxId", "creationInfo", "relationshipType", "from", "to"},
            path,
        )

    return {
        "format": SPDX_FORMAT,
        "document_sha256": _sha256(payload),
        "components": sorted(components, key=lambda item: item["source_ref"]),
        "dependencies": [
            {"dependent_ref": dependent, "dependency_ref": dependency}
            for dependent, dependency in sorted(dependencies)
        ],
        "ignored_field_paths": sorted(ignored),
        "coverage": PROJECTION_COVERAGE,
    }


def project_bom(payload: bytes, format_name: str) -> Dict[str, Any]:
    """Project one strict source BOM into the bounded common representation."""

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_DOCUMENT_BYTES:
        raise ValueError("source BOM must be non-empty bytes within the 8 MiB limit")
    if format_name == CYCLONEDX_FORMAT:
        return _cyclonedx_projection(payload)
    if format_name == SPDX_FORMAT:
        return _spdx_projection(payload)
    raise ValueError("unsupported source BOM format")


def _mapping(value: Any, field: str) -> Dict[str, Any]:
    mapping = _exact(
        value,
        field,
        ("component_id", "artifact_id", "kind", "cyclonedx_ref", "spdx_id"),
    )
    _identifier(mapping["component_id"], f"{field}.component_id")
    if mapping["artifact_id"] is not None:
        _identifier(mapping["artifact_id"], f"{field}.artifact_id")
    _kind(mapping["kind"], f"{field}.kind")
    _source_ref(mapping["cyclonedx_ref"], f"{field}.cyclonedx_ref")
    _source_ref(mapping["spdx_id"], f"{field}.spdx_id")
    return dict(mapping)


def validate_bom_manifest(
    value: Any, artifact_plan: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    manifest = _exact(
        value,
        "LureBOM manifest",
        (
            "schema",
            "schema_version",
            "reconciliation_id",
            "created_at",
            "artifact_plan_sha256",
            "workload_principal_id",
            "primary_format",
            "cyclonedx_document_sha256",
            "spdx_document_sha256",
            "components",
            "policy",
            "limitations",
        ),
    )
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["schema_version"] != 1:
        raise ValueError("unsupported LureBOM manifest schema")
    _identifier(manifest["reconciliation_id"], "LureBOM reconciliation_id")
    _timestamp(manifest["created_at"], "LureBOM manifest created_at")
    _digest(manifest["artifact_plan_sha256"], "LureBOM artifact plan digest")
    _identifier(manifest["workload_principal_id"], "LureBOM workload principal")
    if manifest["primary_format"] not in {CYCLONEDX_FORMAT, SPDX_FORMAT}:
        raise ValueError("LureBOM primary format is unsupported")
    _digest(manifest["cyclonedx_document_sha256"], "CycloneDX document digest")
    _digest(manifest["spdx_document_sha256"], "SPDX document digest")
    if manifest["cyclonedx_document_sha256"] == manifest["spdx_document_sha256"]:
        raise ValueError("distinct source formats cannot have the same reviewed document digest")
    if manifest["policy"] != POLICY:
        raise ValueError("LureBOM policy must use the fixed fail-closed v1 profile")
    if manifest["limitations"] != MANIFEST_LIMITATIONS:
        raise ValueError("LureBOM manifest limitations are invalid")
    mappings = [
        _mapping(item, f"LureBOM components[{index}]")
        for index, item in enumerate(
            _bounded_list(manifest["components"], "LureBOM components", MAX_COMPONENTS)
        )
    ]
    if mappings != sorted(mappings, key=lambda item: item["component_id"]):
        raise ValueError("LureBOM component mappings must be sorted by component_id")
    for key in ("component_id", "cyclonedx_ref", "spdx_id"):
        values = [item[key] for item in mappings]
        if len(values) != len(set(values)):
            raise ValueError(f"LureBOM component mappings contain duplicate {key} values")
    artifact_ids = [item["artifact_id"] for item in mappings if item["artifact_id"] is not None]
    if len(artifact_ids) != len(set(artifact_ids)):
        raise ValueError("LureBOM component mappings contain duplicate artifact identifiers")

    if artifact_plan is not None:
        plan = validate_artifact_plan(artifact_plan)
        if manifest["artifact_plan_sha256"] != _sha256(_canonical(plan)):
            raise ValueError("LureBOM manifest does not bind the supplied LureArtifact plan")
        if _time(manifest["created_at"]) < _time(plan["created_at"]):
            raise ValueError("LureBOM manifest predates its LureArtifact plan")
        workloads = {item["workload_principal_id"]: item for item in plan["workloads"]}
        workload = workloads.get(manifest["workload_principal_id"])
        if workload is None:
            raise ValueError("LureBOM manifest selects an unknown workload")
        if manifest["primary_format"] != workload["ai_bom"]["format"]:
            raise ValueError("LureBOM primary format does not match LureArtifact")
        primary_digest = (
            manifest["cyclonedx_document_sha256"]
            if manifest["primary_format"] == CYCLONEDX_FORMAT
            else manifest["spdx_document_sha256"]
        )
        if primary_digest != workload["ai_bom"]["document_sha256"]:
            raise ValueError("LureBOM primary document digest does not match LureArtifact")
        expected_artifact_ids = set(workload["ai_bom"]["subject_artifact_ids"])
        if set(artifact_ids) != expected_artifact_ids:
            raise ValueError(
                "LureBOM mappings must cover every AI-BOM subject artifact exactly once"
            )
        artifact_by_id = {item["artifact_id"]: item for item in workload["artifacts"]}
        for mapping in mappings:
            artifact_id = mapping["artifact_id"]
            if artifact_id is not None:
                expected_kind = ROLE_KIND[artifact_by_id[artifact_id]["role"]]
                if mapping["kind"] != expected_kind:
                    raise ValueError("LureBOM root mapping kind does not match artifact role")
    return dict(manifest)


def _class_supports_kind(format_name: str, source_class: str, kind: str) -> bool:
    if format_name == CYCLONEDX_FORMAT:
        if source_class == "machine-learning-model":
            return kind == "model"
        if source_class == "data":
            return kind == "dataset"
        if source_class == "container":
            return kind == "container"
        return kind in {"package", "policy", "runtime"}
    if source_class == "ai_AIPackage":
        return kind == "model"
    if source_class == "dataset_DatasetPackage":
        return kind == "dataset"
    return kind in {"container", "package", "policy", "runtime"}


def _validate_projection(value: Any, format_name: str) -> Dict[str, Any]:
    projection = _exact(
        value,
        f"{format_name} projection",
        (
            "format",
            "document_sha256",
            "components",
            "dependencies",
            "ignored_field_paths",
            "coverage",
        ),
    )
    if projection["format"] != format_name:
        raise ValueError("LureBOM projection format is invalid")
    _digest(projection["document_sha256"], "LureBOM projection document digest")
    components: list[Dict[str, Any]] = []
    for index, raw in enumerate(
        _bounded_list(projection["components"], "LureBOM projection components", MAX_COMPONENTS)
    ):
        component = _exact(
            raw,
            f"LureBOM projection components[{index}]",
            ("source_ref", "source_class", "sha256", "package_url"),
        )
        _source_ref(component["source_ref"], "LureBOM projection source_ref")
        if not isinstance(component["source_class"], str):
            raise ValueError("LureBOM projection source_class must be text")
        allowed = (
            CYCLONEDX_COMPONENT_TYPES if format_name == CYCLONEDX_FORMAT else SPDX_PACKAGE_TYPES
        )
        if component["source_class"] not in allowed:
            raise ValueError("LureBOM projection source_class is unsupported")
        _digest(component["sha256"], "LureBOM projection component digest")
        _package_url(component["package_url"], "LureBOM projection component Package URL")
        components.append(dict(component))
    if components != sorted(components, key=lambda item: item["source_ref"]):
        raise ValueError("LureBOM projection components are not canonical")
    refs = [item["source_ref"] for item in components]
    if len(refs) != len(set(refs)):
        raise ValueError("LureBOM projection contains duplicate component references")
    dependencies: list[Dict[str, str]] = []
    for index, raw in enumerate(
        _bounded_list(
            projection["dependencies"],
            "LureBOM projection dependencies",
            MAX_RELATIONSHIPS,
            allow_empty=True,
        )
    ):
        edge = _exact(
            raw,
            f"LureBOM projection dependencies[{index}]",
            ("dependent_ref", "dependency_ref"),
        )
        dependent = _source_ref(edge["dependent_ref"], "LureBOM dependent_ref")
        dependency = _source_ref(edge["dependency_ref"], "LureBOM dependency_ref")
        if dependent not in refs or dependency not in refs or dependent == dependency:
            raise ValueError("LureBOM projection dependency is invalid")
        dependencies.append(dict(edge))
    if dependencies != sorted(
        dependencies, key=lambda item: (item["dependent_ref"], item["dependency_ref"])
    ) or len({(item["dependent_ref"], item["dependency_ref"]) for item in dependencies}) != len(
        dependencies
    ):
        raise ValueError("LureBOM projection dependencies are not canonical and unique")
    ignored = _bounded_list(
        projection["ignored_field_paths"],
        "LureBOM projection ignored fields",
        MAX_IGNORED_FIELDS,
        allow_empty=True,
    )
    if any(not isinstance(item, str) or not 1 <= len(item) <= 4096 for item in ignored):
        raise ValueError("LureBOM ignored field paths must be bounded text")
    if ignored != sorted(set(ignored)):
        raise ValueError("LureBOM ignored field paths are not canonical and unique")
    if projection["coverage"] != PROJECTION_COVERAGE:
        raise ValueError("LureBOM projection coverage is invalid")
    return dict(projection)


def _finding(code: str, subject: str) -> Dict[str, str]:
    return {"code": code, "subject": subject}


def _derive_evaluation(
    artifact_plan: Mapping[str, Any],
    manifest: Mapping[str, Any],
    cyclonedx: Mapping[str, Any],
    spdx: Mapping[str, Any],
    *,
    evaluated_at: str,
) -> Dict[str, Any]:
    plan = validate_artifact_plan(artifact_plan)
    checked_manifest = validate_bom_manifest(manifest, plan)
    cdx = _validate_projection(cyclonedx, CYCLONEDX_FORMAT)
    spdx_projection = _validate_projection(spdx, SPDX_FORMAT)
    if cdx["document_sha256"] != checked_manifest["cyclonedx_document_sha256"]:
        raise ValueError("CycloneDX projection does not bind the reviewed document")
    if spdx_projection["document_sha256"] != checked_manifest["spdx_document_sha256"]:
        raise ValueError("SPDX projection does not bind the reviewed document")
    _timestamp(evaluated_at, "LureBOM evaluated_at")
    if _time(evaluated_at) < _time(checked_manifest["created_at"]):
        raise ValueError("LureBOM evaluation predates its manifest")

    workload = next(
        item
        for item in plan["workloads"]
        if item["workload_principal_id"] == checked_manifest["workload_principal_id"]
    )
    artifact_by_id = {item["artifact_id"]: item for item in workload["artifacts"]}
    cdx_by_ref = {item["source_ref"]: item for item in cdx["components"]}
    spdx_by_ref = {item["source_ref"]: item for item in spdx_projection["components"]}
    cdx_map = {item["cyclonedx_ref"]: item for item in checked_manifest["components"]}
    spdx_map = {item["spdx_id"]: item for item in checked_manifest["components"]}
    findings: list[Dict[str, str]] = []

    for source_ref in sorted(set(cdx_by_ref) - set(cdx_map)):
        findings.append(_finding("cyclonedx_component_unmapped", source_ref))
    for source_ref in sorted(set(spdx_by_ref) - set(spdx_map)):
        findings.append(_finding("spdx_component_unmapped", source_ref))

    component_results: list[Dict[str, Any]] = []
    for mapping in checked_manifest["components"]:
        component_id = mapping["component_id"]
        cdx_component = cdx_by_ref.get(mapping["cyclonedx_ref"])
        spdx_component = spdx_by_ref.get(mapping["spdx_id"])
        if cdx_component is None:
            findings.append(_finding("cyclonedx_component_missing", component_id))
        if spdx_component is None:
            findings.append(_finding("spdx_component_missing", component_id))
        sha_match = bool(
            cdx_component and spdx_component and cdx_component["sha256"] == spdx_component["sha256"]
        )
        purl_match = bool(
            cdx_component
            and spdx_component
            and cdx_component["package_url"] == spdx_component["package_url"]
        )
        kind_match = bool(
            cdx_component
            and spdx_component
            and _class_supports_kind(
                CYCLONEDX_FORMAT, cdx_component["source_class"], mapping["kind"]
            )
            and _class_supports_kind(SPDX_FORMAT, spdx_component["source_class"], mapping["kind"])
        )
        if cdx_component and spdx_component and not sha_match:
            findings.append(_finding("sha256_mismatch", component_id))
        if cdx_component and spdx_component and not purl_match:
            findings.append(_finding("package_url_mismatch", component_id))
        if cdx_component and spdx_component and not kind_match:
            findings.append(_finding("component_kind_mismatch", component_id))

        artifact_binding_match = True
        artifact_id = mapping["artifact_id"]
        if artifact_id is not None:
            artifact = artifact_by_id[artifact_id]
            if (
                not cdx_component
                or not spdx_component
                or any(
                    item["sha256"] != artifact["sha256"] for item in (cdx_component, spdx_component)
                )
            ):
                artifact_binding_match = False
                findings.append(_finding("artifact_digest_mismatch", component_id))
            if (
                not cdx_component
                or not spdx_component
                or any(
                    item["package_url"] != artifact["package_url"]
                    for item in (cdx_component, spdx_component)
                )
            ):
                artifact_binding_match = False
                findings.append(_finding("artifact_package_url_mismatch", component_id))
            if mapping["kind"] != ROLE_KIND[artifact["role"]]:
                artifact_binding_match = False
                findings.append(_finding("artifact_kind_mismatch", component_id))

        component_results.append(
            {
                "component_id": component_id,
                "artifact_id": artifact_id,
                "kind": mapping["kind"],
                "cyclonedx_ref": mapping["cyclonedx_ref"],
                "spdx_id": mapping["spdx_id"],
                "cyclonedx_sha256": cdx_component["sha256"] if cdx_component else None,
                "spdx_sha256": spdx_component["sha256"] if spdx_component else None,
                "cyclonedx_package_url": (cdx_component["package_url"] if cdx_component else None),
                "spdx_package_url": (spdx_component["package_url"] if spdx_component else None),
                "sha256_match": sha_match,
                "package_url_match": purl_match,
                "kind_match": kind_match,
                "artifact_binding_match": artifact_binding_match,
            }
        )

    def mapped_edges(
        projection: Mapping[str, Any], source_map: Mapping[str, Mapping[str, Any]], label: str
    ) -> set[tuple[str, str]]:
        result: set[tuple[str, str]] = set()
        for edge in projection["dependencies"]:
            dependent = source_map.get(edge["dependent_ref"])
            dependency = source_map.get(edge["dependency_ref"])
            if dependent is None or dependency is None:
                findings.append(
                    _finding(
                        f"{label}_dependency_unmapped",
                        f"{edge['dependent_ref']}->{edge['dependency_ref']}",
                    )
                )
                continue
            result.add((dependent["component_id"], dependency["component_id"]))
        return result

    cdx_edges = mapped_edges(cdx, cdx_map, "cyclonedx")
    spdx_edges = mapped_edges(spdx_projection, spdx_map, "spdx")
    for pair in sorted(spdx_edges - cdx_edges):
        findings.append(_finding("dependency_missing_from_cyclonedx", f"{pair[0]}->{pair[1]}"))
    for pair in sorted(cdx_edges - spdx_edges):
        findings.append(_finding("dependency_missing_from_spdx", f"{pair[0]}->{pair[1]}"))

    findings = sorted(findings, key=lambda item: (item["code"], item["subject"]))
    if len(findings) > MAX_FINDINGS:
        raise ValueError("LureBOM evaluation has too many findings")
    edge_union = cdx_edges | spdx_edges
    matched_components = sum(
        1
        for item in component_results
        if item["sha256_match"]
        and item["package_url_match"]
        and item["kind_match"]
        and item["artifact_binding_match"]
    )
    matched_dependencies = len(cdx_edges & spdx_edges)
    component_count = len(component_results)
    dependency_count = len(edge_union)
    summary = {
        "component_count": component_count,
        "matched_component_count": matched_components,
        "component_parity_rate": matched_components / component_count,
        "dependency_count": dependency_count,
        "matched_dependency_count": matched_dependencies,
        "dependency_parity_rate": (
            matched_dependencies / dependency_count if dependency_count else 1.0
        ),
        "artifact_subject_count": len(workload["ai_bom"]["subject_artifact_ids"]),
        "ignored_field_count": len(cdx["ignored_field_paths"])
        + len(spdx_projection["ignored_field_paths"]),
        "finding_count": len(findings),
        "verdict": "pass" if not findings else "fail",
    }
    return {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "evaluation_id": f"{checked_manifest['reconciliation_id']}-evaluation",
        "evaluated_at": evaluated_at,
        "engine": {"name": "lurebench-lurebom-reference", "version": VERSION},
        "artifact_plan": plan,
        "manifest": checked_manifest,
        "projections": {"cyclonedx": cdx, "spdx": spdx_projection},
        "components": component_results,
        "dependencies": {
            "cyclonedx": [
                {"dependent_component_id": item[0], "dependency_component_id": item[1]}
                for item in sorted(cdx_edges)
            ],
            "spdx": [
                {"dependent_component_id": item[0], "dependency_component_id": item[1]}
                for item in sorted(spdx_edges)
            ],
        },
        "findings": findings,
        "summary": summary,
        "limitations": EVALUATION_LIMITATIONS,
    }


def reconcile_boms(
    artifact_plan: Mapping[str, Any],
    manifest: Mapping[str, Any],
    cyclonedx_payload: bytes,
    spdx_payload: bytes,
    *,
    evaluated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Reconcile two exact source BOMs and return a deterministic evaluation."""

    plan = validate_artifact_plan(artifact_plan)
    checked_manifest = validate_bom_manifest(manifest, plan)
    cdx = project_bom(cyclonedx_payload, CYCLONEDX_FORMAT)
    spdx = project_bom(spdx_payload, SPDX_FORMAT)
    return _derive_evaluation(
        plan,
        checked_manifest,
        cdx,
        spdx,
        evaluated_at=evaluated_at or _now(),
    )


def validate_bom_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "LureBOM evaluation",
        (
            "schema",
            "schema_version",
            "evaluation_id",
            "evaluated_at",
            "engine",
            "artifact_plan",
            "manifest",
            "projections",
            "components",
            "dependencies",
            "findings",
            "summary",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureBOM evaluation schema")
    _identifier(evaluation["evaluation_id"], "LureBOM evaluation_id")
    _timestamp(evaluation["evaluated_at"], "LureBOM evaluated_at")
    engine = _exact(evaluation["engine"], "LureBOM engine", ("name", "version"))
    if engine != {"name": "lurebench-lurebom-reference", "version": VERSION}:
        raise ValueError("LureBOM evaluation engine is unsupported")
    projections = _exact(evaluation["projections"], "LureBOM projections", ("cyclonedx", "spdx"))
    expected = _derive_evaluation(
        evaluation["artifact_plan"],
        evaluation["manifest"],
        projections["cyclonedx"],
        projections["spdx"],
        evaluated_at=evaluation["evaluated_at"],
    )
    if evaluation != expected:
        raise ValueError("LureBOM evaluation does not independently reconcile")
    return dict(evaluation)


def _read_bytes(path: Path, label: str) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.parent.is_symlink():
        raise ValueError(f"{label} must be a non-symlink regular local file")
    size = target.stat().st_size
    if not 1 <= size <= MAX_DOCUMENT_BYTES:
        raise ValueError(f"{label} must be non-empty and at most 8 MiB")
    return target.read_bytes()


def read_bom_json(path: Path, label: str) -> Any:
    return loads_strict_json(_read_bytes(path, label))


def write_bom_evaluation(path: Path, value: Mapping[str, Any]) -> None:
    target = Path(path)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(_canonical(validate_bom_evaluation(value)))
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_bom_evaluation(path: Path) -> Dict[str, Any]:
    return validate_bom_evaluation(read_bom_json(path, "LureBOM evaluation"))


def reconcile_bom_files(
    artifact_plan_path: Path,
    manifest_path: Path,
    cyclonedx_path: Path,
    spdx_path: Path,
    output_path: Path,
    *,
    evaluated_at: Optional[str] = None,
) -> Dict[str, Any]:
    plan = read_bom_json(artifact_plan_path, "LureArtifact plan")
    manifest = read_bom_json(manifest_path, "LureBOM manifest")
    result = reconcile_boms(
        plan,
        manifest,
        _read_bytes(cyclonedx_path, "CycloneDX BOM"),
        _read_bytes(spdx_path, "SPDX BOM"),
        evaluated_at=evaluated_at,
    )
    write_bom_evaluation(output_path, result)
    return result
