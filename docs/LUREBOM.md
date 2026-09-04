# LureBOM Twin: detect semantic drift between AI-BOM formats

Organizations often publish the same release inventory as both CycloneDX and
SPDX. Byte signatures can prove that each document is authentic, but they do
not prove that the two documents describe the same components or dependency
graph. LureBOM Twin makes that cross-format question reproducible and
fail-closed for one deployed LureArtifact workload.

The v1 reference engine reads one CycloneDX 1.7 JSON BOM and one SPDX 3.0.1
JSON-LD BOM. A reviewed manifest maps source identifiers explicitly; names and
versions are never used to guess identity. The primary document digest must be
the exact AI-BOM already authorized by LureArtifact. The mirror document and
every mapping are separately committed by the manifest.

```text
LureArtifact plan ───────┐
reviewed mapping ────────┼─> bounded projections ─> semantic parity report
CycloneDX 1.7 bytes ─────┤
SPDX 3.0.1 JSON-LD bytes ┘
```

## Run the conformance vector

```bash
lurebench bom-reconcile \
  --artifact-plan conformance/lurebom-v1/artifact-plan.json \
  --manifest conformance/lurebom-v1/manifest.json \
  --cyclonedx conformance/lurebom-v1/cyclonedx-1.7.json \
  --spdx conformance/lurebom-v1/spdx-3.0.1.json \
  --evaluated-at 2026-09-05T00:03:00Z \
  --out lurebom-evaluation.json

lurebench bom-verify lurebom-evaluation.json
```

Exit `0` means the declared common-denominator projection matches. Exit `1`
means both documents were valid inputs but component or dependency drift was
found. Exit `2` means an input or saved report was invalid. Output is canonical
JSON, mode `0600`, and never overwritten.

## What v1 compares

| Semantic claim | CycloneDX 1.7 | SPDX 3.0.1 JSON-LD |
|---|---|---|
| Source identity | `bom-ref` | `spdxId` |
| Component class | component `type` | package `type` |
| Integrity | exactly one `SHA-256` hash | exactly one inline `Hash` with `sha256` |
| Package identity | `purl` | `packageUrl` or `software_packageUrl` |
| Dependency | `dependencies[].ref/dependsOn` | `Relationship` with `dependsOn` |

Every projected source component must have one explicit manifest mapping. Every
LureArtifact AI-BOM subject—the model, container, and policy in the reference
profile—must be mapped exactly once and match the authorized digest, Package
URL, and role. Missing components, additional unmapped components, duplicate
hashes, unknown edge targets, self edges, duplicate edges, class mismatches, and
one-sided dependencies are findings or invalid input; none become a quiet pass.

SPDX 3.0.1 expands BOM scope to AI packages, datasets, build data, security,
licensing, and relationships. CycloneDX 1.7 similarly models machine-learning
components, model cards, dependency graphs, vulnerability disclosures, and
other supply-chain domains. Their richer fields are not all semantically
equivalent. LureBOM therefore records every ignored top-level or element field
path in `ignored_field_paths`. A pass applies only to the four fields and one
relationship type in the table above.

Official references:

- [SPDX 3.0.1 scope](https://spdx.github.io/spdx-spec/v3.0.1/scope/)
- [SPDX AIPackage](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/Classes/AIPackage/)
- [SPDX RelationshipType](https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/RelationshipType/)
- [CycloneDX 1.7 reference](https://cyclonedx.org/docs/1.7/json/)
- [CISA 2025 SBOM Minimum Elements](https://www.cisa.gov/sites/default/files/2025-08/2025_CISA_SBOM_Minimum_Elements.pdf)

LureBOM is a bounded semantic adapter, not a complete implementation or
conformance validator for those standards.

## Why explicit mappings are required

Names, mutable versions, and even Package URLs can be absent or duplicated.
Automatically merging components on those values can turn ambiguity into a
false assurance result. The manifest requires a reviewer to bind one canonical
component ID to one CycloneDX reference and one SPDX identifier. Package URLs
and hashes are then compared as claims, not used as hidden identity heuristics.

This also makes corrections reviewable. A changed source identifier changes
the manifest digest, while a changed source document changes its raw SHA-256.

## Independent verification

LureScope reparses the original source bytes with an independent local
implementation, reproduces the producer evaluation exactly, and embeds both
documents in a private self-checking report:

```bash
lurescope bom verify \
  artifact-plan.json manifest.json lurebom-evaluation.json \
  cyclonedx-1.7.json spdx-3.0.1.json \
  --out lurebom-verification.json

lurescope bom check lurebom-verification.json
```

See the [LureScope verification guide](https://github.com/immu4989/lurescope/blob/main/docs/LUREBOM_VERIFICATION.md).

## Claims boundary

LureBOM never fetches external references or opens a model, container, policy,
dataset, package, or other artifact. It does not establish that either BOM is
complete, current, true, schema-conformant, signed by an authorized issuer, or
free of vulnerabilities and license problems. It does not compare licenses,
suppliers, model-card claims, training data, VEX, services, formulation,
cryptography, annotations, or lifecycle metadata in v1. A passing evaluation is
not compliance, procurement approval, an authorization to operate, or proof of
artifact safety.
