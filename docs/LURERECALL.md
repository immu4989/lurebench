# LureRecall: transitive AI-artifact recall and recovery

LureRecall answers an operational question that an inventory alone cannot:

> If a model, dataset, package, container layer, runtime, policy, or AI-BOM is
> declared affected or still under investigation, which exact workload
> deployments must stop, by when, which replacements may restore them, and
> which unrelated deployments must remain available?

It compiles a bounded dependency DAG against one exact [LureArtifact
plan](LUREARTIFACT.md), computes the transitive blast radius, derives a complete
pre/quarantine/recovery probe matrix, and evaluates claimed response telemetry.
Everything is deterministic and metadata-only. No artifact, advisory document,
workload, registry, model hub, scanner, or network endpoint is opened.

## Why this exists

An SBOM or AI-BOM can enumerate components, and provenance can bind build
metadata, but neither demonstrates that an organization can locate and stop
every deployed dependent after a component incident. LureRecall makes that
response claim testable while preserving exact workload identity and deployment
scope.

The contract draws narrowly from four public sources:

- [CISA's minimum VEX requirements](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf)
  define machine-readable product, vulnerability, status, and document metadata;
- the [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
  defines `affected`, `fixed`, `not_affected`, and `under_investigation` status;
- [GUAC](https://docs.guac.sh/guac/) demonstrates dependency-graph queries over
  supply-chain metadata, including transitive vulnerability reachability; and
- [NIST SP 800-61r3](https://doi.org/10.6028/NIST.SP.800-61r3) frames incident
  response across detection, response, and recovery.

LureRecall is not an implementation or conformance validator for any of those
standards. It is a small benchmark projection with explicit limitations.

## Data flow

```text
exact LureArtifact plan
          ×
normalized acyclic lineage ── root → dependency edges
          ×
bounded VEX-like advisory ─── affected / under_investigation
          │
          ▼
    LureRecall compiler
          │
          ├── actionable and transitively affected components
          ├── impacted root artifacts, workloads, nodes, and shortest paths
          ├── complete replacement requirements
          └── 3 probes for every deployment
                    │
                    ▼
            claimed response run
                    │
                    ▼
       independently recomputable evaluation
```

Edges point from a dependent component to a dependency. If component `A`
depends on component `B`, an actionable statement about `B` reaches `A` by
reverse impact propagation. The compiler stores a deterministic shortest path
from every impacted deployment root to every triggering advisory component.

## Run the public vector

Start from the exact LureArtifact conformance plan:

```bash
lurebench recall-compose \
  --artifact-plan conformance/lureartifact-v1/plan.json \
  --lineage conformance/lurerecall-v1/lineage.json \
  --advisory conformance/lurerecall-v1/advisory.json \
  --out recall-plan.json

lurebench recall-run \
  --plan recall-plan.json \
  --out recall-run.json

lurebench recall-eval \
  --plan recall-plan.json \
  --run recall-run.json \
  --out recall-evaluation.json

lurebench recall-verify recall-evaluation.json
```

The bundled incident marks a base model `under_investigation`. The compiler
follows a `fine_tuned_from` edge, identifies one affected model root, one
workload on two nodes, and one unaffected workload control. It derives nine
probes: three for each deployment.

`recall-run` is only a deterministic passing fixture. Replace it with output
from a reviewed adapter before drawing operational conclusions.

## Strict input contracts

### Normalized lineage

The lineage must:

- bind the canonical bytes of one exact LureArtifact plan;
- map every `(workload_principal_id, artifact_id)` root exactly once;
- preserve root digest, package URL, and role-to-kind identity;
- use only `contains`, `depends_on`, `trained_on`, or `fine_tuned_from` edges;
- form an acyclic graph with no duplicate or self edges; and
- make every component reachable from a deployment root.

The implementation does not parse an SPDX, CycloneDX, GUAC, model-card, or
registry response directly. A production adapter should normalize reviewed
source data and retain the source document separately. The exact source bytes
remain externally auditable through their digest.

### Advisory

The advisory binds the artifact plan and lineage and carries a digest for an
externally reviewed CISA-VEX-like, CSAF VEX, or OpenVEX document. Status behavior
is deliberately fail closed:

| Status | LureRecall behavior |
|---|---|
| `affected` | quarantine and replacement required |
| `under_investigation` | quarantine and replacement required |
| `fixed` | not actionable in this run |
| `not_affected` | not actionable; machine-readable justification required |

At least one statement must be actionable. Its component digest must exactly
match lineage. Every transitively impacted deployment root requires exactly one
different replacement digest and one replacement provenance-statement digest.
Missing, extra, duplicate, unchanged, or recalled replacement material is
rejected before a plan is written.

The `externally_verified_document_metadata` label states an integration
precondition; it is not proof that this library authenticated the issuer.

## Derived probes and metrics

Every deployment receives three plan-bound probes:

1. `pre_advisory`: the original artifact set must be allowed;
2. `post_quarantine_deadline`: affected original sets must be blocked while
   unaffected sets remain allowed; and
3. `post_recovery_deadline`: affected deployments must allow the exact declared
   replacement set while unaffected sets remain unchanged.

The evaluator recomputes:

- actionable, affected, root-artifact, workload, deployment, and node counts;
- advisory delivery coverage, on-time coverage, p95, and maximum delay;
- quarantine recall and exact-replacement recovery recall;
- unaffected-deployment preservation;
- post-deadline compromised allows, wrong replacement sets, collateral blocks,
  missing/duplicate/unexpected probes, and all findings; and
- eight explicit pass/fail checks plus the overall verdict.

An `allow` observation must commit to the exact active artifact-set digest. A
`block` observation must not claim an active set. Observation identifiers are
unique across advisory and response records.

## Production adapter checklist

1. Build and independently review a complete artifact inventory with
   LureArtifact.
2. Normalize signed SBOM/AI-BOM, provenance, registry, and model-lineage data
   into the lineage contract; reject ambiguity rather than guessing.
3. Authenticate and authorize the advisory issuer outside LureRecall. Record
   the exact source-document SHA-256.
4. Treat `under_investigation` as actionable unless a separately governed
   policy explicitly chooses a different risk posture.
5. Declare rebuilt root artifacts and provenance before composing the plan.
6. Deliver the advisory through independently monitored channels.
7. Project controller and enforcement telemetry into the run contract without
   secrets, tokens, prompts, model content, or artifact bytes.
8. Run `recall-eval` in CI or release control. Preserve failed evaluations;
   exit status `1` is a valid benchmark failure, while `2` is invalid evidence.
9. Authenticate evidence, verify replacement signatures and provenance, scan
   replacement bytes, and authorize restoration through separate controls.

All CLI files are created with mode `0600`, symbolic-link inputs are refused,
JSON is duplicate-key/NaN rejecting, files are size bounded, and existing
outputs are never overwritten.

## Claims boundary

A pass means only that the supplied metadata says every declared affected node
received the exact advisory on time, every affected original artifact set was
blocked at the quarantine probe, every exact replacement set was allowed at the
recovery probe, and every declared unaffected control remained available.

A pass does **not** prove:

- source-lineage completeness or dependency truth;
- advisory authenticity, issuer authority, or vulnerability accuracy;
- artifact, model, dataset, policy, builder, or replacement safety;
- actual workload stop, registry removal, cache eviction, or restoration;
- clock synchronization, telemetry origin, completeness, or causality; or
- incident containment, recovery, authorization, certification, or regulatory
  compliance.

Use signed source documents, trusted-key verification, independent runtime
sensors, vulnerability and malware scanning, provenance verification, and
ordinary incident-command authority around this benchmark.
