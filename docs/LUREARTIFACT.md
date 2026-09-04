# LureArtifact: authorize the AI deployment, not only the workload

LureArtifact is an offline, fail-closed benchmark for a deployment question
that identity policy alone cannot answer:

> Is this authorized workload running the exact model, container, policy,
> AI bill of materials, and build provenance that reviewers approved?

It compiles a reviewed artifact campaign against one exact LureIdentity plan.
Every active workload in that identity plan must appear exactly once. The
compiler derives each workload's canonical SPIFFE ID and system identity,
refuses undeclared nodes, and produces a deterministic plan. A separate
observation is then compared against the complete expected deployment matrix.

```text
LureIdentity plan ─┐
                   ├─ compile ─> LureArtifact plan ─┐
artifact campaign ─┘                                ├─ evaluate ─> pass/fail + findings
claimed deployment observation ────────────────────┘
```

No command fetches a registry object, opens a model, imports custom code,
executes a policy, parses an AI-BOM document, or deserializes artifact bytes.

## What is bound

For every active workload and every node assigned to it, v1 requires:

| Binding | Required metadata |
|---|---|
| Workload | LureIdentity plan digest, principal ID, canonical SPIFFE ID, node ID |
| Container | Exact SHA-256, media type, optional package URL |
| Model weights | Exact SHA-256, media type, optional package URL, approved non-executable serialization |
| Policy bundle | Exact SHA-256, media type, optional package URL |
| AI-BOM | Exact document SHA-256, SPDX/CycloneDX profile, complete subject coverage |
| Build provenance | in-toto statement type, SLSA v1 predicate, statement and subject digests, approved builder, build type, source digest |

The strict v1 model policy accepts `safetensors`, `onnx`, and `gguf`. It denies
model-embedded executable code and models that require remote code. An observed
`pickle`, `pytorch_pickle`, `hdf5`, unknown serialization, embedded code, remote
code requirement, or unapproved builder is represented as an explicit policy
finding. This is a metadata assertion: LureArtifact does not inspect a file to
decide whether the label is truthful.

## Run the public conformance workflow

Start with the bundled LureIdentity campaign so the exact identity-plan digest
matches the LureArtifact example:

```bash
lurebench identity-compose \
  --campaign conformance/lureidentity-campaign-v1/campaign.json \
  --out identity-plan.json

lurebench artifact-compose \
  --identity-plan identity-plan.json \
  --campaign examples/lureartifact-campaign-v1.json \
  --out artifact-plan.json

# Synthetic success fixture only—not production observation collection:
lurebench artifact-observe \
  --plan artifact-plan.json \
  --out artifact-observation.json

lurebench artifact-eval \
  --plan artifact-plan.json \
  --observation artifact-observation.json \
  --out artifact-evaluation.json

lurebench artifact-verify artifact-evaluation.json
```

The packaged [`conformance/lureartifact-v1`](../conformance/lureartifact-v1/)
directory contains exact identity plan, campaign, compiled plan, observation,
and evaluation vectors. LureScope independently exercises the same vector
without importing LureBench.

For a real integration, replace `artifact-observe` with a separately trusted
collector that emits the strict observation schema. Preserve the actual
lowercase SHA-256 values; do not substitute tags, mutable revisions, friendly
names, or placeholders.

## Failure semantics

Exit `0` means every declared binding matched. Exit `1` means a valid
observation produced one or more findings. Exit `2` means the input contract or
integrity check was invalid. Important findings include:

- missing, unexpected, or duplicate workload/node deployments;
- identity-plan, system, or SPIFFE mismatch;
- missing or substituted model, image, policy, or AI-BOM metadata;
- missing, unexpected, or changed SLSA provenance metadata;
- AI-BOM document or subject-coverage mismatch;
- an unapproved observed builder;
- disallowed model serialization, embedded code, or required remote code; and
- observations or evaluations that predate their source contract.

Unknown fields, duplicate JSON keys, malformed identifiers, unsupported
standards profiles, incomplete active-workload coverage, unsafe reviewed model
formats, and output overwrite attempts fail before an evaluation is written.

## Standards mapping

LureArtifact uses the
[in-toto Statement v1](https://github.com/in-toto/attestation) identifier and a
bounded projection of [SLSA Provenance v1](https://slsa.dev/spec/v1.1/provenance):
subject digest, statement digest, builder ID, build type, and source digest. It
does not parse the complete statement or verify its signature or build
platform.

AI-BOM metadata accepts
[SPDX 3.0.1 AI packages](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/Classes/AIPackage/)
and CycloneDX 1.6/1.7 labels. SPDX explicitly models AI packages and integrity
methods; CycloneDX models machine-learning components and dependency graphs.
LureArtifact binds a separately produced BOM document—it is not an SPDX or
CycloneDX conformance checker.

The design supports the secure-development evidence needs described by
[NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final), but a passing
result is not NIST conformance, procurement approval, or an authorization to
operate.

## Claims boundary

A pass proves that the exact submitted metadata is a valid consequence of the
exact submitted LureIdentity and LureArtifact contracts. It does **not** prove:

- that an SVID was issued, validated, or possessed by the observed workload;
- that a collector discovered every workload, node, process, model, or file;
- that a SHA-256-matching artifact is safe, unbiased, licensed, vulnerability
  free, or suitable for its intended use;
- that a provenance statement was signed by the named builder or that the
  builder and source are trustworthy;
- that an AI-BOM is complete, truthful, or valid under SPDX or CycloneDX;
- that serialization metadata was derived from artifact inspection; or
- supply-chain containment, compliance, certification, or deployment
  authorization.

Use signatures, transparency logs, registry policy, measured boot/runtime
attestation, independent collection, vulnerability analysis, and human release
authority around this benchmark when those claims matter.
