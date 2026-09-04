# LureAttest: authenticated provenance expectations

LureArtifact binds workloads to declared provenance metadata. LureAttest closes
the next gap: it compiles the exact signer, builder, source, build type, subject,
and external-parameter expectations that an independent verifier must apply to
the real provenance envelopes.

This split follows the verification model in
[SLSA v1.2](https://slsa.dev/spec/v1.2/verifying-artifacts): authenticate the
envelope against a configured root of trust, bind the statement subject to the
artifact digest, and compare the provenance with producer-defined
expectations. The payload uses an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with the `https://slsa.dev/provenance/v1` predicate inside a
[DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
envelope.

## What LureBench compiles

The trust policy binds one exact LureArtifact plan and declares:

- one ECDSA P-256 public-key fingerprint for each builder identity;
- the maximum SLSA Build level the reviewer is willing to assign that
  signer–builder pair;
- one exact signer, source URI, external-parameter commitment, and minimum
  policy level for every provenance statement; and
- a fixed fail-closed verification profile.

The compiler rejects missing or extra attestations and builders, a signer that
is not authorized for the claimed builder, or a required level above the
reviewed builder level. One signer may be explicitly authorized for multiple
builder identities, matching SLSA's signer–builder-pair model. Evidence
filenames are derived from bounded attestation IDs; paths are never accepted
from policy input.

```bash
lurebench attest-compose \
  --artifact-plan artifact-plan.json \
  --policy trust-policy.json \
  --out attest-plan.json

lurebench attest-verify attest-plan.json
```

Every output is canonical JSON, created mode `0600`, and never overwritten.
The packaged [`conformance/lureattest-v1`](../conformance/lureattest-v1/)
directory contains a one-workload, three-attestation plan plus real signed DSSE
envelopes and the public verification key.

## Exact commitments

`public_key_sha256` is SHA-256 over the DER-encoded SubjectPublicKeyInfo, not the
PEM text. `external_parameters_sha256` is SHA-256 over UTF-8 JSON serialized
with keys sorted, no insignificant whitespace, no NaN/Infinity, and one final
newline. LureScope provides commands that compute both values without putting a
private key in the policy:

```bash
lurescope attest key-id builder-public.pem
lurescope attest commit-external-parameters external-parameters.json
```

The source expectation is one exact `resolvedDependencies` member whose `uri`
and `digest.sha256` both match. Other dependencies may be present, but duplicate
exact matches are rejected.

## Independent verification

Use [LureScope's authenticated verifier](https://github.com/immu4989/lurescope/blob/main/docs/LUREATTEST_VERIFICATION.md)
to recompile the plan and inspect the real evidence. The LureBench compiler has
no cryptography or network dependency and deliberately never opens an envelope,
public key, source tree, build output, AI-BOM, or subject artifact.

## Claims boundary

A valid LureAttest plan means only that the reviewed expectations are complete
and internally consistent. It does not authenticate provenance, certify a build
platform, establish a SLSA level, or prove that source code, parameters,
dependencies, builders, models, policies, images, or outputs are safe.

The v1 profile supports externally distributed ECDSA P-256 keys. It is not a
Sigstore verifier: Fulcio certificate identity and lifetime, Rekor inclusion,
signed checkpoints, RFC 3161 timestamps, and trust-root/key lifecycle remain
outside this profile. Sigstore's bundle format requires those materials for
public keyless verification, so LureAttest does not reduce them to a misleading
boolean.
