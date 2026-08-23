# LureEval: private operational evaluation receipts

LureEval lets organizations report comparable detector outcomes without sharing
messages, people, tenant identifiers, cases, or row-level scores. LureScope
produces a receipt from locally adjudicated outcomes; LureBench verifies and pools
only compatible receipts.

This is an evidence interchange format, not federated learning and not a claim
that all sites observe the same population.

## Privacy-minimized statement

A v1 receipt is an in-toto Statement whose predicate contains:

- protocol, sampling, labeling, decision-policy, and confidence parameters;
- opaque commitments to the evaluated cohort and label snapshot;
- aggregate confusion counts and exact one-sided error bounds;
- aggregate routing/resilience outcomes and a Pilot Gate result;
- optional slices only when every reported cell meets the declared minimum size.

The semantic validator uses exact field allowlists. Source paths, message content,
subjects, addresses, message IDs, case IDs, URLs, attachment names, raw message
hashes, and per-message scores are prohibited anywhere in the receipt. A schema
alone cannot express all of those cross-field rules, so `lurebench verify-receipt`
runs both JSON Schema-shape checks and strict semantic recomputation.

## Authenticate a receipt

Unsigned receipts are useful for local review. Cross-organization aggregation
should require a trusted P-256 key for every source. LureEval wraps the statement
in a DSSE envelope and signs the exact pre-authentication encoding.

```bash
lurebench verify-receipt site-a.dsse.json \
  --public-key site-a-public.pem \
  --require-signature
```

Pool compatible sources and authenticate the resulting aggregate:

```bash
lurebench aggregate-receipts \
  --receipt site-a.dsse.json \
  --receipt site-b.dsse.json \
  --source-key "$PWD/site-a.dsse.json=$PWD/site-a-public.pem" \
  --source-key "$PWD/site-b.dsse.json=$PWD/site-b-public.pem" \
  --require-source-signatures \
  --signing-key consortium-private.pem \
  --issuer "Regional fraud-defense pilot" \
  --out pooled.dsse.json
```

Aggregation fails if cohorts repeat or protocols, sampling plans, labeling rules,
confidence levels, slice suppression thresholds, controls, or decision boundaries
differ. Pooled rates and confidence bounds are recomputed from counts; source
percentages are never averaged.

## Trust model and non-guarantees

A valid signature authenticates a statement to a key; it does not prove the
issuer followed the protocol or labeled outcomes correctly. Cohort commitments
detect accidental reuse but are not public record identifiers. Small-cell
suppression reduces disclosure risk but is not a formal differential-privacy
guarantee. Establish key ownership out of band, protect private keys, document
the sampling frame, and audit a sample of source adjudications before using a
pooled result for procurement or policy.

The normative artifacts are:

- [`lureeval-receipt-v1.schema.json`](../spec/lureeval-receipt-v1.schema.json)
- [`lureeval-aggregate-v1.schema.json`](../spec/lureeval-aggregate-v1.schema.json)
- [`lureeval-dsse-v1.schema.json`](../spec/lureeval-dsse-v1.schema.json)
