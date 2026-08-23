# LureEval v1 semantic conformance

The LureEval conformance kit is a deterministic, language-neutral collection of
valid and invalid receipts. It lets another implementation demonstrate the same
strict parsing, privacy boundary, semantic checks, and metric recomputation as
the reference implementation.

Passing this suite means “these reviewed protocol vectors receive the expected
verdict.” It does not measure detector accuracy, authenticate an issuer, prove
secure implementation, establish compliance, or predict deployment performance.

## Run the reference implementation

```bash
python -m pip install "lurebench==0.11.0"
lurebench conformance
lurebench conformance --out lureeval-conformance-report.json --json
```

Exit codes are `0` for a passing suite, `1` for a completed suite with mismatched
verdicts, and `2` when the suite or report cannot be safely processed. Reports are
created mode `0600` and existing paths are never overwritten.

Use an unpacked suite from another source only when you intend to test those
exact bytes:

```bash
lurebench conformance --suite ./conformance/lureeval-v1
```

## Portable suite layout

The canonical vectors are in [`conformance/lureeval-v1`](../conformance/lureeval-v1):

```text
suite.json
valid/*.json
invalid/*.json
```

`suite.json` identifies each case, expected verdict, artifact kind, category,
and SHA-256 digest. The manifest schema is
[`lureeval-conformance-suite-v1.schema.json`](../spec/lureeval-conformance-suite-v1.schema.json);
the result schema is
[`lureeval-conformance-report-v1.schema.json`](../spec/lureeval-conformance-report-v1.schema.json).

## Requirements for independent implementations

An implementation claiming conformance to `lureeval-v1-semantic` version `1.0.0`
must:

1. parse the manifest as strict UTF-8 JSON, rejecting duplicate object keys,
   non-finite numbers, malformed UTF-8, and trailing data;
2. reject absolute paths, parent traversal, hidden components, symbolic links,
   non-regular files, oversized artifacts, duplicate case IDs, and duplicate
   artifact paths;
3. verify the artifact SHA-256 digest **before** parsing the artifact;
4. run every case using the LureEval receipt or aggregate semantic validator,
   including exact field allowlists and recomputation from integer counts;
5. emit one result per case and reconcile case totals with the report summary;
6. preserve the three required interpretation limitations in the report.

The suite is data, not executable code. Runners must never invoke programs named
by a suite, load plugins from it, fetch URLs from it, or deserialize it with a
general object loader.

## Rebuild and review

The checked-in vectors are produced by a deterministic generator:

```bash
python scripts/build_lureeval_conformance.py
git diff --exit-code -- conformance/lureeval-v1
```

Every vector is intentionally synthetic. Invalid files are malformed in one
targeted way and must never be used as detector inputs. Any vector change requires
a suite-version decision, regenerated hashes, schema validation, and human review.

DSSE signature authentication is intentionally outside this semantic profile.
LureEval supports DSSE and tests it separately; portable static signature vectors
should be introduced as a separately versioned authentication profile with an
explicit trust-anchor model.
