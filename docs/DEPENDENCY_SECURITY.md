# Dependency security review — 2026-09-21

These findings describe this source branch, not an already-published release.
Dependency resolution is not runtime reachability analysis or a security
certification. The core harness has no required third-party dependencies.

## HTTPX2

The optional dependency lock now selects HTTPX2 and HTTPCore2 2.13.0. A uv
constraint prevents HTTPX2 below 2.12.0 from returning during resolution.
This addresses the reviewed HTTPX2 advisories
[decompression amplification](https://github.com/advisories/GHSA-8xx6-hgc6-gc2m),
[multipart header injection](https://github.com/advisories/GHSA-h4x7-gw46-3wm6),
and [conflicting framing headers](https://github.com/advisories/GHSA-pf96-p4fj-6566)
in this lock. No provider endpoint was called during remediation.

The constraint applies to uv project resolution; it is not a runtime patch or
a dependency requirement embedded in the wheel. Consumers managing their own
optional provider environment must independently update its HTTPX2 dependency.
Existing environments are not upgraded by merely pulling the changed lock.

## Accelerate remains unresolved

[GHSA-4j2p-28q2-5m79](https://github.com/advisories/GHSA-4j2p-28q2-5m79)
lists Accelerate through 1.14.0 as affected and currently lists no patched
release. The optional Llama Guard extra still resolves Accelerate 1.14.0.
Do not treat the HTTPX2 update as resolution of this separate alert.

The advisory concerns shard filenames supplied through checkpoint indexes to
`load_checkpoint_in_model` and `load_checkpoint_and_dispatch`. LureBench calls
Transformers `from_pretrained`, rather than those functions directly. Inspection
of the locked Transformers 5.15.0
[Accelerate integration](https://github.com/huggingface/transformers/blob/v5.15.0/src/transformers/integrations/accelerate.py)
found `dispatch_model`, not direct calls to the two named loading functions.
This limited static observation does not prove non-reachability for every model,
configuration, older allowed dependency version, or future dependency change.

Until a patched upstream release is verified, do not load untrusted checkpoints
with this optional stack. Use reviewed immutable artifacts, a dedicated
low-privilege environment without unrelated secrets, and externally enforced
resource limits. Keep the alert open; no exception or advisory dismissal was
created. Model downloads and large-model loading were not performed in this
review, so compatibility has not been established through a real gated-model run.
