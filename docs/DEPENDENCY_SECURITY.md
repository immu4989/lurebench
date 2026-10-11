# Dependency security review

These findings describe this source branch, not an already-published release.
Dependency resolution is not runtime reachability analysis or a security
certification. The core harness has no required third-party dependencies.

## urllib3 update on 10 October 2026

The optional lock selects urllib3 2.8.0, replacing 2.7.0, with a uv resolution
floor of 2.8.0. This addresses the upstream
[unbounded chunk-size line](https://github.com/advisories/GHSA-vxq7-64xx-v4gw) and
[chunked Deflate loop](https://github.com/advisories/GHSA-gh4c-6fx4-qh6g)
advisories in that lock. The Requests streaming API can expose these urllib3
paths. Regression tests require every locked urllib3 entry to meet the floor;
the core package still has no required HTTP dependency.

These constraints apply to uv project resolution, not independently resolved
consumer environments. Existing installations need an explicit dependency
update. GitHub's default-branch alerts remain until reviewed changes reach the
default branch and its dependency graph is refreshed; a local lock change does
not dismiss them. The separate HTTPX2 and Accelerate assessments below still apply.

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

## Adapter safeguards reviewed on 2026 10 02

The upstream advisory still lists no patched version as of this review. The
Llama Guard adapter now passes `trust_remote_code=False` to both loaders and
`use_safetensors=True` to the model loader. An optional `revision` accepts only a
40-character lowercase commit hash, and `local_files_only=True` requests offline
loading. These are explicit loader controls, **not a patch** for shard traversal,
not an atomic directory-integrity guarantee, and not authentication of a publisher.
The separate checkpoint preflight remains inspection rather than safe execution.

Configuration and inference contracts are tested using in-process stubs only.
No gated model was downloaded or loaded. Do not infer that all allowed versions,
devices, or model variants were tested. A real optional-stack compatibility run
still needs reviewed artifacts, isolation, resources, and separate authorization.
