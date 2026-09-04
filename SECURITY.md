# Security Policy

LureBench is defensive security research: it measures how well fraud detectors
work and where they fail. It necessarily contains material that looks offensive
in isolation (fraud lures, evasion attacks), so this policy covers both
conventional vulnerabilities and the dual-use questions specific to this kind of
project.

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting form][report] whenever possible.
Reports submitted there are visible only to the reporter and repository
maintainers. If GitHub reporting is unavailable, email **immu4989@gmail.com**.
Please do not open a public issue for anything that could be exploited before a
fix ships.

[report]: https://github.com/immu4989/lurebench/security/advisories/new

Include what you have: affected version or commit, reproduction steps, and the
impact you see. A rough report sent promptly is more useful than a polished one
sent late.

Expect an acknowledgement within **5 working days** and an assessment within
**15 working days**. This is a single-maintainer research project, not a vendor
with an on-call rotation, so those are honest targets rather than an SLA. You
will get credit in the changelog for anything you report unless you ask
otherwise.

## What is in scope

- Code execution, path traversal, or injection reachable through the CLI, the
  harness, or dataset loading.
- Anything that causes the library to make network calls a user did not ask for,
  or to send corpus text to an endpoint they did not configure.
- Leakage of provider API keys through logs, caches, error messages, or files
  written to disk.
- Undefanged content in a shipped data shard: a real working URL, real contact
  details, real payment rails, or real personal data. See [DATA.md](DATA.md).
- Dependency vulnerabilities that are actually reachable from this code.
- LurePermit, LureRange, LureInvariant, LureIdentity, runtime, topology,
  telemetry, or LureRevoke evaluators producing a passing result from
  contradictory inputs, incomplete required observations, alternate authority
  paths, altered bindings, contaminated controls, or incorrectly recomputed
  metrics.
- LureIdentity telemetry accepting a log body, raw directory or workload
  identity, unknown attribute, mismatched receiver/node, reused trace context,
  or access timestamp not exactly bound to its preregistered probe.
- LureIdentity campaign composition omitting a derived cut, accepting a partial
  actor deauthorization, failing to cover an unchanged unrelated authorization,
  producing duplicate or misphased probes, or bypassing its bounded matrix.
- LureArtifact accepting an omitted active workload, undeclared node, model,
  image, policy, AI-BOM, or provenance substitution, unapproved builder,
  executable/remote model code, unsafe serialization, changed identity-plan
  binding, contradictory summary, noncanonical JSON, or overwrite attempt.
- LureRecall omitting a transitive affected component, artifact root, workload,
  node, replacement, or probe; accepting a cycle, orphan, ambiguous VEX state,
  unbound advisory or lineage, recalled replacement digest, post-deadline
  compromised allow, wrong recovered artifact set, collateral block, altered
  metric, noncanonical JSON, or overwrite attempt while still reporting pass.
- LureAttest accepting an unbound artifact plan, missing or extra attestation
  or builder, unauthorized signer–builder mapping, signer–builder substitution,
  policy SLSA floor above reviewed builder trust, unsafe evidence
  filename, weakened fixed requirement, duplicate key, noncanonical JSON, or
  overwrite.
- LureBOM reconciliation accepting a changed primary or mirror document,
  duplicate JSON key, unsupported standard version, ambiguous SHA-256, inferred
  rather than reviewed identity, missing or extra component, incompatible
  component class, artifact digest/PURL drift, unknown/self/duplicate edge,
  one-sided dependency, hidden projection loss, altered metric or verdict,
  unsafe path, oversized input, or overwrite while still reporting pass.
- LureChannel accepting an unauthorized, residual, late, duplicate, or
  unexpected-path sighting while reporting pass; treating an incomplete sensor
  window or failed positive control as evidence of isolation; accepting
  contradictory run lifetimes, same-domain transfer tests, untested denied
  channels, changed bindings, duplicate canaries or identifiers, noncanonical
  JSON, unsafe paths, oversized input, or overwrite.
- SPIFFE parsing that admits ambiguous authority components, percent encoding,
  relative or empty path segments, Unicode, oversized IDs, or a root identity
  where a workload path is required; or disagreement between identity, runtime,
  topology, and public-schema validation.

## What is not a vulnerability

- **That the corpus contains fraud lures.** That is the dataset. Samples are
  defanged (`<<link>>`, `<<contact>>`), synthetic or sourced under the terms in
  [DATA.md](DATA.md), and exist so detectors can be measured against them.
- **That the attacks work.** `homoglyph`, `leet`, `zero-width`, `whitespace`, and
  the LLM rewrites are supposed to evade detectors. Measuring that is the point.
  A newly discovered evasion technique is a welcome *contribution*, not a report.
- **That a detector scores badly.** Detectors failing is a finding, and several
  such findings are published in `docs/`.

## Reporting a measurement error

This is unusual for a security policy, but for a benchmark it matters as much as
a memory-safety bug: a wrong number that people cite is a real harm.

If you believe a published result is incorrect, open a **public issue** with the
command you ran and what you observed. Public is right here because reproduction
is the whole value, and corrections belong in the open.

Known past examples, both corrected in the changelog: metrics computed only over
the records a detector chose to answer, so a model that declined half the corpus
scored a perfect 1.000; and single-run attack results reported as precise point
estimates when re-running moved them by up to 17 points.

## Repository supply-chain controls

Repository-wide CODEOWNERS coverage is included, but it has no enforcement
effect by itself. Enable branch or ruleset protection that requires code-owner
review, and protect workflow, benchmark-schema, and release-policy changes from
unilateral modification. Pin external GitHub Actions to reviewed full commit
SHAs.
Release builds are deliberately separated from the job that receives OIDC
attestation and GitHub Release write authority, reducing the privilege available
to package build backends.

LureChannel is intended only for authorized, operator-controlled environments.
Canaries must be non-sensitive and non-executable; never use credentials,
customer data, real prompts, personal data, or exploit payloads. Do not probe a
third-party service without authorization. Evaluations expose internal topology
identifiers and should remain private. A `complete` sensor window is an operator
assertion, not infrastructure discovery, and a passing declared matrix does not
prove that unknown or uninstrumented communication paths are absent.

## Acceptable use

This project is licensed under Apache-2.0, which does not restrict use. That is a
licensing fact, not an endorsement. The intended uses are evaluating detectors,
reproducing published results, and researching detection and defense.

Using this code or corpus to generate, personalize, or deliver fraud against real
people is outside the intent of the project and is a Code of Conduct violation
if it involves this community. Requests for help doing so will be refused and
the issue closed.

Generation of new lures requires your own provider key and is gated behind an
explicit review step (`review: pending` until promoted). No provider key ships
with this repository, and the OpenAI-compatible client never contacts
`api.openai.com` or `api.anthropic.com` unless you configure it to.

## Supported versions

The `main` branch is supported. Fixes ship in the next release rather than as
backports to older tags.
