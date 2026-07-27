# Security Policy

LureBench is defensive security research: it measures how well fraud detectors
work and where they fail. It necessarily contains material that looks offensive
in isolation (fraud lures, evasion attacks), so this policy covers both
conventional vulnerabilities and the dual-use questions specific to this kind of
project.

## Reporting a vulnerability

Report privately to **immu4989@gmail.com**. Please do not open a public issue for
anything that could be exploited before a fix ships.

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
