---
title: 'LureBench: a benchmark and evaluation harness for detecting AI-generated fraud lures'
tags:
  - Python
  - security
  - fraud detection
  - phishing
  - machine-generated text detection
  - adversarial robustness
authors:
  - name: Imran Ahamed
    orcid: 0009-0002-7717-7480
    affiliation: 1
affiliations:
  - name: Independent Researcher
    index: 1
date: 27 July 2026
bibliography: paper.bib
---

<!--
STATUS: unsubmitted draft. Kept in the repository so the framing stays in step
with the code, not because a submission is pending. Before submitting anywhere,
re-verify: every citation in paper.bib (none were checked against the published
record), the numbers quoted below against the current docs/, and the target
venue's own criteria for scope and project maturity.
-->

# Summary

Large language models have made it cheap to write fluent, targeted fraud: phishing
mail, business email compromise, romance and "pig-butchering" investment scams.
Defenders need to know whether their detectors still work on this text, and the
honest answer is difficult to obtain, because the obvious way to assemble a corpus
produces a benchmark that flatters every model tested on it.

LureBench is a Python benchmark and evaluation harness for that question. It
provides a single record schema, a distribution-matched corpus of human- and
AI-written fraud lures across four typologies and nine languages, a set of
detector baselines from keyword rules to a trained classifier to LLM-as-classifier
judges, and an adversarial layer of character-level and LLM-driven evasion
attacks. Detectors are scored on two tasks: `fraud` (is this a lure?) and
`provenance` (did a machine write it?). Everything runs with no model downloads
and no API keys; provider keys are needed only to generate new lures or to run the
LLM-backed detectors and attacks.

The design goal is that a result be reproducible and hard to overstate. Scores are
cached to disk so a published table can be regenerated for free; metrics report
how many records a detector actually answered, so a model that declines the hard
cases cannot be graded on the easy ones; and stochastic experiments are run as
replicates that report a range rather than a point estimate.

# Statement of need

Fraud detection is usually benchmarked on public spam corpora that predate
instruction-tuned language models. A detector that scores well there may or may
not survive contact with text a model wrote last week, and there has been no
common footing on which to check.

The harder problem is that assembling such a corpus naively introduces a
confound. Training a classifier to separate AI-written fraud from human-written
fraud on a naively assembled corpus yields a near-perfect cross-generator AUC of
1.00. Inspecting the model shows it has learned *corpus of origin* rather than
authorship: the human samples were older, longer, tokenized differently, and
defanged differently from the freshly generated text. Once each human lure is
paired with an AI rewrite of the same lure, matched on length and defanged
identically, cross-generator AUC falls to 0.58 and 0.57 for two of three
generators, barely above chance. LureBench ships both the confounded and the
corrected corpora, along with the procedure, so the effect can be reproduced
rather than taken on trust.

Two further results follow from the same harness and are, to the author's
knowledge, not otherwise available in one place. First, a trained TF-IDF baseline
appears to achieve near-perfect multilingual recall; stripping the defang
placeholders, which are language-invariant, collapses its recall on non-Latin
scripts to 0.04 for Arabic and 0.06 for Russian, exposing the earlier number as an
artifact rather than detection. Second, robustness ordering depends entirely on
the attack: character-level obfuscation destroys token-based detectors while
barely affecting LLM judges, whereas an attacker permitted to rewrite the message
repeatedly inverts the ranking. The two detector families fail in complementary
directions, which is an argument for deploying both rather than choosing one.

LureBench is aimed at security engineers benchmarking a detector before trusting
it, researchers extending the corpus or adding detectors (a detector is roughly
thirty lines), and analysts who need measured numbers rather than vendor claims
when reasoning about AI-enabled fraud.

# Functionality

The package exposes a command-line interface covering the pipeline: `ingest`,
`generate`, `assemble-core`, `train`, `eval`, `leaderboard`, `cross-generator`,
`robustness`, `multilingual`, `stix`, `manifest`, and `publish`. Detectors
implement a single `score` method and register in a lazy registry, so optional
heavy dependencies such as `torch` never burden a plain import. Baselines include
a keyword heuristic, a TF-IDF and logistic-regression classifier built on
scikit-learn [@pedregosa2011], the Binoculars perplexity detector for the
provenance task [@hans2024], the Llama Guard content-safety model [@inan2023],
and LLM-as-classifier judges reachable through any OpenAI-compatible provider.

Generation of new lures is deliberately constrained. Output is defanged (URLs
become `<<link>>`, contacts become `<<contact>>`), screened automatically, and
marked `review: pending` until a human promotes it, so synthetic fraud cannot
enter a shard unreviewed. The data conventions and their rationale are documented
in a datasheet [@gebru2021].

A companion project, LureScope, wraps the same detectors and attacks behind an
HTTP API and a browser demo, so a single message can be scored and stress-tested
interactively against the same code that produces the benchmark numbers.

# Acknowledgements

The corpus construction draws on persuasion categories from the social-influence
literature [@cialdini2007] for its typology tags.

# References
