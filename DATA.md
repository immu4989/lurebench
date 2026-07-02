# Data policy

LureBench is a defensive benchmark. This document describes what data the project
holds, how it is handled, and what it will not do.

## Record schema

Every record is a JSON object with the fields defined in
[`lurebench/schema.py`](lurebench/schema.py):

| Field | Meaning |
|---|---|
| `id` | Stable unique identifier |
| `text` | Message text (defanged for fraud samples) |
| `label` | `1` = fraud lure, `0` = benign (target of the `fraud` task) |
| `source` | `ai` or `human` (target of the `provenance` task) |
| `typology` | `phishing`, `bec`, `romance`, `pig_butchering`, or `benign` |
| `generator` | Model id for AI text, else `null` |
| `language` | ISO 639-1 code |
| `channel` | `email`, `sms`, `chat`, `social`, `voice_transcript` |
| `persuasion` | Cialdini-style tags (`urgency`, `authority`, ...) |
| `meta` | Free-form provenance metadata |

## Defanging

Fraud samples are defanged before release:

- URLs are replaced with `<<link>>`.
- Off-platform contact hand-offs are replaced with `<<contact>>`.
- No real personal data, real institutions, working payment details, or live
  infrastructure appear in released records.

The `data/samples/` shard is a tiny illustrative set for smoke-testing the
harness. It is **not** a benchmark split and should not be used to report results.

## What is not in this repo

- No code to generate, personalize, or deliver fraud campaigns.
- No live URLs, phone numbers, wallet addresses, or credential-harvesting kits.
- Restricted or license-encumbered source corpora are referenced, not
  redistributed. Any such material lives behind a request process, and the
  ignored paths `data/restricted/` and `data/full/` are never committed.

## Provenance and licensing of incorporated corpora

Where LureBench incorporates or maps to existing public datasets, each is listed
with its original license and citation. Datasets that prohibit redistribution are
referenced by pointer only.
