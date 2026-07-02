# LureBench shard specification (v1)

This is the concrete build target for `lurebench-core-v1`. It defines splits,
naming, the coverage matrix, balance targets, the provenance-labeling protocol,
and the controlled-generation protocol for scarce typologies.

## Splits

| Split | Purpose | Labels | Frozen? |
|---|---|---|---|
| `train` | model / detector development | public | grows across minor versions |
| `test` | headline leaderboard numbers | public | **frozen within a major version** |
| `heldout` | future hidden-label leaderboard | withheld | reserved for v2 |

Split assignment is by stratified hash of the record `id` so that adding new
`train` data never leaks into `test`. Near-duplicate texts (normalized-hash
collisions) are forced into the same split.

## Naming

- Hub dataset: `lurebench/core` with config `v1` and the three splits above.
- Reporting slices (views over the same records, not separate files):
  `typology={phishing,bec,romance,pig_butchering}`,
  `source={ai,human}`, `generator=<id>`, `language=<code>`, `channel=<id>`.

Report the headline as MCC on `test`, then the per-typology and per-generator
slice table. The story of this benchmark is in the slices — a detector that is
strong on human phishing and weak on `deepseek`-generated `pig_butchering` is
exactly what LureBench should expose.

## Coverage matrix (v1 target)

Generators (AI provenance) — spread instances across at least:

`gpt-4o`, `gpt-4o-mini`, `claude-3.5`, `llama-3-70b`, `mistral-large`,
`qwen-2.5`, `deepseek-v3`, `gemini-1.5`. A `wormgpt`/uncensored-derivative bucket
is included where public data exists (e.g. the Greco corpus) to represent
purpose-built abuse models.

| Typology | Human source | AI source | v1 confidence |
|---|---|---|---|
| `phishing` | Nazario, Nigerian-419, SpamAssassin | Greco, e-PhishGen, DataPhish, GPT-o1/Cialdini set | high (public data exists) |
| `benign` | Enron ham, SpamAssassin ham | rephrased-legit from DataPhish | high |
| `bec` | limited public; reported-incident text | **controlled generation** | medium (gap) |
| `romance` | scam-report excerpts | romance-baiting corpus (2512.16280) | medium |
| `pig_butchering` | limited public | **controlled generation** + romance-baiting | low (largest gap) |

The two `controlled generation` cells are where LureBench adds new data, because
public BEC and pig-butchering corpora are the thinnest. That is also where the
benchmark is most novel.

## Balance targets

- Corpus level: fraud:benign ≈ 50:50 (±5pp).
- Within fraud: no typology below 15% or above 35% of fraud instances.
- Within each typology: both `source` values present; AI instances spread so no
  single generator exceeds ~30% of that typology's AI rows.
- Languages: English primary; Italian carried from e-PhishGen; add others only
  with a documented human/AI pair.

Ship a `manifest.json` per shard with the realized counts for every
typology × source × generator × language cell, so imbalance is visible rather
than hidden.

## Provenance-labeling protocol

`source` and `generator` are assigned from **origin**, never inferred:

- Text from a human-written corpus → `source: human`, `generator: null`.
- Text from an LLM-generated corpus or LureBench controlled generation →
  `source: ai`, `generator: <model-id>`.

Never label provenance with a detector. Doing so would make the benchmark measure
agreement with that detector instead of ground truth.

## Controlled-generation protocol (BEC, pig-butchering)

For typologies with scarce public data, LureBench generates synthetic lures under
a recorded, auditable protocol:

1. **Prompts and seeds are logged** (typology, persona, persuasion target,
   generator, decoding params) and released alongside the data.
2. **Output is defanged** at generation time (placeholders for links/contacts;
   no real institutions, no working payment rails).
3. **Human review** removes any sample that names a real person/entity with
   actionable detail or that constitutes operational instructions.
4. **No delivery tooling** is written or released — generation produces detector
   training/eval text only.
5. Each generated record carries `meta.generation = {prompt_id, params}` for
   reproducibility.

## Dedup and quality gates

- Normalized-text SHA1 dedup across all sources before split assignment.
- Drop records under a minimum token length or that fail schema validation.
- Language detection cross-check against the declared `language`.
- A held-back 5% is manually spot-checked per release; results noted in the
  changelog.

## Build

The corpus is assembled by the adapters in [`lurebench/ingest/`](../lurebench/ingest/)
plus the controlled-generation step. Each incorporated source is registered in
[sources.md](sources.md) with its license and citation. Sources whose license
forbids redistribution are pointer-only: the build reads a locally-downloaded
copy and emits normalized records, which are released only where the upstream
license permits.
