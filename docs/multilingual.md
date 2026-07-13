# Multilingual fraud detection — and why the recall you see is a mirage

Fraud detectors are trained almost entirely on English. Fraud is not. The same lure is
sent in Spanish, Portuguese, Chinese, and dozens of other languages, and the populations
some scams target most are not English-first. So the obvious question is: how do
English-trained detectors do when the language shifts?

The answer turned out to be more interesting than "they fail" — and checking it carefully
is the whole point.

## The pilot set

Controlled-generation data: hard-mode AI lures produced in each language by a provider
that handles it well (Mistral for the European languages, DeepSeek for Chinese), under the
same defensive guardrails as the rest of LureBench (placeholders only, no real entities).
It covers `phishing` and `bec` in **Spanish (17), French (14), German (7), and Chinese
(19)**, evaluated against the **English AI lures already in `lurebench-core` (38)** as the
baseline. This is a pilot — the German cell in particular is thin — but the effect below
is categorical, not marginal.

## What a naive evaluation shows

Run the two baselines and look at raw recall (fraction of lures flagged):

| Detector | English | Spanish | French | German | Chinese |
|---|---|---|---|---|---|
| `tfidf-logreg` (trained) | 0.97 | 1.00 | 1.00 | 1.00 | 1.00 |
| `heuristic-v0` (keyword) | 0.68 | 0.00 | 0.07 | 0.29 | 0.00 |

Two different stories. The keyword detector collapses the moment the language changes —
unsurprising, it keys on English words. But the **trained model looks *perfectly*
cross-lingual**: 1.00 recall in every language, including Chinese. If you stopped here, you
would ship a press release saying LureBench's trained baseline detects fraud in any
language.

That would be wrong.

## What an honest evaluation shows

Every generated lure is defanged: a URL becomes `<<link>>`, which tokenizes to the word
`link` — one of the model's strongest fraud features, present in **every** language. So
"detection" might just be the model spotting that a URL was there, not reading the lure.
The `multilingual` command tests this directly by re-scoring with the placeholders
stripped (`--strip` is the default comparison view):

| Detector | Language | Recall (raw) | Recall (artifact-controlled) |
|---|---|---|---|
| `tfidf-logreg` | English | 0.97 | **0.97** |
| `tfidf-logreg` | Spanish | 1.00 | **1.00** |
| `tfidf-logreg` | French | 1.00 | **1.00** |
| `tfidf-logreg` | German | 1.00 | **1.00** |
| `tfidf-logreg` | Chinese | 1.00 | **0.05** |
| `heuristic-v0` | English | 0.68 | 0.08 |
| `heuristic-v0` | non-English | ≤0.29 | 0.00 |

Now the picture is real:

- **English and the European languages survive the control.** The trained model retains
  its recall on Spanish, French, and German even with the placeholder removed — because
  those languages share tokens with English (cognates, brand-neutral words, digits). This
  is genuine, if shallow, overlap.
- **Chinese collapses from 1.00 to 0.05.** A placeholder-stripped Chinese lure has
  **zero** tokens the English-trained model has ever seen. Its apparent perfect recall was
  *entirely* the `<<link>>` artifact. The model was never reading the fraud; it was
  detecting that a URL had been present.
- **Even the keyword detector's English recall is mostly the artifact** (0.68 → 0.08) — it
  leans far more on the link/hand-off signal than on its English trigger words.

```bash
lurebench multilingual -d data/full/multilingual/eval.jsonl -m tfidf-logreg -m heuristic-v0
```

## The claim, stated carefully

- **Not** "detectors fail on multilingual fraud" — too simple; the raw numbers look great.
- **Not** "LureBench's detector works in any language" — false; that recall is an artifact.
- **The actual finding:** an English-trained detector's cross-lingual recall is an
  illusion that a controlled evaluation dissolves. It survives only where the target
  language happens to share tokens with English (Latin-script, cognate-rich); on a
  distinct script it detects nothing once a single language-invariant artifact is removed.
  This is the same confound lesson LureBench documents for
  [provenance](provenance_results.md), now in the language dimension — and it is why the
  `multilingual` command reports the artifact-controlled column by default.

## Honest limitations

- **Pilot scale.** 17/14/7/19 lures per non-English language — enough for a categorical
  effect (1.00 → 0.05), not for precise per-language rates. German is thinnest.
- **Coverage.** Spanish, French, German, Chinese. Broader coverage (Hindi, Arabic,
  Tagalog, and other languages named in GenAI-fraud advisories) is future work.
- **Quality review.** European lures were spot-checked for fluency and guardrail
  compliance; the Chinese set was checked for structure, placeholder compliance, and
  on-topic content but not reviewed by a native speaker.

## Extending it

Generation is language-aware: `lurebench generate --typology phishing --language es
--engine mistral --hard` writes native-quality Spanish lures (add a name to
`LANGUAGE_NAMES` in `lurebench/generate/base.py` for anything not yet listed). Regenerate
the pilot with `python scripts/build_multilingual_pilot.py` (paced to respect provider
rate limits; saves after every lure).
