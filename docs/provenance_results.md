# Provenance results: the confound, and its removal

The question: **can a detector tell AI-authored fraud from human-authored fraud,
and does it generalize across generators?** Getting a *credible* answer required
removing a dataset confound first.

## The confound (naive corpus)

Training TF-IDF + logistic regression to separate AI lures from human phishing on
the raw corpus gives **perfect** cross-generator separation. Leave-one-generator-out
(train on the other generators, test on the held-out one):

| Held-out generator | AUC |
|---|---|
| deepseek-v4-pro | 1.000 |
| glm-4.6 | 1.000 |
| mistral-large-latest | 1.000 |

That is **not** AI-detection. Feature inspection showed the model separating
*corpus-of-origin*: `<<link>>` in most AI lures vs raw `http`/`www`/`com` in the
human shard, human phishing averaging far more words than AI, the human corpus
being pre-tokenized (spaces around punctuation), and era/register differences. When
the positive and negative classes come from different sources, a classifier learns
the source. A perfect AUC on a hard problem is the signature of that artifact.

## The fix

1. **De-tokenize** the human corpus to natural prose and rejoin spaced URLs
   (`detokenize`), bounded so legit words like "net income" survive.
2. **Strengthen defang** to strip HTML and bare domains (`Mail.com`), placeholder-safe.
3. **Paired rewriting**: have each LLM rewrite the *same* human lure — matched
   scenario, typology, and length — so the only remaining signal is authorship.

After this, human and AI lengths match (98 vs 96 words) and defang usage is
consistent.

## The distribution-matched result

300 human phishing seeds, paired AI rewrites across three generators (DeepSeek 222,
GLM 250, Mistral 300; 772 AI total). Leave-one-generator-out:

| Held-out generator | AUC | balanced accuracy | (recall / FPR @ 0.5) |
|---|---|---|---|
| deepseek-v4-pro | **0.583** | 0.533 | 0.55 / 0.48 |
| glm-4.6 | **0.574** | 0.552 | 0.50 / 0.40 |
| mistral-large-latest | 0.835 | 0.627 | 0.99 / 0.73 |

Chance is 0.50. Top features are now genuine authorship style (AI: `just`, `hey`,
`fast`, `secure`, `opt out`; human: `information`, `would`, `software`, `made`),
not defang, length, or era artifacts.

## What this means

- The perfect naive AUC was an artifact. Once removed, distinguishing AI-authored
  fraud from human-authored fraud **across held-out generators is close to a coin
  flip** for two of three generators (AUC 0.57–0.58, balanced accuracy ~0.53–0.55).
- One generator's output (Mistral) carries a more detectable stylistic signature
  (AUC 0.835), but it does not transfer: a detector trained on DeepSeek and GLM
  barely beats chance on Mistral's calibration, and vice versa.
- The high false-positive rates at a 0.5 threshold (0.40–0.73) show the detector is
  not cleanly separating; it leans toward calling text AI once trained on several
  generators. AUC and balanced accuracy are the honest, threshold-independent read.

This is the confound-controlled evidence for the benchmark's thesis: detecting
AI-generated fraud, and generalizing across the models that produce it, is an open
problem, not a solved one.

## Honest limitations

- Three generators, phishing only (the human data is phishing-only).
- The human corpus is older-era phishing; de-tokenization and rewriting remove the
  largest tells, and the residual signal is register/style, but a contemporary
  human-fraud source would be stronger still.
- Reproduce with `python scripts/build_paired_provenance.py` per generator, then
  `python scripts/eval_paired_provenance.py`.
