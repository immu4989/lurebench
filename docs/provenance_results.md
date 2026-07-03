# Provenance results: the confound, and its removal

The question: **can a detector tell AI-authored fraud from human-authored fraud,
and does it generalize across generators?** Getting a *credible* answer required
removing a dataset confound first.

## The confound (naive corpus)

Training TF-IDF + logistic regression to separate AI lures from human phishing on
the raw corpus gave near-perfect, cross-generator-robust separation:

| Held-out generator | AI-recall | human-FPR |
|---|---|---|
| deepseek-v4-pro | 0.979 | 0.001 |
| mistral-large-latest | 1.000 | 0.001 |

That is **not** AI-detection. Feature inspection showed the model separating
*corpus-of-origin*: `<<link>>` in 69% of AI vs 12% of human, raw `http`/`www`/`com`
in the human shard, human phishing averaging 283 words vs 81 for AI, and the human
corpus being pre-tokenized (spaces around punctuation). A 0.1% FPR with ~100%
recall is the signature of that artifact.

## The fix

1. **De-tokenize** the human corpus to natural prose and rejoin spaced URLs
   (`detokenize`), bounded so legit words like "net income" survive.
2. **Strengthen defang** to strip HTML and bare domains (`Mail.com`), placeholder-safe.
3. **Paired rewriting**: have each LLM rewrite the *same* human lure — matched
   scenario, typology, and length — so the only remaining signal is authorship.

After this, human and AI lengths match (98 vs 97 words), and defang usage is
consistent.

## The distribution-matched result

300 human phishing seeds, paired AI rewrites (Mistral 300, DeepSeek 84):

**Leave-one-generator-out** (train excludes the held-out generator):

| Held-out generator | AI-recall | human-FPR | test AI |
|---|---|---|---|
| deepseek-v4-pro | 0.321 | 0.100 | 84 |
| mistral-large-latest | 0.557 | 0.183 | 300 |

Top features are now genuine authorship style — AI: `just`, `hey`, `'ve`, `don'`,
`now`, `exclusive`; human: `please`, `information`, `do you`, `will` — not defang,
length, or era artifacts.

## What this means

- The confounded ~1.00 recall / 0.001 FPR was an artifact. Once removed, detecting
  AI-authored fraud is **hard and does not generalize across generators**: a
  detector trained on one generator catches 32–56% of a held-out generator's
  lures, at a 10–18% false-positive rate.
- This is the confound-controlled evidence for the benchmark's thesis. It is a
  defensible, non-trivial claim.

## Honest limitations

- Two generators, phishing only (the human data is phishing-only).
- DeepSeek yield was low (84/150) — reasoning-model empties — so its numbers are
  smaller-sample; its in-distribution recall (0.00 on 17 test) is noisy.
- The human corpus is still older-era phishing; rewriting + de-tokenization remove
  the largest tells, and the residual signal is register/style (arguably a
  legitimate authorship signal), but a contemporary human-fraud source would be
  stronger still.
- Scaling to more generators and more seeds would tighten the numbers.
