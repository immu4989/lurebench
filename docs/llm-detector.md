# `llm-judge` — the strongest detector you can actually run

Until now LureBench's detectors split into two useless-for-most-people groups: weak
baselines anyone can run (`heuristic-v0`, `tfidf-logreg`) and strong detectors gated
behind a GPU (`llama-guard-3`, `binoculars`) or OpenAI credits (`openai-moderation`). A
company asking "can I detect AI fraud lures?" downloaded the repo and found nothing that
both works and runs.

`llm-judge` fills that hole. It asks a large language model — over the same
OpenAI-compatible provider plumbing that powers generation (DeepSeek, GLM, Mistral, …;
your own key, never api.openai.com or api.anthropic.com) — for a 0–100 fraud-likelihood,
mapped to a probability. It slots into every existing harness, so the interesting question
isn't "is it good" (it is) but **does it survive the checks that broke the baselines?**

```bash
export DEEPSEEK_API_KEY=...        # or MISTRAL_API_KEY, ZHIPUAI_API_KEY, ...
lurebench eval -d data/full/core/test.jsonl -m llm-judge
```

Scoring the entire multilingual + robustness experiments below cost **under $0.50** on
DeepSeek. It is one API call per message, so it is slower and costlier than a local
model — the tradeoff for reading meaning instead of tokens.

## It closes the cross-lingual gap

LureBench's [multilingual finding](multilingual.md) was that `tfidf-logreg`'s ~1.00
recall in every language was an artifact: strip the `<<link>>` placeholder and non-Latin
scripts collapse, because the model has no tokens for them. `llm-judge` reads the language
itself, so it should hold. It does. Per-language recall, raw and artifact-controlled
(placeholder stripped), on the same eval set:

| Language | Script | `tfidf-logreg` raw→ctrl | `llm-judge` raw→ctrl |
|---|---|---|---|
| English | Latin | 0.97 → 0.97 | 0.76 → 0.68 |
| Spanish | Latin | 1.00 → 1.00 | 0.94 → 0.80 |
| French | Latin | 1.00 → 0.96 | 1.00 → 0.96 |
| German | Latin | 1.00 → 1.00 | 1.00 → 0.96 |
| Italian | Latin | 1.00 → 0.91 | 0.86 → 0.72 |
| Portuguese | Latin | 0.93 → 0.79 | 0.93 → 0.70 |
| **Chinese** | Han | 1.00 → **0.09** | 0.87 → **0.91** |
| **Russian** | Cyrillic | 0.94 → **0.06** | 0.97 → **0.97** |
| **Arabic** | Arabic | 0.98 → **0.04** | 1.00 → **0.95** |

On the three non-Latin scripts, artifact-controlled recall goes from **~0.06 (tfidf) to
~0.94 (llm-judge)**. The LLM is reading the fraud, not the URL that got redacted.

Read it honestly, though:

- **The LLM's *raw* recall is lower than tfidf's** in several languages (English 0.76,
  Italian 0.86). That is the LLM being *right*: tfidf's raw ~1.00 was inflated by flagging
  everything with a `<<link>>`, while the LLM genuinely misses some deliberately subtle
  hard-mode lures. Lower, but real.
- **The LLM does use the placeholder as a minor signal.** Latin-script recall drops
  ~10–20 points under artifact control (Spanish 0.94→0.80, Portuguese 0.93→0.70). It
  leans on "there was a link" a little — it just doesn't *collapse* to it the way tfidf
  does, and on non-Latin scripts it barely moves.

## It survives the attacks that broke the keyword detector

The [character attacks](adversarial-robustness.md) drove `heuristic-v0`'s attack success
rate (share of caught lures that evade after the attack) to ~1.00 and dented `tfidf`. An
LLM reads *through* `vеrify` and `v3r1fy`, so it should hold. On an identical sample of
caught fraud lures:

| Attack | `heuristic-v0` | `tfidf-logreg` | `llm-judge` |
|---|---|---|---|
| homoglyph | 1.00 | 0.47 | **0.08** |
| leet | 1.00 | 0.13 | **0.04** |
| zero-width | 1.00 | 0.00 | 0.08 |
| whitespace | 0.78 | 0.00 | 0.04 |
| **paraphrase** (LLM rewrite) | — | — | **0.17** |

Character tricks that shatter token-based detectors barely register (ASR 0.04–0.08). The
LLM's real vulnerability is the one attack that changes *meaning* rather than characters: a
full **LLM paraphrase** evades it ~17% of the time. That is the honest headline — you do
not beat a semantic detector by mangling letters; you beat it by rewriting the lure.

## Honest limitations

- **Pilot scale.** The cross-lingual comparison is 21–56 lures per language; the robustness
  comparison is 30 caught lures. The effects are categorical (0.06 vs 0.94; 1.00 vs 0.08),
  not marginal, but these are not precise rates.
- **One provider, one model.** All numbers are DeepSeek. Other providers/models will
  differ; the harness makes re-running on Mistral/GLM a one-flag change.
- **Cost and latency.** One API call per message. Fine for triage and evaluation, not for
  line-rate filtering of high-volume streams without batching/caching.
- **The paraphrase weakness is real.** A motivated adversary with an LLM can rewrite past
  it. That is a genuine limit of any content-based detector, surfaced rather than hidden.

Scores for both experiments are cached in `data/full/multilingual/llm_scores_deepseek.json`
and `llm_robust_deepseek.json`, and regenerate with `scripts/score_llm_multilingual.py`
and `scripts/score_llm_robustness.py`.
