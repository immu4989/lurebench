# Adaptive robustness: attempts to evade

A real attacker does not stop after one rewrite. Each row attacks only the lures that detector caught on clean text (there is nothing to evade otherwise), paraphrasing repeatedly until the score falls below the threshold or the 5-round budget runs out. The rewrite is instructed to preserve the message's intent, so an 'evasion' that simply dropped the fraudulent ask does not count.

_Attacker `deepseek/deepseek-v4-flash` · data/full/core/test.jsonl · threshold 0.50._

| Detector | caught clean | evaded within budget | median attempts | ≤1 | ≤2 | ≤3 | ≤4 | ≤5 |
|---|---|---|---|---|---|---|---|---|---|
| `tfidf-logreg` | 58/60 | 12% | 4 | 2% | 2% | 3% | 7% | 12% |
| `llm-judge (openai/gpt-5-nano)` | 35/60 | 23% | 2 | 11% | 23% | 23% | 23% | 23% |
| `llm-judge (deepseek/deepseek-v4-flash)` | 43/60 | 37% | 2 | 16% | 26% | 33% | 33% | 37% |

The cumulative columns are the point: they show how quickly a detector gives way as the attacker keeps trying. A detector whose ≤1 column is low but whose ≤5 column is high is not resisting the attack, only delaying it.

This table inverts the character-attack result. Against homoglyphs and zero-width padding the token baselines collapse and the LLM judges are essentially immune, because those attacks change spelling and the judges read meaning. Against an attacker that rewrites *meaning* the ordering reverses: the trained TF-IDF model is the hardest to get past, while the judges give way — and keep giving way as the budget grows, which is the signature of delay rather than resistance. The two detector families fail in complementary directions, which is an argument for running both rather than picking a winner.

Caveat: the attacker (`deepseek/deepseek-v4-flash`) is also one of the defenders, and that row is the most evadable. Some of that gap is likely self-coupling — a model rewriting text to get past itself — so read the cross-vendor rows as the cleaner measurement. Each row's denominator is only the lures that detector caught clean, so rows are not scored on identical sets.

These numbers are a **lower bound**. The attacker runs at temperature 0 so the experiment reproduces exactly, but a deterministic rewriter can converge: once it settles into a phrasing, further rounds rewrite that same phrasing the same way and stop finding new ground. Where a row's cumulative columns go flat, that is what happened — the budget was not exhausted, the attacker was. A sampling attacker (`temperature > 0`) explores more and evades more; an earlier temperature-1.0 run of this same setup put the judges a few points higher (26% and 44% against 23% and 37% here). Reproducibility was worth that trade, but do not read these rates as the ceiling.
