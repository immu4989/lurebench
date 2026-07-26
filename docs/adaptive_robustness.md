# Adaptive robustness: attempts to evade

A real attacker does not stop after one rewrite. Each row attacks only the lures that detector caught on clean text, paraphrasing repeatedly until the score falls below the threshold or the 5-round budget runs out. The rewrite is instructed to preserve the message's intent, so an 'evasion' that simply dropped the fraudulent ask does not count.

**Every rate is the mean of 3 independent replicates, with the observed range in brackets.** One run is not enough: hosted providers are not bit-deterministic even at temperature 0, so re-running the same setup produces a different attack chain and a materially different rate. An earlier single-run version of this table reported numbers that moved by up to 20 points on re-run.

_Attacker `deepseek/deepseek-v4-flash` · data/full/core/test.jsonl · threshold 0.50._

| Detector | caught clean | evaded (mean [min-max]) | ≤1 | ≤2 | ≤3 | ≤4 | ≤5 |
|---|---|---|---|---|---|---|---|
| `tfidf-logreg` | 58/60 | 9% [9%-10%] | 1% | 2% | 4% | 6% | 9% |
| `llm-judge (openai/gpt-5-nano)` | 35/60 | 35% [29%-46%] | 14% | 23% | 25% | 31% | 35% |
| `llm-judge (deepseek/deepseek-v4-flash)` | 43/60 | 40% [37%-42%] | 15% | 25% | 28% | 36% | 40% |

The cumulative columns show how quickly a detector gives way as the attacker keeps trying. A detector whose ≤1 column is low but whose ≤5 column is high is not resisting the attack, only delaying it.

This inverts the character-attack result. Against homoglyphs and zero-width padding the token baselines collapse and the LLM judges are essentially immune, because those attacks change spelling and the judges read meaning. Against an attacker that rewrites *meaning* the ordering reverses: the trained TF-IDF model is the hardest to get past. The two families fail in complementary directions, which is an argument for running both rather than picking a winner. Read the ranges before leaning on any single gap — some are wider than the differences between detectors.

Caveat: the attacker (`deepseek/deepseek-v4-flash`) is also one of the defenders, so some of that row's evasion is likely self-coupling. Each row's denominator is only the lures that detector caught clean, so rows are not scored on identical sets.
