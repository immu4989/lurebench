# Adversarial robustness

A detector's clean-data accuracy is the wrong number to trust in production. A real
fraudster does not send you the lure your detector was trained on — they perturb it
until it slips through. The robustness suite measures exactly that: take the lures a
detector **catches** on clean text, apply an attack a real adversary could run, and
count how many now evade.

The headline metric is **attack success rate (ASR)**:

> Of the lures a detector caught on clean text, the fraction that evade after the attack.

ASR of 0.0 means the attack changed nothing; ASR of 1.0 means the detector is fully
defeated on the messages it used to catch. It is deliberately conditioned on the
clean catches, so a detector that already misses everything cannot look "robust" —
it simply has nothing left to lose.

## Attacks

Two families, mirroring the two tiers of real adversary.

**Character-level (dependency-free, deterministic).** The attacks a fraudster runs
for free with no model at all. They keep the message readable to a human victim but
break the exact-token matching that keyword and bag-of-words detectors rely on.

| Attack | What it does | Example (`verify`) |
|---|---|---|
| `homoglyph` | Latin → confusable Cyrillic/Greek lookalikes | `vеrifу` |
| `leet` | Letter → digit substitution | `v3r1fy` |
| `zero-width` | Insert invisible U+200B between characters | `ver​ify` |
| `whitespace` | Split long words with a space | `ver ify` |

All four are deterministic — the same input always yields the same output, so
results are reproducible with no seed to pin.

**LLM-driven (needs a provider key).** The stronger attacker who has a model:

| Attack | What it does |
|---|---|
| `llm-paraphrase` | Rewrite preserving intent and length but sharing no surface text |
| `llm-keyword-evasion` | Rewrite while avoiding the detector's most predictive words (a targeted attack — the word list is pulled from the model itself for linear detectors) |

These reuse the OpenAI-compatible provider plumbing (any provider by name, your own
key); they never call api.openai.com or api.anthropic.com.

## Running it

```bash
# Stress-test the keyword baseline against every free attack
lurebench robustness -d data/full/core/test.jsonl -m heuristic-v0 \
  -a homoglyph -a leet -a zero-width -a whitespace

# Same for the trained baseline, as JSON
lurebench robustness -d data/full/core/test.jsonl -m tfidf-logreg \
  -a homoglyph -a leet --json

# An LLM attack needs a provider engine and that provider's key in the environment
lurebench robustness -d data/full/core/test.jsonl -m tfidf-logreg \
  -a llm-keyword-evasion --engine deepseek
```

Programmatically:

```python
from lurebench.robustness import run_robustness
from lurebench.attacks import get_attack
from lurebench.detectors import get_detector
from lurebench.harness import load_jsonl

report = run_robustness(
    get_detector("tfidf-logreg"),
    load_jsonl("data/full/core/test.jsonl"),
    get_attack("homoglyph"),
)
print(report.summary_line())
```

## What the baselines show

On `lurebench-core` (test split), the two shipped baselines separate sharply — which
is the point: robustness is a *different axis* from clean accuracy, and it ranks
detectors differently.

**`heuristic-v0`** (hand-written keyword rules) — clean recall 0.21, and almost
totally defeated by any character-level attack:

| Attack | ASR | attacked recall |
|---|---|---|
| `homoglyph` | 0.99 | 0.00 |
| `leet` | 0.99 | 0.00 |
| `zero-width` | 1.00 | 0.00 |
| `whitespace` | 0.52 | 0.10 |

**`tfidf-logreg`** (trained word/bigram TF-IDF) — clean recall 0.96, and far more
resilient, because sub-word features and normalization absorb much of the noise:

| Attack | ASR | attacked recall |
|---|---|---|
| `homoglyph` | 0.38 | 0.60 |
| `leet` | 0.16 | 0.81 |
| `zero-width` | 0.03 | 0.94 |
| `whitespace` | 0.00 | 0.96 |

The keyword rules look cheap and interpretable until an attacker types `vеrifу` once;
the trained model degrades gracefully instead of collapsing. Homoglyph substitution
is the most effective free attack against both — worth knowing before you deploy
either. (Numbers regenerate from the commands above; they are not hand-entered.)

## Interpreting ASR honestly

- **ASR is conditioned on clean catches.** A detector with clean recall 0.05 that
  keeps its 5% under attack has low ASR but is still useless. Always read ASR next to
  clean recall, never alone.
- **Character attacks favor whichever detector normalizes input.** A detector that
  strips zero-width characters or Unicode-folds homoglyphs before scoring will show
  low ASR on those specific attacks — that is a real defense, and the suite is meant
  to reward it.
- **The LLM attacks are the harder bar.** Character tricks are caught by input
  sanitization; a fluent paraphrase is not. A detector that survives
  `llm-keyword-evasion` is genuinely robust; one that only survives `homoglyph` has
  just told you to add a normalization step.
