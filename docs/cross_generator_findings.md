# Cross-generator & provenance evaluation — findings

Run: `python scripts/eval_cross_generator.py` (LOGO = leave-one-generator-out).
These experiments stress-test what the random-split leaderboard cannot:
generalization across generators, and whether AI-authored fraud is separable
from human-authored fraud.

## Results (lurebench-core v1: 20,393 records, 540 AI across 3 generators)

**LOGO — fraud detection** (recall on a held-out generator the detector never saw):

| Held-out generator | Recall |
|---|---|
| deepseek-v4-pro | 0.921 |
| glm-4.6 | 0.907 |
| mistral-large-latest | 0.965 |

**LOGO — provenance** (flag AI-authored among fraud lures; human phishing = negative):

| Held-out generator | AI-recall | human-FPR |
|---|---|---|
| deepseek-v4-pro | 0.979 | 0.001 |
| glm-4.6 | 0.973 | 0.001 |
| mistral-large-latest | 1.000 | 0.001 |

At face value: AI fraud is caught even cross-generator, and AI-vs-human
separates near-perfectly. **That conclusion is wrong** — see below.

## The separation is a dataset artifact, not AI-detection

Inspecting the provenance model's top features shows it separates
**corpus-of-origin**, not authorship:

- **Defang inconsistency:** `<<link>>` appears in 69% of AI lures vs 12% of human
  phishing. Top *human* features are `http`, `www`, `com` — raw URL fragments the
  human-shard defang left behind. The model partly detects which corpus defanged
  its URLs.
- **Length:** human phishing averages 283 words; AI lures 81 — nearly separable on
  length alone.
- **Register/era:** human features are old-school spam (`click here`, `free`,
  `now`); AI features are modern polite prose (`hi`, `hey`, `thanks`, `could you`).
- **Format:** AI lures carry `Subject:` lines; the human corpus mostly does not.

When the positive and negative classes come from different sources, a classifier
learns the source. The 0.1% FPR with ~100% recall is the signature of that
confound, not of an easy detection problem.

## Implications

1. **The provenance task is not yet valid.** A credible "can you detect
   AI-authored fraud?" benchmark needs human and AI lures matched in distribution
   — same typologies, same defang, comparable length and register. Ideally
   human-written and AI-written versions of the *same* scenarios.
2. **Fix defang consistency** in the human shard (bare domains like `example.com`
   and residual `http`/`www` fragments) so placeholder usage isn't a tell.
3. **The fraud-vs-benign task remains solvable** by a trained model (MCC 0.909),
   largely a classical human-phishing-vs-benign result; the AI slices are small
   and stylistically homogeneous.

## Honest status

lurebench-core v1 is a well-engineered pilot that demonstrates the pipeline and
exposes these issues rigorously. It is **not yet** a benchmark that supports a
clean "detectors fail on AI-generated fraud" claim, because the human and AI
classes are confounded. Closing that gap (distribution-matched human/AI data,
consistent defang, larger and more diverse AI generation) is the work before a
credible public release.
