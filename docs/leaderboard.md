# Leaderboard

MCC is the headline metric. Detection rate (recall) and FPR matter because a fraud detector is only useful at a tolerable false-positive rate.

_Generated from **data/samples/lures.jsonl** (16 records)._

## Task: `fraud` (lure vs. benign)

| Detector | MCC | TPR | FPR | F1 | AUC |
|---|---|---|---|---|---|
| `heuristic-v0` | 0.878 | 0.900 | 0.000 | 0.947 | 1.000 |

### Detection rate by fraud typology

| Detector | `phishing` | `bec` | `romance` | `pig_butchering` |
|---|---|---|---|---|
| `heuristic-v0` | 1.000 | 1.000 | 0.000 | 1.000 |

## Not run

- `binoculars`: ImportError: BinocularsDetector requires the 'binoculars' package.
- `llama-guard-3`: OSError: You are trying to access a gated repo.
- `openai-moderation`: ImportError: OpenAIModerationDetector requires the 'openai' extra.
