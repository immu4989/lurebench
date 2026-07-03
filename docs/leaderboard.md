# Leaderboard

MCC is the headline metric. Detection rate (recall) and FPR matter because a fraud detector is only useful at a tolerable false-positive rate.

_Generated from **data/full/core/test.jsonl** (2055 records)._

## Task: `fraud` (lure vs. benign)

| Detector | MCC | TPR | FPR | F1 | AUC |
|---|---|---|---|---|---|
| `heuristic-v0` | 0.099 | 0.173 | 0.105 | 0.260 | 0.524 |

### Detection rate by fraud typology

| Detector | `phishing` | `bec` | `romance` | `pig_butchering` |
|---|---|---|---|---|
| `heuristic-v0` | 0.156 | 0.826 | 0.148 | 0.071 |
