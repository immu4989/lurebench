# Leaderboard

MCC is the headline metric. Detection rate (recall) and FPR matter because a fraud detector is only useful at a tolerable false-positive rate.

_Generated from **data/full/core/test.jsonl** (2056 records)._

## Task: `fraud` (lure vs. benign)

| Detector | MCC | TPR | FPR | F1 | AUC |
|---|---|---|---|---|---|
| `heuristic-v0` | 0.120 | 0.212 | 0.123 | 0.304 | 0.578 |
| `tfidf-logreg` | 0.910 | 0.963 | 0.049 | 0.946 | 0.992 |

### Detection rate by fraud typology

| Detector | `phishing` | `bec` | `romance` | `pig_butchering` |
|---|---|---|---|---|
| `heuristic-v0` | 0.199 | 0.826 | 0.148 | 0.091 |
| `tfidf-logreg` | 0.963 | 0.957 | 1.000 | 0.955 |
