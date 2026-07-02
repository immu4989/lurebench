# Leaderboard

Results are reported per task. **MCC is the headline metric** — it is robust to
the class imbalance typical of fraud corpora. TPR (detection rate) and FPR are
reported alongside because a fraud detector is only useful at a tolerable
false-positive rate.

Numbers below are from the `data/samples/` smoke shard (16 records) and exist to
show the report format. **They are not benchmark results** — the real shards land
on the Hugging Face Hub.

## Task: `fraud` (lure vs. benign)

| Detector | MCC | TPR | FPR | F1 | AUC | Notes |
|---|---|---|---|---|---|---|
| `heuristic-v0` | _run locally_ | | | | | dependency-free floor |
| `llama-guard-3` | _tbd_ | | | | | content-safety baseline |
| `openai-moderation` | _tbd_ | | | | | moderation-API baseline |

## Task: `provenance` (AI vs. human)

| Detector | MCC | TPR | FPR | F1 | AUC | Notes |
|---|---|---|---|---|---|---|
| `binoculars` | _tbd_ | | | | | zero-shot MGT detector |

Reproduce the floor:

```bash
lurebench eval -d data/samples/lures.jsonl -m heuristic-v0 --json
```
