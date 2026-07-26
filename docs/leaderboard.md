# Leaderboard

MCC is the headline metric. Detection rate (recall) and FPR matter because a fraud detector is only useful at a tolerable false-positive rate.

_Generated from **['data/full/core/test.jsonl']** (2056 records)._

## Task: `fraud` (lure vs. benign)

| Detector | MCC | TPR | FPR | F1 | AUC | scored |
|---|---|---|---|---|---|---|
| `heuristic-v0` | 0.120 | 0.212 | 0.123 | 0.304 | 0.578 | 2056/2056 |
| `tfidf-logreg` | 0.910 | 0.963 | 0.049 | 0.946 | 0.992 | 2056/2056 |
| `llm-judge (openai/gpt-5-nano)` | 0.622 | 0.902 | 0.268 | 0.782 | 0.900 | 2056/2056 |
| `llm-judge (google/gemini-2.5-flash-lite)` | 0.760 | 0.726 | 0.015 | 0.830 | 0.937 | 2048/2056 (8 abstained) |
| `llm-judge (deepseek/deepseek-v4-flash)` | 0.781 | 0.750 | 0.015 | 0.847 | 0.940 | 2053/2056 (3 abstained) |
| `llm-judge (qwen/qwen-2.5-7b-instruct)` | 0.641 | 0.576 | 0.017 | 0.720 | 0.889 | 2056/2056 |
| `llm-judge (meta-llama/llama-3.1-8b-instruct)` | 0.548 | 0.785 | 0.227 | 0.737 | 0.816 | 2050/2056 (6 abstained) |
| `llm-judge (mistralai/mistral-nemo)` | 0.456 | 0.958 | 0.533 | 0.694 | 0.869 | 2042/2056 (14 abstained) |

### Detection rate by fraud typology

| Detector | `phishing` | `bec` | `romance` | `pig_butchering` |
|---|---|---|---|---|
| `heuristic-v0` | 0.199 | 0.826 | 0.148 | 0.091 |
| `tfidf-logreg` | 0.963 | 0.957 | 1.000 | 0.955 |
| `llm-judge (openai/gpt-5-nano)` | 0.934 | 0.870 | 0.481 | 0.364 |
| `llm-judge (google/gemini-2.5-flash-lite)` | 0.748 | 0.783 | 0.370 | 0.364 |
| `llm-judge (deepseek/deepseek-v4-flash)` | 0.756 | 0.826 | 0.667 | 0.591 |
| `llm-judge (qwen/qwen-2.5-7b-instruct)` | 0.625 | 0.087 | 0.111 | 0.000 |
| `llm-judge (meta-llama/llama-3.1-8b-instruct)` | 0.830 | 0.391 | 0.296 | 0.273 |
| `llm-judge (mistralai/mistral-nemo)` | 0.970 | 0.913 | 0.815 | 0.773 |

> The `scored` column is load-bearing: every other metric is computed only over the records a detector was willing to answer. An LLM judge that declines half the corpus would otherwise report metrics on the easy half and look flawless. AUC is threshold-free, so read it alongside TPR/FPR — a judge can rank fraud above benign well (high AUC) while being badly calibrated at the 0.5 cut used for TPR.
