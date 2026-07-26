# Can an LLM tell AI-written fraud from human-written fraud?

Every record here is a fraud lure; the only question is who wrote it. AUC is the honest read because it does not depend on where the threshold sits.

_Generated from **human.jsonl, deepseek-v4-pro.jsonl, glm-4.6.jsonl, mistral-large-latest.jsonl** (1072 records)._

## Task: `provenance` (AI vs. human)

AUC and balanced accuracy are the honest read (0.5 = chance).

| Detector | AUC | bal-acc | MCC | TPR | FPR | scored |
|---|---|---|---|---|---|---|
| `llm-judge-provenance (openai/gpt-5-nano)` | 0.503 | 0.499 | -0.019 | 0.999 | 1.000 | 1072/1072 |
| `llm-judge-provenance (google/gemini-2.5-flash-lite)` | 0.665 | 0.649 | 0.268 | 0.592 | 0.293 | 1072/1072 |
| `llm-judge-provenance (deepseek/deepseek-v4-flash)` | 0.737 | 0.639 | 0.280 | 0.352 | 0.074 | 1002/1072 (70 abstained) |
| `llm-judge-provenance (qwen/qwen-2.5-7b-instruct)` | 0.461 | 0.499 | -0.003 | 0.845 | 0.847 | 1072/1072 |
| `llm-judge-provenance (meta-llama/llama-3.1-8b-instruct)` | 0.461 | 0.496 | -0.007 | 0.637 | 0.644 | 1069/1072 (3 abstained) |
| `llm-judge-provenance (mistralai/mistral-nemo)` | 0.533 | 0.500 | 0.000 | 1.000 | 1.000 | 1072/1072 |

> 0.5 AUC is chance. The question is whether an LLM can tell AI-written fraud from human-written fraud on distribution-matched data, where a trained classifier drops from a perfect score to near chance once corpus artifacts are removed. The judge is told to ignore how scam-like the text is (every record here is fraud) and that the defang placeholders are applied uniformly, so neither can leak the answer.
