# Multilingual: can an LLM judge read the lure?

Detection rate (recall) per language, **artifact-controlled**: the defang placeholders (`<<link>>`, `<<contact>>`) are stripped before scoring, because a detector can otherwise score near 1.00 in a language it cannot read at all by keying on the placeholder. The shard is all-fraud, so recall here is not accuracy — read every row against its **FPR** column, measured on the benign half of the core test set. A detector with a high FPR is not reading the language, it is flagging everything.

_Generated from **['data/full/multilingual/eval.jsonl']**, threshold 0.50._

| Detector | FPR (benign) | ar (56) | de (26) | en (38) | es (32) | fr (27) | it (22) | pt (28) | ru (32) | zh (32) |
|---|---|---|---|---|---|---|---|---|---|---|
| `heuristic-v0` | 0.12 | 0.00 | 0.00 | 0.08 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| `tfidf-logreg` | 0.05 | 0.04 | 1.00 | 0.97 | 1.00 | 0.96 | 0.91 | 0.79 | 0.06 | 0.09 |
| `llm-judge (openai/gpt-5-nano)` | 0.27 | 1.00 | 0.62 | 0.53 | 0.78 | 0.81 | 0.59 | 0.64 | 0.84 | 0.88 |
| `llm-judge (google/gemini-2.5-flash-lite)` | 0.02 | 0.95 | 0.81 | 0.61 | 0.69 | 0.81 | 0.59 | 0.57 | 0.88 | 0.84 |
| `llm-judge (deepseek/deepseek-v4-flash)` | 0.01 | 0.93 | 0.96 | 0.63 | 0.91 | 0.96 | 0.91 | 0.93 | 0.78 | 0.75 |
| `llm-judge (qwen/qwen-2.5-7b-instruct)` | 0.02 | 0.16 | 0.00 | 0.03 | 0.00 | 0.00 | 0.00 | 0.11 | 0.09 | 0.19 |
| `llm-judge (meta-llama/llama-3.1-8b-instruct)` | 0.23 | 0.50 | 0.31 | 0.21 | 0.50 | 0.33 | 0.23 | 0.43 | 0.50 | 0.69 |
| `llm-judge (mistralai/mistral-nemo)` | 0.53 | 1.00 | 1.00 | 0.83 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |

Read the non-Latin columns (`ar`, `ru`, `zh`) against the Latin ones. The trained TF-IDF baseline holds up in the languages that share English's script and collapses in the ones that do not, which is what you would expect from a model that matches tokens it has seen. The stronger LLM judges do not have that cliff: they detect Arabic, Russian and Chinese lures at rates comparable to their Latin-script performance, at a lower false-positive rate than the baseline. That is the case for putting an LLM in front of non-English traffic.

The FPR column is what makes the rest of the table trustworthy. A detector that flags indiscriminately scores a perfect 1.00 in every language on an all-fraud shard while being useless in production, and without a false-positive number next to it that row is indistinguishable from genuine multilingual competence.
