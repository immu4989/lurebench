# LureBench

**A maintained benchmark and evaluation harness for detecting AI-generated fraud lures — phishing, business email compromise (BEC), and romance / pig-butchering scams.**

Detectors that score well on classic spam corpora fall apart on lures written or rewritten by modern language models. LureBench measures that gap on a common footing: one schema, one harness, one leaderboard, across fraud typologies and generator families. It runs out of the box with no model downloads or API keys, and it ships baseline wrappers for the detectors most people reach for first.

```bash
pip install lurebench
lurebench eval --dataset data/samples/lures.jsonl --detector heuristic-v0
```

## Why this exists

Two questions matter for a fraud lure, and most tools only answer one:

- **Is this a fraud lure?** (the `fraud` task — lure vs. benign)
- **Was this written by an LLM?** (the `provenance` task — AI vs. human)

A machine-generated-text detector answers the second. A content-safety model or spam filter answers the first. Scoring a detector against the wrong question is the most common way results in this space end up misleading, so LureBench keeps the two tasks explicit and picks the ground-truth target for you.

The detection gap is not hypothetical. Published evaluations report content-safety models collapsing on AI-generated romance-baiting text (a 0% true-positive rate in one study) while doing fine on tax and e-commerce scams, and academic phishing detectors losing large amounts of MCC when the phishing text is LLM-generated rather than human-written. Meanwhile the datasets that exist are mostly one-off paper artifacts: single generator, single typology, often withheld or "available on request." LureBench is built to be the opposite — multi-typology, multi-generator, versioned, and alive.

## What's in the box

| Component | Status in v0.1 |
|---|---|
| Dataset schema (`Lure`, JSONL) | Stable |
| Evaluation harness (`fraud` + `provenance` tasks) | Stable |
| Metrics (MCC, TPR, FPR, F1, ROC-AUC), pure-Python | Stable |
| `heuristic-v0` baseline (no dependencies) | Stable |
| Baseline wrappers: Binoculars, Llama Guard 3, OpenAI moderation | Included, need extras |
| Benchmark dataset shards on Hugging Face Hub | In progress |
| Public leaderboard | In progress |

The `data/samples/` shard is 16 defanged, illustrative records for smoke-testing only. It is not a benchmark split. See [DATA.md](DATA.md) for the data policy.

## Usage

List detectors:

```bash
lurebench detectors
```

Run several at once and emit JSON:

```bash
lurebench eval -d data/samples/lures.jsonl -m heuristic-v0 -m binoculars --json
```

As a library:

```python
from lurebench import load_jsonl, run
from lurebench.detectors import HeuristicDetector

data = load_jsonl("data/samples/lures.jsonl")
report = run(HeuristicDetector(), data, task="fraud")
print(report.summary_line())
```

Adding your own detector is a subclass with one method:

```python
from lurebench.detectors.base import Detector

class MyDetector(Detector):
    name = "my-detector"
    task = "fraud"          # or "provenance"

    def score(self, lure):
        return 0.0 <= my_probability(lure.text) <= 1.0   # P(positive), or None to abstain
```

Optional baselines install as extras:

```bash
pip install "lurebench[binoculars]"    # provenance baseline (Hans et al., ICML 2024)
pip install "lurebench[llamaguard]"    # content-safety baseline (gated model)
pip install "lurebench[openai]"        # moderation-API baseline (needs OPENAI_API_KEY)
```

## Generating the AI class

Cleanly-licensed public data covers human-written phishing well, but AI-generated lures (and BEC / romance / pig-butchering) are scarce — so LureBench generates them under a controlled protocol (see [docs/SHARD_SPEC.md](docs/SHARD_SPEC.md)). Generation runs through a single OpenAI-compatible engine with presets for common providers, plus a dependency-free template engine that needs no key:

```bash
# Offline template baseline (no API key)
lurebench generate --typology bec --n 20 --engine template --out staging.jsonl

# Any OpenAI-compatible provider via preset (uses that provider's own key)
export DEEPSEEK_API_KEY=...
lurebench generate --typology phishing --n 50 --engine deepseek --out staging.jsonl

# Or a custom endpoint
lurebench generate --typology romance --n 50 --engine openai-compat \
  --base-url https://api.example.com/v1 --model some-model --api-key-env SOME_KEY --out staging.jsonl
```

Presets: `deepseek`, `qwen`, `glm`, `kimi`, `mistral` (and `anthropic` for the aligned-model contrast). Using several generators is the point — the leaderboard's per-generator slice shows where detectors fail on one model's output but not another's. Every generated record is defanged, provenance-logged, and lands `review: pending`; nothing enters a shard until a human approves it.

## Demand signals

LureBench targets a threat that U.S. regulators and law enforcement have named explicitly:

- **FinCEN**, Alert FIN-2024-Alert004 (Nov 2024), lists GenAI-generated **text** among its red-flag indicators and names BEC, spear phishing, elder exploitation, romance scams, and virtual-currency investment ("pig-butchering") scams as active GenAI-enabled vectors.
- **FBI / IC3**, PSA I-120324-PSA (Dec 2024), warns that criminals use generative AI to produce phishing text and fraudulent content at greater scale and believability.
- **FS-ISAC** (Oct 2024) published a deepfake threat taxonomy for the financial sector and cites a Deloitte projection of **$40B** in U.S. AI-enabled fraud losses by 2027.

## Scope

LureBench covers **text** lures. Audio and video deepfake fraud are well served by existing benchmarks (ASVspoof 5, Deepfake-Eval-2024, VishGPT for vishing); LureBench cites and complements those rather than duplicating them.

## Responsible use

This is a defensive research project. The corpus exists to train and evaluate detectors. Controlled generation produces **defanged, clearly-synthetic, review-gated** detector-training text — it does not personalize lures to real targets, embed working links or payment rails, or deliver anything. All generated records are held `review: pending` behind a human-approval gate. See [DATA.md](DATA.md), [docs/SHARD_SPEC.md](docs/SHARD_SPEC.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

## Citation

See [CITATION.cff](CITATION.cff). Licensed under Apache-2.0.
