# Contributing to LureBench

Thanks for helping build an open benchmark for AI-generated fraud detection.

## Ground rules

LureBench is a defensive project. Contributions must serve detection, evaluation,
or measurement. We do not accept tooling to generate, personalize, or deliver
fraud campaigns, live malicious infrastructure, or real personal data.

All contributed fraud samples must be **defanged** per [DATA.md](DATA.md): URLs to
`<<link>>`, contacts to `<<contact>>`, no real PII or working payment details.

## Ways to contribute

- **Detectors.** Add a `Detector` subclass under `lurebench/detectors/` and
  register it in `lurebench/detectors/__init__.py`. Heavy dependencies must be
  imported lazily inside `__init__` and declared as an optional extra in
  `pyproject.toml`, so that `import lurebench` stays dependency-free.
- **Data shards.** Propose a dataset shard with a datasheet: typologies,
  generators, languages, provenance, license, and how it was labelled.
- **Metrics / harness.** Keep the core pure-Python and free of required
  third-party dependencies.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

A new detector should come with a test that at least constructs it (or asserts a
clean error when its extra is absent) and runs it over the sample shard.

## Adding a detector: checklist

1. Subclass `Detector`, set `name` and `task` (`fraud` or `provenance`).
2. Return `P(positive)` in `[0, 1]` from `score`, or `None` to abstain.
3. Lazy-import heavy deps; raise a helpful `ImportError` with the install hint.
4. Register in the `_LAZY` or `_EAGER` map.
5. Add a test.
