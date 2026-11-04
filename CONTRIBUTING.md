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
uv sync --extra dev --extra train
uv run pytest
uv run ruff check .
```

CI uses `uv 0.12.3` and `uv sync --locked`. If a dependency changes, run
`uv lock`, review the package and hash changes in `uv.lock`, and commit the
updated lockfile with the manifest change.

### Source-distribution reproduction

Default `pytest` discovery is restricted to `tests/`, so a backend's temporary
source tree and local scratch experiments are not collected. Explicit paths
still work; `pytest .` deliberately opts out of that default scope. Documentation
checks likewise enumerate first-party roots, including the blog where present.
Put maintained tests under `tests/`, and review the archive inventory when adding
a new first-party input directory. Run only one package build per checkout at
a time; this does not make arbitrary concurrent source edits/builds safe.

After building, check the archive against this checkout:

```bash
uv build
uv run python scripts/check_source_distribution.py dist/lurebench-*.tar.gz --package lurebench
```

The standard-library checker compares selected code, tests, fixtures, scripts,
schemas, public documentation/assets, and workflow inputs byte-for-byte. It
refuses missing/stale inputs, duplicate or noncanonical member names, links and
special files, transient/credential filenames, and configured archive-size
limits. It reads without extraction or execution. This is not publisher
authentication, a general secret scanner, or a sandbox for untrusted archives.

CI also runs the tests from the locally built source distribution outside the
checkout, using the already-provisioned test environment. Optional dependencies
and deliberately unbundled datasets can still cause documented skips. To repeat
that check for a **trusted local build** after the archive gate passes:

```bash
source_test_python="$(pwd)/.venv/bin/python"
source_test_root="$(mktemp -d)"
tar -xzf dist/lurebench-*.tar.gz --strip-components=1 -C "$source_test_root"
(cd "$source_test_root" && "$source_test_python" -m pytest -q)
```

Running tests executes code: do not substitute an unreviewed downloaded archive.
The release build performs the source and wheel gates before handing artifacts
to publishing jobs, without adding release authority to the build job.
See [pytest discovery guidance](https://docs.pytest.org/en/stable/explanation/goodpractices.html#conventions-for-python-test-discovery)
and [setuptools source inclusion](https://setuptools.pypa.io/en/latest/userguide/miscellaneous.html).

A new detector should come with a test that at least constructs it (or asserts a
clean error when its extra is absent) and runs it over the sample shard.

## Adding a detector: checklist

1. Subclass `Detector`, set `name` and `task` (`fraud` or `provenance`).
2. Return `P(positive)` in `[0, 1]` from `score`, or `None` to abstain.
3. Lazy-import heavy deps; raise a helpful `ImportError` with the install hint.
4. Register in the `_LAZY` or `_EAGER` map.
5. Add a test.
