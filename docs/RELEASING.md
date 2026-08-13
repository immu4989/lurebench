# Releasing LureBench

Releases are built only from immutable `vMAJOR.MINOR.PATCH` tags whose commit is
reachable from protected `main`. The release workflow verifies `pyproject.toml`,
`lurebench.__version__`, `CITATION.cff`, the README badge, and the changelog before
building. It runs `twine check`, creates GitHub build-provenance attestations, and
attaches the wheel and source distribution to the GitHub release.

## One-time PyPI Trusted Publisher setup

The `lurebench` name is currently unclaimed on PyPI. Before enabling publication:

1. Sign in to [PyPI's pending publisher page](https://pypi.org/manage/account/publishing/).
2. Enter project name `lurebench`, owner `immu4989`, repository `lurebench`,
   workflow `release.yml`, and environment `pypi`.
3. In the GitHub repository, create a `pypi` environment and require manual
   approval for deployments.
4. Set the repository Actions variable `PYPI_PUBLISH` to `true`.

This follows the Python Packaging Authority's
[Trusted Publishing guide](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/).
No long-lived PyPI token belongs in GitHub secrets.

## Release procedure

1. Update the version in `pyproject.toml`, `lurebench/__init__.py`,
   `CITATION.cff`, the README badge, and the changelog.
2. Run `python scripts/verify_release.py vX.Y.Z`.
3. Merge through protected CI.
4. Create a GitHub release targeting the exact tested `main` commit and tag it
   `vX.Y.Z`.
5. Confirm the release workflow, PyPI project, attached distributions,
   attestations, and Zenodo version record.
