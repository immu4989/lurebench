from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTIONS = ROOT / ".github" / "actions"
USES = re.compile(r"^\s*(?:-\s*)?uses:\s+([^#\s]+)", re.MULTILINE)
IMMUTABLE_REMOTE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def _automation_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(ACTIONS.glob("*/action.yml"))


def test_remote_actions_are_pinned_to_full_commit_shas():
    violations = []
    for path in _automation_files():
        for reference in USES.findall(path.read_text(encoding="utf-8")):
            if not reference.startswith("./") and not IMMUTABLE_REMOTE.fullmatch(reference):
                violations.append(f"{path.relative_to(ROOT)}: {reference}")
    assert not violations, "mutable action references:\n" + "\n".join(violations)


def test_workflows_declare_permissions_and_avoid_pull_request_target():
    violations = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        source = path.read_text(encoding="utf-8")
        if not re.search(r"^permissions(?:\s*:|:)", source, re.MULTILINE):
            violations.append(f"{path.relative_to(ROOT)}: missing top-level permissions")
        if re.search(r"^[^#\n]*\bpull_request_target\b", source, re.MULTILINE):
            violations.append(f"{path.relative_to(ROOT)}: pull_request_target is prohibited")
    assert not violations, "workflow security violations:\n" + "\n".join(violations)


def test_release_assets_cannot_be_silently_replaced():
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "gh release upload" in release
    assert "--clobber" not in release
    assert "group: release-${{ github.ref }}" in release
    assert "cancel-in-progress: false" in release


def test_checkout_never_persists_git_credentials():
    violations = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if "uses: actions/checkout@" not in line:
                continue
            indent = len(line) - len(line.lstrip())
            body = []
            for candidate in lines[index + 1 :]:
                candidate_indent = len(candidate) - len(candidate.lstrip())
                if candidate_indent == indent and candidate.lstrip().startswith("-"):
                    break
                body.append(candidate.strip())
            if "persist-credentials: false" not in body:
                violations.append(f"{path.relative_to(ROOT)}:{index + 1}")
    assert not violations, "checkout persists credentials:\n" + "\n".join(violations)


def test_every_workflow_job_has_a_timeout():
    violations = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        lines = path.read_text(encoding="utf-8").splitlines()
        jobs_index = lines.index("jobs:")
        job_starts = [
            index
            for index in range(jobs_index + 1, len(lines))
            if re.fullmatch(r"  [a-zA-Z0-9_-]+:", lines[index])
        ]
        for offset, start in enumerate(job_starts):
            end = job_starts[offset + 1] if offset + 1 < len(job_starts) else len(lines)
            if not any(line.startswith("    timeout-minutes:") for line in lines[start:end]):
                violations.append(f"{path.relative_to(ROOT)}:{start + 1}")
    assert not violations, "jobs without timeouts:\n" + "\n".join(violations)


def test_release_build_is_separated_from_release_authority():
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    build = release.split("\n  build:", 1)[1].split("\n  attest-release:", 1)[0]
    attest = release.split("\n  attest-release:", 1)[1].split("\n  publish-pypi:", 1)[0]
    assert "contents: write" not in build
    assert "id-token: write" not in build
    assert "attest-build-provenance" not in build
    assert "needs: build" in attest
    assert "contents: write" in attest
    assert "id-token: write" in attest
    assert "attest-build-provenance" in attest
    publish = release.split("\n  publish-pypi:", 1)[1]
    assert "needs: attest-release" in publish
