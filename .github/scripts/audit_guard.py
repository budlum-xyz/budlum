#!/usr/bin/env python3
"""Fail-closed, dependency-free audit of Budlum's review boundary.

This is deliberately a structural gate, not a replacement for Rust, CodeQL,
actionlint, zizmor, or the supply-chain jobs. Its purpose is to catch a CI
configuration that silently stops auditing, and to keep the repository's own
review identity out of active code and new commit subjects.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
SCRIPT = Path(__file__).resolve()
# Constructed rather than written as one token so this guard cannot trip over
# its own explanatory source text.
REVIEW_IDENTITY = "Ar" + "ena"
SHA_REF = re.compile(r"@[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
CHECKOUT = "actions/checkout@"


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def workflow_text_audit(rel: str, text: str, errors: list[str]) -> None:
    """Audit one workflow text. Kept pure so the red-team can mutate it."""
    uncommented = "\n".join(line.split("#", 1)[0] for line in text.splitlines())

    if not re.search(r"^permissions:\s*$", text, re.MULTILINE):
        fail(f"{rel}: missing top-level permissions block", errors)
    if re.search(r"^\s*pull_request_target\s*:", text, re.MULTILINE):
        fail(f"{rel}: pull_request_target is forbidden", errors)
    if re.search(r"^\s*workflow_run\s*:", text, re.MULTILINE):
        fail(f"{rel}: workflow_run is forbidden in the audit surface", errors)

    # The guard workflow is itself part of the review boundary. Removing its
    # self-test, its real audit, or its fail-closed shell mode must turn this
    # audit red rather than silently reducing coverage.
    if rel.endswith("/.github/workflows/audit-guard.yml") or rel == ".github/workflows/audit-guard.yml":
        if "audit_guard.py --self-test" not in text:
            fail(f"{rel}: guard self-test is missing", errors)
        if re.search(r"^\s*python3 \.github/scripts/audit_guard\.py\s*$", text, re.MULTILINE) is None:
            fail(f"{rel}: real audit invocation is missing", errors)
        if re.search(r"^\s*continue-on-error:\s*true\s*$", text, re.MULTILINE):
            fail(f"{rel}: audit guard may not continue on error", errors)
        if re.search(r"\|\|\s*true", text):
            fail(f"{rel}: audit guard may not swallow failures", errors)
    if rel.endswith("/.github/workflows/ci.yml") or rel == ".github/workflows/ci.yml":
        if "python3 .github/scripts/audit_guard.py --self-test" not in text:
            fail(f"{rel}: gates aggregator is missing Audit Guard self-test", errors)
        if re.search(r"^\s*python3 \.github/scripts/audit_guard\.py\s*$", text, re.MULTILINE) is None:
            fail(f"{rel}: gates aggregator is missing the real Audit Guard", errors)

    for line_no, line in enumerate(text.splitlines(), 1):
        match = USES_LINE.match(line)
        if not match:
            continue
        ref = match.group(1)
        if ref.startswith("./"):
            continue
        if not SHA_REF.search(ref):
            fail(f"{rel}:{line_no}: action is not pinned to a full commit SHA: {ref}", errors)

    lines = text.splitlines()
    checkout_lines = [
        i for i, line in enumerate(lines) if CHECKOUT in line and not line.lstrip().startswith("#")
    ]
    for start in checkout_lines:
        block = lines[start : start + 12]
        if not any("persist-credentials: false" in line for line in block):
            fail(f"{rel}:{start + 1}: checkout must disable persisted credentials", errors)

    has_pull_request = bool(re.search(r"^\s*pull_request:\s*$", text, re.MULTILINE))
    if has_pull_request:
        for line_no, line in enumerate(uncommented.splitlines(), 1):
            if re.search(
                r"^\s*(?:contents|actions|pull-requests):\s*(?:write|write-all)\s*$",
                line,
            ):
                fail(f"{rel}:{line_no}: write permission on a pull_request workflow", errors)

    for line_no, line in enumerate(uncommented.splitlines(), 1):
        if re.search(r"\bgit\s+push\b", line):
            fail(f"{rel}:{line_no}: workflow must not push repository changes", errors)


def workflow_audit(errors: list[str]) -> None:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    if not files:
        fail("no workflow files were found", errors)
        return
    for path in files:
        workflow_text_audit(path.relative_to(ROOT).as_posix(), path.read_text(encoding="utf-8"), errors)


def tracked_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    return [ROOT / item for item in result.stdout.decode().split("\0") if item]


def active_code_audit(errors: list[str]) -> None:
    prefixes = (
        "src/",
        "crates/",
        "bud/",
        "budzero/",
        "xtask/",
        "contracts/",
        "ops/",
        "fuzz/",
        "kani/",
        "examples/",
        ".github/workflows/",
    )
    for path in tracked_paths():
        rel = path.relative_to(ROOT).as_posix()
        if path == SCRIPT or not rel.startswith(prefixes) or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if REVIEW_IDENTITY in text:
            fail(f"{rel}: review identity remains in active code or workflow text", errors)


def commit_subject_audit(errors: list[str]) -> None:
    result = subprocess.run(
        ["git", "log", "--format=%H%x09%s", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    for row in result.stdout.splitlines():
        sha, _, subject = row.partition("\t")
        if REVIEW_IDENTITY.casefold() in subject.casefold():
            fail(f"commit {sha[:12]}: review identity remains in subject", errors)


def red_team() -> None:
    """Mutate each protected rule and require the detector to go red."""
    clean = """
permissions:
  contents: read
on:
  pull_request:
    branches: [main]
jobs:
  check:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          persist-credentials: false
"""
    mutants = {
        "unpinned-action": clean.replace(
            "actions/checkout@0123456789abcdef0123456789abcdef01234567",
            "actions/checkout@main",
        ),
        "missing-permissions": clean.replace("permissions:\n  contents: read\n", "", 1),
        "checkout-credentials": clean.replace("persist-credentials: false", "persist-credentials: true"),
        "forbidden-trigger": clean.replace("pull_request:\n", "pull_request_target:\n"),
        "pull-write": clean.replace("contents: read\n    steps:", "contents: write\n    steps:"),
        "workflow-push": clean + "\n# mutation\nrun: git push\n",
    }
    expected = {
        "unpinned-action": "not pinned",
        "missing-permissions": "missing top-level permissions",
        "checkout-credentials": "disable persisted credentials",
        "forbidden-trigger": "pull_request_target is forbidden",
        "pull-write": "write permission on a pull_request",
        "workflow-push": "workflow must not push",
    }
    for name, mutant in mutants.items():
        errors: list[str] = []
        workflow_text_audit(f"red-team/{name}.yml", mutant, errors)
        if not any(expected[name] in error for error in errors):
            raise AssertionError(f"red-team mutant passed unexpectedly: {name}: {errors}")

    guard_clean = """
permissions:
  contents: read
jobs:
  audit-guard:
    steps:
      - run: |
          set -euo pipefail
          python3 .github/scripts/audit_guard.py --self-test
      - run: |
          set -euo pipefail
          python3 .github/scripts/audit_guard.py
"""
    guard_mutants = {
        "guard-self-test-removed": guard_clean.replace(
            "          python3 .github/scripts/audit_guard.py --self-test\n", ""
        ),
        "guard-real-audit-removed": guard_clean.replace(
            "          python3 .github/scripts/audit_guard.py\n", ""
        ),
        "guard-continue-open": guard_clean + "\n    continue-on-error: true\n",
        "guard-swallowed-error": guard_clean + "\n          python3 audit_guard.py || true\n",
    }
    guard_expected = {
        "guard-self-test-removed": "self-test is missing",
        "guard-real-audit-removed": "real audit invocation is missing",
        "guard-continue-open": "may not continue on error",
        "guard-swallowed-error": "may not swallow failures",
    }
    for name, mutant in guard_mutants.items():
        errors = []
        workflow_text_audit(".github/workflows/audit-guard.yml", mutant, errors)
        if not any(guard_expected[name] in error for error in errors):
            raise AssertionError(f"guard mutant passed unexpectedly: {name}: {errors}")
    print("audit-guard red-team: PASS (10 mutations rejected)")


def self_test() -> None:
    red_team()
    errors: list[str] = []
    active_code_audit(errors)
    commit_subject_audit(errors)
    if errors:
        raise SystemExit("self-test found existing violations:\n" + "\n".join(f"- {e}" for e in errors))
    print("audit-guard self-test: PASS")


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        self_test()
        return 0

    errors: list[str] = []
    workflow_audit(errors)
    active_code_audit(errors)
    commit_subject_audit(errors)
    if errors:
        print("audit-guard: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("audit-guard: PASS")
    print(f"- workflows checked: {len(list(WORKFLOWS.glob('*.yml'))) + len(list(WORKFLOWS.glob('*.yaml')))}")
    print("- action refs, permissions, checkout credentials, forbidden triggers and push paths checked")
    print("- active code/workflow review identity check: clean")
    print("- reachable commit subjects review identity check: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
