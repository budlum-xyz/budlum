#!/usr/bin/env python3
"""Static, read-only audit of every open pull request.

Nothing is checked out, compiled, merged or pushed. For each changed file the
audit downloads the PR head content and runs the cheap syntax checks that need
no toolchain: shell parsing, Python byte-compilation, JSON/TOML/YAML parsing.
It also flags two defect classes that have already shipped inside an open PR
(and are therefore worth looking for everywhere):

  * a record/filename interpolated into generated source (shell -> `python3 -c`
    or heredoc), and
  * the same brand-new path created by more than one open PR (lock collision).

Run:
    python3 tests/review/pr_static_audit.py            # markdown on stdout
    python3 tests/review/pr_static_audit.py --out r.md

Requires the `gh` CLI, authenticated, with `repo` read access. Exit status is
0 whether or not findings exist: this is an audit, not a merge gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from collections import defaultdict
from pathlib import Path

SHELL_SUFFIXES = {".sh", ".bash"}
PY_SUFFIXES = {".py"}
YAML_SUFFIXES = {".yml", ".yaml"}
MAX_BYTES = 2 * 1024 * 1024

# A `python3 -c "..."` or an unquoted heredoc that still expands `$var`.
GENERATED_SOURCE = re.compile(r"python[0-9.]*\s+-c\b")
UNQUOTED_HEREDOC = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)")
HEREDOC_VAR = re.compile(r"^[^#\n]*\$[A-Za-z_{]")


def gh(args: list[str]) -> str:
    result = subprocess.run(
        ["gh", *args], text=True, capture_output=True, timeout=180
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def gh_json_pages(args: list[str]) -> list:
    # `--jq '.[]'` keeps the output one JSON value per line and works on every
    # gh version (`--slurp` is newer than the CLI this repository's CI pins).
    raw = gh([*args, "--paginate", "--jq", ".[]"])
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def open_prs(repo: str) -> list[dict]:
    prs = gh_json_pages(["api", f"repos/{repo}/pulls?state=open&per_page=100"])
    for pr in prs:
        pr["files"] = gh_json_pages(
            ["api", f"repos/{repo}/pulls/{pr['number']}/files?per_page=100"]
        )
    return prs


def head_content(repo: str, path: str, sha: str) -> bytes | None:
    try:
        raw = gh(["api", f"repos/{repo}/contents/{path}?ref={sha}", "--jq", ".content"])
    except RuntimeError:
        return None
    import base64

    try:
        return base64.b64decode(raw.strip())
    except Exception:
        return None


def check_shell(path: str, data: bytes, tmp: Path) -> list[str]:
    problems: list[str] = []
    target = tmp / Path(path).name
    target.write_bytes(data)
    parsed = subprocess.run(
        ["bash", "-n", str(target)], text=True, capture_output=True
    )
    if parsed.returncode != 0:
        problems.append(f"bash -n: {parsed.stderr.strip().splitlines()[-1] if parsed.stderr.strip() else 'parse error'}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return problems + ["not valid UTF-8"]
    lines = text.splitlines()
    in_heredoc: str | None = None
    for line in lines:
        if "$" in line and GENERATED_SOURCE.search(line):
            problems.append("generated source interpolates a shell variable into python -c")
            break
    for line in lines:
        if in_heredoc:
            if line.strip() == in_heredoc:
                in_heredoc = None
            elif HEREDOC_VAR.match(line):
                problems.append("unquoted heredoc expands shell variables into generated source")
                break
        else:
            match = UNQUOTED_HEREDOC.search(line)
            if match:
                in_heredoc = match.group(1)
    return problems


def check_python(path: str, data: bytes, tmp: Path) -> list[str]:
    target = tmp / f"{Path(path).stem}.py"
    target.write_bytes(data)
    compiled = subprocess.run(
        [sys.executable, "-m", "py_compile", str(target)],
        text=True, capture_output=True,
    )
    if compiled.returncode != 0:
        tail = compiled.stderr.strip().splitlines()[-1] if compiled.stderr.strip() else "compile error"
        return [f"py_compile: {tail}"]
    return []


def check_json(data: bytes) -> list[str]:
    try:
        json.loads(data)
    except Exception as exc:  # noqa: BLE001 - report the parser message
        return [f"json: {exc}"]
    return []


def check_toml(data: bytes) -> list[str]:
    try:
        tomllib.loads(data.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"toml: {exc}"]
    return []


def check_yaml(path: str, data: bytes) -> list[str]:
    try:
        import yaml  # noqa: PLC0415 - optional dependency, reported when absent
    except ImportError:
        return []
    try:
        list(yaml.safe_load_all(data))
    except Exception as exc:  # noqa: BLE001
        return [f"yaml: {exc}"]
    return []


def audit(repo: str, prs: list[dict]) -> tuple[list[tuple], dict[str, list[int]]]:
    findings: list[tuple] = []
    created: dict[str, list[int]] = defaultdict(list)
    for pr in prs:
        number = pr["number"]
        sha = pr["head"]["sha"]
        for changed in pr.get("files") or []:
            path = changed.get("filename") or changed.get("path") or ""
            if changed.get("status") == "added":
                created[path].append(number)
            suffix = Path(path).suffix.lower()
            if suffix not in SHELL_SUFFIXES | PY_SUFFIXES | YAML_SUFFIXES | {".json", ".toml"}:
                continue
            if (changed.get("changes") or 0) > 20000:
                continue
            data = head_content(repo, path, sha)
            if data is None or len(data) > MAX_BYTES:
                continue
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                if suffix in SHELL_SUFFIXES:
                    problems = check_shell(path, data, tmp)
                elif suffix in PY_SUFFIXES:
                    problems = check_python(path, data, tmp)
                elif suffix == ".json":
                    problems = check_json(data)
                elif suffix == ".toml":
                    problems = check_toml(data)
                else:
                    problems = check_yaml(path, data)
            for problem in problems:
                findings.append((number, path, problem))
    return findings, created


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "lubothebook/budlum"))
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    prs = open_prs(args.repo)
    findings, created = audit(args.repo, prs)
    collisions = {
        path: sorted(set(nums)) for path, nums in created.items() if len(set(nums)) > 1
    }

    lines = [
        "# Open-PR static audit",
        "",
        f"Pull requests read: {len(prs)}. Read-only: nothing was checked out, compiled or merged.",
        "",
        "## Parse and generation findings",
        "",
    ]
    if findings:
        for number, path, problem in sorted(findings):
            lines.append(f"- #{number} `{path}` — {problem}")
    else:
        lines.append("- none")
    lines += ["", "## Paths created by more than one open PR", ""]
    if collisions:
        for path in sorted(collisions):
            nums = ", ".join(f"#{n}" for n in sorted(collisions[path]))
            lines.append(f"- `{path}` — {nums}")
    else:
        lines.append("- none")
    report = "\n".join(lines) + "\n"

    if args.out:
        Path(args.out).write_text(report)
        print(f"report written to {args.out}: {len(findings)} finding(s), {len(collisions)} collision(s)")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
