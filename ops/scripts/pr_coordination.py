#!/usr/bin/env python3
"""Report where the open branches collide, so a merge order can be chosen.

Fifty pull requests are open against `main` at the same time. Each one was
written as if it were alone, and the directive's lock rules (Section 15.3)
assume four agents, not fifty. This script measures the collision rather than
guessing at it:

* **Shared files.** A file two branches both change is a rebase at best and a
  semantic clash at worst.
* **Divergent additions.** A file two branches both *add*, with different
  content, is the expensive case: two independent implementations of one new
  module, and only one can survive. Identical copies are cheap (either will do).
* **Duplicate declarations.** Two branches adding the same `pub` item to the
  same existing file cannot both land without a decision.

Usage:

    python3 ops/scripts/pr_coordination.py [--base main] [--remote origin]
    python3 ops/scripts/pr_coordination.py --prs-only

By default every remote branch is measured, including dependabot branches and
branches with no pull request. `--prs-only` limits the measurement to the heads
of the open pull requests reported by `gh`, which is the scope a coordination
report claims when it says "open pull requests".

The output is stable enough to paste into `docs/work/PR_COORDINATION.md`: it
sorts every list, so two runs on the same refs print the same text.
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys


def git(*args: str) -> str:
    """Run git and return stdout, failing loudly rather than returning ""."""
    done = subprocess.run(["git", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout


def git_try(*args: str) -> str | None:
    """Run git and return stdout, or None when the command failed."""
    done = subprocess.run(["git", *args], capture_output=True, text=True)
    return done.stdout if done.returncode == 0 else None


def branches(base: str, remote: str) -> list[str]:
    """Every remote branch except the base and the symbolic HEAD."""
    out = git("for-each-ref", "--format=%(refname:short)", f"refs/remotes/{remote}")
    keep = []
    for name in out.split():
        if name in (f"{remote}/HEAD", f"{remote}/{base}"):
            continue
        keep.append(name)
    return sorted(keep)


def open_pull_requests(remote: str) -> tuple[list[str], list[tuple[int, str]]]:
    """(remote refs of open PR heads, PRs whose base is not main).

    `gh` is available where the report is produced. A PR head on a fork has no
    local remote ref and is named in the returned diagnostics instead of being
    silently dropped.
    """
    done = subprocess.run(
        [
            "gh", "pr", "list", "--state", "open", "--limit", "200",
            "--json", "number,headRefName,baseRefName",
        ],
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        raise SystemExit(f"gh pr list failed: {done.stderr.strip()}")
    refs: list[str] = []
    non_main: list[tuple[int, str]] = []
    for pr in json.loads(done.stdout):
        if pr["baseRefName"] != "main":
            non_main.append((pr["number"], pr["baseRefName"]))
        ref = f"{remote}/{pr['headRefName']}"
        if git_try("rev-parse", "--verify", f"{ref}^{{commit}}") is None:
            continue
        refs.append(ref)
    return sorted(set(refs)), sorted(non_main)


def changes(base: str, branch: str) -> list[tuple[str, str]]:
    """(status letter, path) for every path the branch changes against base.

    A branch with no merge base against the base (an orphan history) is
    compared by tree instead, so the report still names its paths instead of
    stopping. Such a branch cannot be merged by a normal merge, and the
    report says so in its header line.
    """
    out = git_try("diff", "--name-status", f"{base}...{branch}")
    if out is None:
        orphan.add(branch)
        out = git("diff", "--name-status", f"{base}", branch)
    parsed = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        parsed.append((parts[0][0], parts[-1]))
    return parsed


orphan: set[str] = set()


def blob(branch: str, path: str) -> str:
    """The object id of `path` on `branch`, or "" when it does not exist."""
    done = subprocess.run(
        ["git", "rev-parse", f"{branch}:{path}"], capture_output=True, text=True
    )
    return done.stdout.strip() if done.returncode == 0 else ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="main")
    parser.add_argument("--remote", default="origin")
    parser.add_argument(
        "--prs-only",
        action="store_true",
        help="measure only the heads of open pull requests, not every remote branch",
    )
    args = parser.parse_args()

    non_main: list[tuple[int, str]] = []
    if args.prs_only:
        names, non_main = open_pull_requests(args.remote)
    else:
        names = branches(args.base, args.remote)
    if not names:
        print("no branches to compare; is the remote fetched?", file=sys.stderr)
        return 1

    changed: dict[str, list[tuple[str, str]]] = {}
    for name in names:
        changed[name] = changes(args.base, name)

    touched_by: dict[str, set[str]] = collections.defaultdict(set)
    added_by: dict[str, dict[str, str]] = collections.defaultdict(dict)
    for name, pairs in changed.items():
        for status, path in pairs:
            touched_by[path].add(name)
            if status == "A":
                added_by[path][name] = blob(name, path)

    shared = {path: sorted(b) for path, b in touched_by.items() if len(b) > 1}
    divergent = {
        path: sorted(b)
        for path, b in added_by.items()
        if len(b) > 1 and len(set(b.values())) > 1
    }
    identical = {
        path: sorted(b)
        for path, b in added_by.items()
        if len(b) > 1 and len(set(b.values())) == 1
    }

    print(f"branches compared against {args.base}: {len(names)}")
    if args.prs_only:
        print(f"scope: heads of open pull requests ({len(names)} distinct refs)")
        print(f"open pull requests based on a branch other than main: {len(non_main)}")
        for number, base in non_main:
            print(f"     #{number} base={base}")
    if orphan:
        print(f"branches with no merge base against the base: {len(orphan)}")
        for name in sorted(orphan):
            print(f"     {name}")
    print(f"paths changed by two or more branches: {len(shared)}")
    print(f"paths added by two or more branches, same content: {len(identical)}")
    print(f"paths added by two or more branches, different content: {len(divergent)}")

    print("\n## The most shared files\n")
    for path, who in sorted(shared.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:25]:
        print(f"{len(who):3d}  {path}")

    print("\n## One new file, several implementations\n")
    for path, who in sorted(divergent.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"{len(who):3d}  {path}  ({', '.join(who)})")

    print("\n## Shared append-only files (Section 15.3 item 4; rebase, never lock)\n")
    append_only = [
        "src/core/transaction.rs",
        "src/rpc/method_class.rs",
        "src/crypto/domain_tags.rs",
        "xtask/gates/src/main.rs",
        ".github/workflows/ci.yml",
        "Cargo.toml",
        "docs/audit/FINDINGS.md",
        "docs/work/PACKAGES.md",
        "config/naming/concept_map.toml",
        ".github/concept-names-baseline.txt",
    ]
    for path in append_only:
        who = shared.get(path, [])
        print(f"{len(who):3d}  {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
