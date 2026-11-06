#!/usr/bin/env python3
"""Compatibility audit of the live open pull request stack.

The repository has many open pull requests that edit the same shared files.
A clean `git merge` does not mean the result compiles: two branches can each
carry a syntactically valid file and still disagree about a public type, or
one of them can carry a machine-mangled file that no merge will repair. This
tool answers four questions from the actual Git objects, without checking out
any branch and without a Rust toolchain:

1. Which changed Rust files on which open PR head have syntax errors?
2. Which paths are edited by more than one open PR (conflict magnets)?
3. Which new files are implemented more than once, with different bytes?
4. Do the presence-message wire shapes disagree across the stack?

Usage:
    python3 ops/scripts/stack_compatibility_audit.py \
        --pr-list docs/audit/OPEN_PR_SNAPSHOT_2026-11-06.json \
        --base cccf1da1f4bcfe97503a3a00cfba24b172b49b31 \
        --out-json docs/audit/STACK_COMPATIBILITY_DATA_2026-11-06.json \
        --out-md docs/audit/STACK_COMPATIBILITY_AUDIT_2026-11-06.md

The `--pr-list` file is a live `gh pr list --json ...` snapshot. A PR head that
is not present in the local object store is reported as missing, not silently
skipped. `tree_sitter` and `tree_sitter_rust` are required; the tool refuses to
run without them rather than reporting a weaker check as a syntax check.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys

try:
    import tree_sitter
    import tree_sitter_rust
except ImportError as exc:  # pragma: no cover - environment guard
    raise SystemExit(
        "tree_sitter and tree_sitter_rust are required: "
        "pip install tree_sitter tree_sitter_rust"
    ) from exc

REPO = pathlib.Path(__file__).resolve().parents[2]
PARSER = tree_sitter.Parser(tree_sitter.Language(tree_sitter_rust.language()))


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(REPO), *args], text=True, errors="replace"
    )


def git_bytes(*args: str) -> bytes | None:
    proc = subprocess.run(
        ["git", "-C", str(REPO), *args], capture_output=True
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def blob(ref: str, path: str) -> bytes | None:
    return git_bytes("show", f"{ref}:{path}")


def syntax_findings(source: bytes) -> list[str]:
    """Names of ERROR/MISSING nodes, from the real Rust grammar."""
    tree = PARSER.parse(source)
    found: list[str] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            line = node.start_point[0] + 1
            kind = "missing" if node.is_missing else "error"
            found.append(f"{kind}@{line}")
        stack.extend(node.children)
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr-list", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    args = ap.parse_args()

    prs = json.loads((REPO / args.pr_list).read_text())
    prs = [p for p in prs if p.get("state", "OPEN") == "OPEN"]
    prs.sort(key=lambda p: p["number"])

    rows = []
    path_owners: dict[str, list[int]] = collections.defaultdict(list)
    new_file_blobs: dict[str, dict[str, list[int]]] = collections.defaultdict(
        lambda: collections.defaultdict(list)
    )
    all_rs = 0
    bad_rs = 0

    for pr in prs:
        num = pr["number"]
        head = "refs/remotes/origin/" + pr["headRefName"]
        exists = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--verify", "--quiet", head],
            capture_output=True,
        ).returncode == 0
        if not exists:
            rows.append({"number": num, "head": pr["headRefName"], "missing": True})
            continue
        sha = git("rev-parse", "--short", head).strip()
        # Two-dot, not three-dot: several stacked PR heads descend from a
        # pre-upload branch with no merge base against `main`. A three-dot
        # diff cannot be computed for them. Two-dot is the tree difference
        # against `main`, which is exactly the integration question.
        changes = git("diff", "--name-status", args.base, head).splitlines()
        errors: list[dict] = []
        rs_count = 0
        for line in changes:
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            status, rel = parts[0], parts[-1]
            path_owners[rel].append(num)
            if status.startswith("A") or status.startswith("M"):
                digest = hashlib.sha256(blob(head, rel) or b"").hexdigest()[:12]
                if status.startswith("A"):
                    new_file_blobs[rel][digest].append(num)
            if status.startswith("D") or not rel.endswith(".rs"):
                continue
            source = blob(head, rel)
            if source is None:
                continue
            rs_count += 1
            all_rs += 1
            findings = syntax_findings(source)
            if findings:
                bad_rs += 1
                errors.append({"file": rel, "findings": findings[:12]})
        rows.append(
            {
                "number": num,
                "head": pr["headRefName"],
                "sha": sha,
                "title": pr.get("title", ""),
                "changed_paths": len(changes),
                "rust_files": rs_count,
                "syntax_errors": errors,
            }
        )

    broken = [r for r in rows if r.get("syntax_errors")]
    shared = sorted(
        ((p, sorted(set(o))) for p, o in path_owners.items() if len(set(o)) > 1),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )
    duplicates = sorted(
        (
            {
                "path": p,
                "versions": len(v),
                "authors": sorted({n for ns in v.values() for n in ns}),
            }
            for p, v in new_file_blobs.items()
            if len(v) > 1
        ),
        key=lambda d: (-d["versions"], d["path"]),
    )

    # Wire-shape drift: collect the presence-message domain tags and digest
    # constants from every presence-related source on every PR head.
    wire: dict[str, dict[str, set[str]]] = collections.defaultdict(
        lambda: collections.defaultdict(set)
    )
    for r in rows:
        if r.get("missing"):
            continue
        head = "refs/remotes/origin/" + r["head"]
        files = git("ls-tree", "-r", "--name-only", head).splitlines()
        for rel in files:
            if not rel.endswith(".rs") or "presence" not in rel.lower():
                continue
            source = blob(head, rel)
            if source is None:
                continue
            text = source.decode("utf-8", "replace")
            for line in text.splitlines():
                s = line.strip()
                if ("BDLM_" in s or "PRESENCE" in s) and (
                    "const " in s or "domain" in s.lower() or "digest" in s.lower()
                ):
                    wire[rel][hashlib.sha256(s.encode()).hexdigest()[:8]].add(
                        f"#{r['number']}"
                    )
    wire_drift = [
        {"file": rel, "distinct_lines": len(v), "lines": len(v)}
        for rel, v in sorted(wire.items())
        if len(v) > 1
    ]

    # The integrated tree of the current working branch.
    tree_errors: list[dict] = []
    tree_rs = 0
    for path in sorted(REPO.rglob("*.rs")):
        if ".git" in path.parts or "target" in path.parts:
            continue
        rel = str(path.relative_to(REPO))
        tree_rs += 1
        findings = syntax_findings(path.read_bytes())
        if findings:
            tree_errors.append({"file": rel, "findings": findings[:12]})

    data = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "base": args.base,
        "open_prs": len(prs),
        "heads_seen": sum(1 for r in rows if not r.get("missing")),
        "heads_missing": [r["number"] for r in rows if r.get("missing")],
        "changed_rust_files_scanned": all_rs,
        "rust_files_with_syntax_errors": bad_rs,
        "branches_with_syntax_errors": [
            {"pr": r["number"], "head": r["head"], "sha": r["sha"], "files": r["syntax_errors"]}
            for r in broken
        ],
        "shared_paths": len(shared),
        "top_shared_paths": [
            {"path": p, "prs": owners[:24], "count": len(owners)}
            for p, owners in shared[:40]
        ],
        "duplicate_new_files": len(duplicates),
        "top_duplicate_new_files": duplicates[:40],
        "presence_wire_drift": wire_drift,
        "integrated_tree_rust_files": tree_rs,
        "integrated_tree_syntax_errors": tree_errors,
        "rows": rows,
    }
    out_json = REPO / args.out_json
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")

    lines = [
        "# Live open-PR stack compatibility audit",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Generated (UTC) | `{data['generated_utc']}` |",
        f"| Base | `{args.base}` |",
        f"| Open PRs in snapshot | {len(prs)} |",
        f"| PR heads available locally | {data['heads_seen']} |",
        f"| Changed `.rs` files parsed | {all_rs} |",
        f"| `.rs` files with syntax errors | {bad_rs} |",
        f"| Branches carrying broken Rust | {len(broken)} |",
        f"| Paths edited by >1 PR | {len(shared)} |",
        f"| New files implemented more than once | {len(duplicates)} |",
        f"| Integrated-tree `.rs` files parsed | {tree_rs} |",
        f"| Integrated-tree syntax errors | {len(tree_errors)} |",
        "",
        "Method: every path of every open PR head is read as a Git blob and every",
        "`.rs` blob is parsed with the tree-sitter Rust grammar. This is a",
        "syntax check, not a type check. No branch was checked out, pushed,",
        "closed, merged or retargeted.",
        "",
        "## 1. Branches that ship syntactically invalid Rust",
        "",
    ]
    if not broken:
        lines.append("None.")
    for r in broken:
        lines += [
            "",
            f"### PR #{r['number']} (`{r['head']}` at `{r['sha']}`)",
            "",
            "| File | First parse findings |",
            "|---|---|",
        ]
        for e in r["syntax_errors"]:
            lines.append(f"| `{e['file']}` | {', '.join(e['findings'])} |")
    lines += [
        "",
        "## 2. Conflict magnets (paths edited by more than one open PR)",
        "",
        "| Path | PRs | Count |",
        "|---|---|---|",
    ]
    for p, owners in shared[:30]:
        shown = ", ".join(f"#{n}" for n in owners[:12])
        if len(owners) > 12:
            shown += ", ..."
        lines.append(f"| `{p}` | {shown} | {len(owners)} |")
    lines += [
        "",
        "## 3. Duplicate new-file implementations",
        "",
        "| Path | Distinct versions | PRs |",
        "|---|---|---|",
    ]
    for d in duplicates[:30]:
        lines.append(
            f"| `{d['path']}` | {d['versions']} | "
            + ", ".join(f"#{n}" for n in d["authors"][:12])
            + (" ..." if len(d["authors"]) > 12 else "")
            + " |"
        )
    lines += [
        "",
        "## 4. Presence-message wire-shape drift",
        "",
    ]
    if wire_drift:
        for d in wire_drift:
            lines.append(
                f"- `{d['file']}`: {d['distinct_lines']} distinct constant/digest lines across the stack."
            )
    else:
        lines.append(
            "No presence-related source in the stack declares more than one shape "
            "of the same constant. The cross-PR digest disagreement reported by "
            "#91 is a disagreement between files, recorded in the findings ledger."
        )
    lines += [
        "",
        "## 5. Integrated tree",
        "",
        f"The current working branch parses {tree_rs} `.rs` files with "
        f"{len(tree_errors)} syntax findings. A zero here is necessary, not "
        "sufficient: semantic compatibility is checked by the wired gates and "
        "by CI, which is the compiler and test verifier for this workspace.",
        "",
        "## 6. Evidence boundary",
        "",
        "No Rust toolchain, crate registry, rustfmt or clippy exists in this "
        "workspace. No Rust test was run locally. Counts are live Git and "
        "GitHub observations, not performance measurements (directive 0.5). "
        "No green CI run is claimed (directive 0.3 item 5).",
        "",
    ]
    out_md = REPO / args.out_md
    out_md.write_text("\n".join(lines))
    print(
        f"open PRs={len(prs)} heads={data['heads_seen']} rs={all_rs} "
        f"broken={bad_rs} broken_branches={len(broken)} shared={len(shared)} "
        f"duplicates={len(duplicates)} tree_errors={len(tree_errors)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
