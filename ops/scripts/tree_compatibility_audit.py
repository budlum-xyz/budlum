#!/usr/bin/env python3
"""Cross-PR compatibility audit of the integrated tree, stdlib only.

The open PR stack edits the same files from different bases. A clean Git merge
does not guarantee that the result satisfies the repository's own gates. This
tool runs six cheap, whole-tree checks locally (no Rust toolchain needed), so
a carried PR's defect is found while it is carried rather than in CI:

1. typographic dashes (the `no_unicode_dashes` gate's 13 characters);
2. Turkish characters outside the files the `tree_is_english` gate exempts;
3. `pub mod x;` / `mod x;` declarations with no source file;
4. `uses: owner/repo@ref` workflow actions that are not pinned to a commit SHA
   (directive 16.2 item 4);
5. JSON and TOML files that fail to parse;
6. duplicate `pub mod` declarations in one module file.

Usage:
    python3 ops/scripts/tree_compatibility_audit.py \
        --out-json docs/audit/TREE_COMPATIBILITY_DATA_2026-11-06.json

Exit status is 1 when a finding exists, 0 otherwise.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "target", "node_modules", ".cargo", "Unselected files", "build", "dist"}
DASHES = "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u00ad\u2e3a\u2e3b\ufe58\ufe63\uff0d"
TURKISH = "\u015f\u011f\u0131\u00e7\u00f6\u00fc\u015e\u011e\u0130\u00c7\u00d6\u00dc"
TEXT_EXT = {".rs", ".md", ".toml", ".json", ".yml", ".yaml", ".py", ".sh", ".kt", ".xml", ".txt", ".gradle", ".kts", ".proto"}
MOD_RE = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.M)
ACTION_RE = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def text_files() -> list[pathlib.Path]:
    out = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or SKIP_DIRS.intersection(path.parts):
            continue
        if path.suffix in TEXT_EXT or path.name in {"Dockerfile", "Makefile"}:
            out.append(path)
    return sorted(out)


def rel(path: pathlib.Path) -> str:
    return str(path.relative_to(ROOT))


def typography(files: list[pathlib.Path]) -> list[str]:
    hits = []
    for path in files:
        try:
            lines = path.read_text().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(lines, 1):
            bad = sorted({c for c in DASHES if c in line})
            if bad:
                hits.append(f"{rel(path)}:{i}: typographic dash U+{ord(bad[0]):04X}")
    return hits


def turkish(files: list[pathlib.Path]) -> list[str]:
    """Turkish is allowed only where the tree's own gate allows it.

    `tree_is_english` baselines five source files, exempts README.tr.md, the
    Turkish localisation resources, the localized link label, the concept-name
    map (whose subject is the Turkish names being retired) and the gate's own
    prose. This check mirrors those exemptions; a new Turkish line anywhere
    else is a cross-PR compatibility defect.
    """
    baseline = ROOT / ".github/turkish-baseline.txt"
    baselined: set[str] = set()
    if baseline.is_file():
        for line in baseline.read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                baselined.add(parts[0])
    exempt_exact = {
        "README.md",
        "README.tr.md",
        "config/naming/concept_map.toml",
        ".github/workflows/ci.yml",
        ".github/concept-names-baseline.txt",
        ".github/turkish-baseline.txt",
        "docs/NAMING.md",
        "ops/scripts/tree_compatibility_audit.py",
        "xtask/gates/src/gates/bud3_forbidden_phrases.rs",
        "xtask/gates/src/gates/pq_claims_are_backed.rs",
        "xtask/gates/src/gates/tree_is_english.rs",
    }
    exempt_prefixes = (
        "docs/audit/",
        "mobile/android/app/src/main/res/values-tr/",
    )
    hits = []
    for path in files:
        r = rel(path)
        if r in exempt_exact or r in baselined or r.startswith(exempt_prefixes):
            continue
        try:
            lines = path.read_text().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(lines, 1):
            if any(c in line for c in TURKISH):
                hits.append(f"{r}:{i}: Turkish character outside the exempt files")
    return hits


def module_declarations(files: list[pathlib.Path]) -> list[str]:
    # A `mod x;` inside an inline `mod gates { ... }` resolves under
    # `gates/` instead of next to the file. Build a stem index so the check
    # can resolve inline modules without re-implementing Rust's name resolver.
    stems: dict[str, list[pathlib.Path]] = {}
    for path in files:
        if path.suffix == ".rs":
            stems.setdefault(path.stem, []).append(path)
    hits = []
    for path in files:
        if path.suffix != ".rs":
            continue
        text = path.read_text()
        names = MOD_RE.findall(text)
        duplicates = sorted({n for n in names if names.count(n) > 1})
        for name in duplicates:
            hits.append(f"{rel(path)}: duplicate module declaration `{name}`")
        # A `mod x;` next to this file resolves to `<dir>/x.rs` or
        # `<dir>/x/mod.rs`. `lib.rs`/`mod.rs` resolve in their own directory.
        directory = path.parent
        lines = text.splitlines()
        for match in MOD_RE.finditer(text):
            name = match.group(1)
            lineno = text[: match.start()].count("\n")
            # `#[path = "..."] mod x;` mounts a file elsewhere. Resolve the
            # mount instead of treating it as a missing sibling.
            mounted = None
            for previous in lines[max(0, lineno - 4) : lineno]:
                if "#[path" in previous and '"' in previous:
                    mounted = previous.split('"')[1]
                    break
            if mounted is not None:
                target = (directory / mounted).resolve()
                if not target.is_file():
                    hits.append(f"{rel(path)}:{lineno + 1}: #[path] target {mounted} is missing")
                continue
            if (directory / f"{name}.rs").is_file() or (directory / name / "mod.rs").is_file():
                continue
            mounted_elsewhere = any(
                candidate.parent == directory or directory in candidate.parents
                for candidate in stems.get(name, [])
            )
            if mounted_elsewhere:
                continue
            hits.append(f"{rel(path)}:{lineno + 1}: mod {name}; has no source file")
    return hits


def action_pins(files: list[pathlib.Path]) -> list[str]:
    hits = []
    for path in files:
        if path.suffix not in {".yml", ".yaml"} or ".github/workflows" not in rel(path):
            continue
        for i, line in enumerate(path.read_text().splitlines(), 1):
            m = ACTION_RE.search(line)
            if m and not SHA_RE.match(m.group(2)):
                hits.append(f"{rel(path)}:{i}: {m.group(1)}@{m.group(2)} is not a commit SHA")
    return hits


def config_parsing(files: list[pathlib.Path]) -> list[str]:
    hits = []
    for path in files:
        if path.suffix == ".json":
            try:
                json.loads(path.read_text())
            except (ValueError, UnicodeDecodeError) as exc:
                hits.append(f"{rel(path)}: invalid JSON: {exc}")
        elif path.suffix == ".toml":
            try:
                tomllib.loads(path.read_text())
            except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
                hits.append(f"{rel(path)}: invalid TOML: {exc}")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-json", required=True)
    args = ap.parse_args()

    files = text_files()
    checks = {
        "typographic_dashes": typography(files),
        "turkish_characters": turkish(files),
        "module_declarations": module_declarations(files),
        "action_pins": action_pins(files),
        "config_parsing": config_parsing(files),
    }
    problems = [p for group in checks.values() for p in group]
    data = {
        "text_files_scanned": len(files),
        "checks": {k: {"count": len(v), "first": v[:20]} for k, v in checks.items()},
        "problems": len(problems),
    }
    out = ROOT / args.out_json
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(f"scanned {len(files)} text files, {len(problems)} findings")
    for name, findings in checks.items():
        print(f"  {name}: {len(findings)}")
        for finding in findings[:8]:
            print("    " + finding)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
