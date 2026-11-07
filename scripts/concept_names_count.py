#!/usr/bin/env python3
"""Count legacy concept-name matches (İP-05 baseline producer).

Reads config/naming/concept_map.toml and, for every concept, counts the files
and matching lines under the scan roots. Output is a tab-separated baseline.

Usage:
  scripts/concept_names_count.py            # print the baseline
  scripts/concept_names_count.py --write    # write .github/concept-names-baseline.txt
  scripts/concept_names_count.py --check    # exit 1 when any count exceeds the baseline
"""
import os
import re
import sys
import tomllib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MAP = os.path.join(ROOT, "config", "naming", "concept_map.toml")
BASELINE = os.path.join(ROOT, ".github", "concept-names-baseline.txt")
SCAN_ROOTS = ["src", "crates", "budzero", "execution", "mobile", "xtask",
              "docs", "config", "proto", "contracts"]
SKIP_DIRS = {"target", ".git", "node_modules", "out", "cache"}
TEXT_EXT = {".rs", ".md", ".toml", ".yml", ".yaml", ".json", ".sol", ".py",
            ".sh", ".txt", ".proto", ".ts", ".js", ".bud", ".nix", ".tr", ""}


def allowed(rel, allow):
    for a in allow:
        if rel == a or rel.startswith(a):
            return True
    return False


def iter_files(allow):
    for base in SCAN_ROOTS:
        top = os.path.join(ROOT, base)
        if not os.path.isdir(top):
            continue
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, ROOT).replace(os.sep, "/")
                if allowed(rel, allow):
                    continue
                if os.path.splitext(fn)[1] not in TEXT_EXT:
                    continue
                yield rel, full


def in_paths(rel, paths):
    if not paths:
        return True
    return any(rel.startswith(p) for p in paths)


def main():
    with open(MAP, "rb") as fh:
        cfg = tomllib.load(fh)
    allow = cfg.get("global_allow_paths", [])
    concepts = cfg["concept"]
    counts = [[0, 0] for _ in concepts]
    compiled = [[re.compile(p) for p in c["patterns"]] for c in concepts]
    files = list(iter_files(allow))
    for rel, full in files:
        try:
            with open(full, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except (UnicodeDecodeError, OSError):
            continue
        for i, c in enumerate(concepts):
            if not in_paths(rel, c.get("paths")):
                continue
            hit_lines = 0
            for line in lines:
                if any(r.search(line) for r in compiled[i]):
                    hit_lines += 1
            if hit_lines:
                counts[i][0] += 1
                counts[i][1] += hit_lines
    rows = []
    for c, (nf, nm) in zip(concepts, counts):
        rows.append((c["old"][0], c["owner"], nf, nm))
    out = ["# concept-names baseline (İP-05). Columns: old name, owner, files, matching lines.",
           "# Only decreases are allowed. Regenerate with scripts/concept_names_count.py --write."]
    for name, owner, nf, nm in rows:
        out.append(f"{name}\t{owner}\t{nf}\t{nm}")
    text = "\n".join(out) + "\n"
    if "--write" in sys.argv:
        with open(BASELINE, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {BASELINE}")
    elif "--check" in sys.argv:
        old = {}
        if os.path.exists(BASELINE):
            with open(BASELINE, encoding="utf-8") as fh:
                for ln in fh:
                    if ln.startswith("#") or not ln.strip():
                        continue
                    n, _o, f, m = ln.rstrip("\n").split("\t")
                    old[n] = (int(f), int(m))
        bad = [(n, nf, nm, old.get(n, (None, None))) for n, _o, nf, nm in rows
               if n not in old or nm > old[n][1] or nf > old[n][0]]
        for n, nf, nm, prev in bad:
            print(f"GROWN {n}: files {nf} lines {nm} baseline {prev}")
        print(f"checked {len(rows)} concepts, {len(files)} files, {len(bad)} grown")
        sys.exit(1 if bad else 0)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
