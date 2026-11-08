#!/usr/bin/env python3
"""Mechanical pre-scan for an externally supplied findings register.

The binding directive stays outside the repository. ``--directive PATH``
selects an operator-supplied copy of its findings table; the scanner extracts
code tokens in backticks and checks them against the current tracked tree:

* path tokens (contain "/") must exist as a tracked file or directory;
* symbol tokens (contain "::" or "_", or are CamelCase) must occur as a whole
  word in code outside the audit documents.

The result is a PRE-SCAN, not a verdict. A present identifier does not prove
the bug is still there, and an absent identifier does not prove the fix. The
closing verdict requires the reproduction test named in directive 14.1.5.

Usage from the repository root:
    python3 docs/audit/live_status_scan.py --directive /path/to/findings.md
    python3 docs/audit/live_status_scan.py --directive /path/to/findings.md \
        --output /tmp/LIVE_STATUS.md
"""

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "docs", "audit", "LIVE_STATUS.md")

SEVERITY = {
    "Kritik": "Critical",
    "Y\u00fcksek": "High",
    "Orta": "Medium",
    "D\u00fc\u015f\u00fck": "Low",
}
EXCLUDED_CORPUS = {
    "THE_BUDLUM_DIREKTIF.md",
    "docs/audit/LIVE_STATUS.md",
    "docs/audit/FINDINGS.md",
    "docs/audit/AUDIT_FINDINGS.md",
}
TEXT_EXTS = (".rs", ".toml", ".md", ".yml", ".yaml", ".sh", ".py", ".json", ".sol", ".proto")


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [f for f in out.splitlines() if f]


def load_corpus(files):
    corpus = {}
    for rel in files:
        if rel in EXCLUDED_CORPUS or not rel.endswith(TEXT_EXTS):
            continue
        try:
            with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                corpus[rel] = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
    return corpus


def parse_rows(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.startswith("| BLG-"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            rows.append(cells)
    return rows


def classify_token(tok):
    """Return ("path", value), ("symbol", value) or None."""
    tok = tok.strip()
    if not tok or " " in tok or "=" in tok or tok.startswith("-"):
        return None
    if "/" in tok and not tok.startswith("http"):
        base = re.split(r"::|\(|\[", tok)[0].rstrip("/")
        if re.fullmatch(r"[A-Za-z0-9_./\-*]+", base) and "*" not in base:
            return ("path", base)
        return None
    head = re.split(r"\(", tok)[0]
    last = head.split("::")[-1]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", last) or len(last) < 5:
        return None
    if "::" in head or "_" in last or re.search(r"[a-z][A-Z]", last):
        return ("symbol", last)
    return None


def path_exists(rel, files_set, file_dirs):
    if rel in files_set or rel in file_dirs:
        return True
    return False


def build_word_index(corpus):
    """Map every identifier-like word to the first file that contains it."""
    index = {}
    for rel in sorted(corpus):
        if rel.endswith(".md"):
            continue  # documentation does not count as code evidence
        for word in set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", corpus[rel])):
            index.setdefault(word, rel)
    return index


def scan(rows, files, corpus):
    word_index = build_word_index(corpus)
    files_set = set(files)
    file_dirs = set()
    for f in files:
        parts = f.split("/")
        for i in range(1, len(parts)):
            file_dirs.add("/".join(parts[:i]))
    out = []
    for cells in rows:
        ident = cells[0]
        severity = next((SEVERITY[c] for c in cells if c in SEVERITY), "Unrated")
        closing = cells[-1]
        packages = sorted(set(re.findall(r"\u0130P-(\d+)", closing)), key=int)
        wp = ", ".join(f"WP-{p}" for p in packages) if packages else "TBD"
        full = " | ".join(cells)
        fix_trace = "Directive notes a fix trace" if "D\u00fczeltme izi" in full else ""
        tokens = re.findall(r"`([^`]+)`", full)
        checks = []
        seen = set()
        for tok in tokens:
            kind = classify_token(tok)
            if kind is None or kind[1] in seen:
                continue
            seen.add(kind[1])
            checks.append((kind[0], kind[1]))
        found, missing_paths, evidence = 0, [], []
        for kind, value in checks:
            if kind == "path":
                if path_exists(value, files_set, file_dirs):
                    found += 1
                    evidence.append(value)
                else:
                    missing_paths.append(value)
            else:
                first = word_index.get(value)
                if first is not None:
                    found += 1
                    evidence.append(first)
                # symbol misses are recorded in the count only
        total = len(checks)
        if total == 0:
            status = "Pre-scan: no checkable token; manual review needed"
        elif found == 0 and missing_paths:
            status = "Pre-scan: named path(s) absent; removal candidate, verify"
        elif found == total:
            status = "Pre-scan: all named identifiers found in code; not a verdict"
        elif found == 0:
            status = "Pre-scan: no named identifier found in code; possibly fixed, verify"
        else:
            status = "Pre-scan: partial; manual review needed"
        uniq = list(dict.fromkeys(evidence))
        ev = "; ".join(f"`{e}`" for e in uniq[:2]) if uniq else "-"
        out.append(
            {
                "id": ident,
                "sev": severity,
                "wp": wp,
                "checks": f"{found}/{total}" if total else "0/0",
                "status": status,
                "evidence": ev,
                "note": fix_trace,
            }
        )
    return out


def write(results, output):
    counts = {}
    for r in results:
        counts[r["sev"]] = counts.get(r["sev"], 0) + 1
    lines = []
    lines.append("# Live Status of the Findings Register")
    lines.append("")
    lines.append(
        "This file is the M0 pre-scan output (directive sections 14.1 and 15.6). "
        "It is generated by `docs/audit/live_status_scan.py` from an external "
        "findings register supplied with `--directive`. Finding titles stay in "
        "that source of record. The status column is NOT a verdict. Closing a "
        "finding requires a reproduction test that fails before the fix and "
        "passes after it (directive 14.1.5)."
    )
    lines.append("")
    lines.append("## Status vocabulary (directive 14.1.3)")
    lines.append("")
    lines.append(
        "Open, Verified (open and reproduced), Closed (fix merged), "
        "Removed (code deleted), Invalid (condition gone, shown by a test). "
        "This scan sets none of them. It only sets a pre-scan indication."
    )
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append(f"- Findings scanned: {len(results)}")
    for sev in ("Critical", "High", "Medium", "Low", "Unrated"):
        if sev in counts:
            lines.append(f"- {sev}: {counts[sev]}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append(
        "| ID | Severity | Closing package | Tokens present | Pre-scan | Evidence | Reproduction test | Note |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in results:
        lines.append(
            f"| {r['id']} | {r['sev']} | {r['wp']} | {r['checks']} | {r['status']} | "
            f"{r['evidence']} | Not written | {r['note']} |"
        )
    lines.append("")
    with open(output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directive",
        required=True,
        help="external findings-register Markdown file; never an in-tree directive",
    )
    parser.add_argument(
        "--output",
        default=OUT,
        help=f"report path (default: {OUT})",
    )
    args = parser.parse_args(argv)
    files = tracked_files()
    corpus = load_corpus(files)
    rows = parse_rows(args.directive)
    if not rows:
        print("no findings rows found", file=sys.stderr)
        return 1
    results = scan(rows, files, corpus)
    write(results, args.output)
    print(f"wrote {args.output} ({len(results)} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
