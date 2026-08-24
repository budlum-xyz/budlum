#!/usr/bin/env python3
# ============================================================================
# check_module_coverage.py - per-module coverage analysis
#
# Aggregates the file summaries in the `cargo llvm-cov --json` output by module
# prefix (weighted: covered/count), prints a table and, if present, applies a GATE
# against the baselines in .github/module-coverage-baselines.json.
#
# An honest two-step design (NO vacuous gate):
#   Step 1 (this wave): REPORT mode - a module table plus a JSON artifact on every run.
#      If the baselines file is ABSENT the gate is skipped (a SKIP marker is printed, exit 0).
#   Step 2 (next wave): MEASURED baselines are written from the first green artifact;
#      from that point a drop is a FAIL (with a canary, ratchet direction: up).
#
# Usage:
#   python3 scripts/check_module_coverage.py <llvm-cov.json> [--prefix KOK]
#   python3 scripts/check_module_coverage.py --self-test
# ============================================================================
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINES = os.path.join(REPO_ROOT, ".github", "module-coverage-baselines.json")

# The module prefix map: (module name, file path prefix)
MODULE_PREFIXES = [
    ("budlum:consensus", "src/consensus/"),
    ("budlum:crypto", "src/crypto/"),
    ("budlum:rpc", "src/rpc/"),
    ("budlum:chain", "src/chain/"),
    ("budlum:core", "src/core/"),
    ("budlum:domain", "src/domain/"),
    ("budlum:network", "src/network/"),
    ("budlum:storage", "src/storage/"),
    ("budlum:tokenomics", "src/tokenomics/"),
    ("budlum:node_di", "src/node_di/"),
    ("budlum:cli", "src/cli/"),
    ("budlum:docs", "src/docs/"),
    ("budzero:vm", "budzero/src/"),
    ("budzero:proof", "budzero/bud-proof/src/"),
    ("budzero:isa", "budzero/bud-isa/src/"),
    ("budzero:node", "budzero/bud-node/src/"),
    ("budzero:compiler", "budzero/bud-compiler/src/"),
]


def normalize(path: str) -> str:
    """Make the llvm-cov file paths repository relative."""
    p = path.replace("\\", "/")
    for anchor in ("/budlum/", "/budzero/"):
        if anchor in p:
            return p.split(anchor, 1)[1] if anchor == "/budlum/" else p[p.index("budzero/"):]
    return p


def module_of(path: str) -> str:
    for name, prefix in MODULE_PREFIXES:
        if path.startswith(prefix):
            return name
    return "__other__"


def analyze(cov: dict) -> list:
    """[(module, covered, total, percent)], percent: 100.0 when total=0."""
    acc = {}
    for data in cov.get("data", []):
        for f in data.get("files", []):
            fname = normalize(f.get("filename", ""))
            lines = (f.get("summary") or {}).get("lines") or {}
            total = lines.get("count", 0)
            covered = lines.get("covered", 0)
            if not total:
                continue
            mod = module_of(fname)
            c, t = acc.get(mod, (0, 0))
            acc[mod] = (c + covered, t + total)
    rows = []
    for mod, (c, t) in sorted(acc.items()):
        pct = (100.0 * c / t) if t else 100.0
        rows.append((mod, c, t, pct))
    return rows


def gate(rows, baselines: dict) -> int:
    fails = []
    for name, floor in baselines.items():
        hit = next((r for r in rows if r[0] == name), None)
        if hit is None:
            print(f"FAIL: a module with a baseline is missing from the report: {name}")
            fails.append(name)
            continue
        if hit[3] + 1e-9 < float(floor):
            print(f"FAIL: {name} coverage {hit[3]:.2f}% < baseline {floor:.2f}% (ratchet)")
            fails.append(name)
    if fails:
        return 1
    print("OK: every module baseline held (ratchet direction: no drop).")
    return 0


def print_table(rows) -> None:
    print(f"{'module':<22}{'covered':>10}{'total':>10}{'%':>9}")
    for mod, c, t, pct in rows:
        print(f"{mod:<22}{c:>10}{t:>10}{pct:>8.2f}")


def self_test() -> int:
    fake = {
        "data": [{
            "files": [
                {"filename": "/x/budlum/src/consensus/pow.rs",
                 "summary": {"lines": {"count": 100, "covered": 50}}},
                {"filename": "/x/budlum/src/crypto/hash.rs",
                 "summary": {"lines": {"count": 100, "covered": 90}}},
                {"filename": "/x/budlum/budzero/src/lib.rs",
                 "summary": {"lines": {"count": 10, "covered": 8}}},
            ]
        }]
    }
    with tempfile.TemporaryDirectory() as td:
        jf = os.path.join(td, "cov.json")
        with open(jf, "w") as fh:
            json.dump(fake, fh)
        rows = analyze(json.load(open(jf)))
        # beklenti: consensus %50, crypto %90, budzero:vm %80
        mp = {r[0]: r[3] for r in rows}
        assert abs(mp["budlum:consensus"] - 50.0) < 1e-6, mp
        assert abs(mp["budlum:crypto"] - 90.0) < 1e-6, mp
        assert abs(mp["budzero:vm"] - 80.0) < 1e-6, mp
        # gate: a baseline of 49 PASSes, a baseline of 51 FAILs (not vacuous)
        if gate(rows, {"budlum:consensus": 49.0}) != 0:
            print("BROKEN GATE: a baseline of 49 was refused!"); return 1
        if gate(rows, {"budlum:consensus": 51.0}) != 1:
            print("VACUOUS GATE: a baseline of 51 passed!"); return 1
        # no baselines file -> SKIP (a CI behaviour canary)
        env = dict(os.environ)
        miss = os.path.join(td, "absent.json")
        code = subprocess.run(
            [sys.executable, os.path.abspath(__file__), jf, "--baselines", miss],
            env=env).returncode
        if code != 0:
            print("BOZUK: baselines yokken SKIP yerine FAIL!"); return 1
    print("canary OK: the measurement is right; below the baseline FAILs, above PASSes, no baselines means SKIP.")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--self-test":
        return self_test()
    if not args:
        print("usage: check_module_coverage.py <llvm-cov.json> [--baselines FILE]")
        return 1
    cov_path = args[0]
    base_path = BASELINES
    if "--baselines" in args:
        base_path = args[args.index("--baselines") + 1]
    cov = json.load(open(cov_path))
    rows = analyze(cov)
    print_table(rows)
    if not os.path.exists(base_path):
        print(f"SKIP: {base_path} is absent - step 1 (report mode). "
              "Measured baselines will be added from the first green artifact (NO vacuous gate).")
        return 0
    with open(base_path) as fh:
        baselines = json.load(fh).get("module_line_floors", {})
    if not baselines:
        print("SKIP: the baselines are empty - report mode.")
        return 0
    return gate(rows, baselines)


if __name__ == "__main__":
    sys.exit(main())
