#!/usr/bin/env python3
# ============================================================================
# check_module_coverage.py — G4 (ADIM8.5 §4): modül-bazı coverage analizi
#
# `cargo llvm-cov --json` çıktısındaki dosya özetlerini modül öneklerine
# toplar (ağırlıklı: covered/count), tablo basar ve (varsa)
# .github/module-coverage-baselines.json'daki tabanlara karşı KAPI uygular.
#
# Dürüst iki-adım tasarım (vacuous-gate YOK):
#   1. Adım (bu dalga): RAPOR modu — her koşuda modül tablosu + JSON artifact.
#      Baselines dosyası YOKSA gate atlanır (SKIP marker'ı basılır, exit 0).
#   2. Adım (sonraki dalga): ilk yeşil artifact'ten ÖLÇÜLMÜŞ tabanlar yazılır;
#      o noktadan sonra düşüş FAIL olur (canary'li, ratchet yönü: yukarı).
#
# Kullanım:
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

# Modül önek haritası: (modül adı, dosya-yolu öneki)
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
    """llvm-cov dosya yollarını repo-göreli hale getir."""
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
    """[(modül, covered, total, percent)], percent: total=0 ise 100.0."""
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
            print(f"FAIL: taban istenen modül raporda yok: {name}")
            fails.append(name)
            continue
        if hit[3] + 1e-9 < float(floor):
            print(f"FAIL: {name} coverage {hit[3]:.2f}% < taban {floor:.2f}% (ratchet)")
            fails.append(name)
    if fails:
        return 1
    print("OK: tüm modül tabanları tuttu (ratchet yönü: düşüş yok).")
    return 0


def print_table(rows) -> None:
    print(f"{'modül':<22}{'kaplanan':>10}{'toplam':>10}{'%':>9}")
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
        # gate: 49 taban PASS, 51 taban FAIL (vacuous değil)
        if gate(rows, {"budlum:consensus": 49.0}) != 0:
            print("BOZUK KAPI: 49 taban reddedildi!"); return 1
        if gate(rows, {"budlum:consensus": 51.0}) != 1:
            print("VACUOUS GATE: 51 taban geçti!"); return 1
        # baselines dosyası yok -> SKIP (CI davranış kanaryası)
        env = dict(os.environ)
        miss = os.path.join(td, "yok.json")
        code = subprocess.run(
            [sys.executable, os.path.abspath(__file__), jf, "--baselines", miss],
            env=env).returncode
        if code != 0:
            print("BOZUK: baselines yokken SKIP yerine FAIL!"); return 1
    print("kanarya OK: ölçüm doğru; taban altı FAIL, üstü PASS, baselines yoksa SKIP.")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--self-test":
        return self_test()
    if not args:
        print("kullanım: check_module_coverage.py <llvm-cov.json> [--baselines DOSYA]")
        return 1
    cov_path = args[0]
    base_path = BASELINES
    if "--baselines" in args:
        base_path = args[args.index("--baselines") + 1]
    cov = json.load(open(cov_path))
    rows = analyze(cov)
    print_table(rows)
    if not os.path.exists(base_path):
        print(f"SKIP: {base_path} yok — G4 1. adım (rapor modu). "
              "İlk yeşil artifact'ten ölçülmüş tabanlar eklenecek (vacuous-gate YOK).")
        return 0
    with open(base_path) as fh:
        baselines = json.load(fh).get("module_line_floors", {})
    if not baselines:
        print("SKIP: baselines boş — rapor modu.")
        return 0
    return gate(rows, baselines)


if __name__ == "__main__":
    sys.exit(main())
