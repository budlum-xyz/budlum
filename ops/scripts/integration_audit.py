#!/usr/bin/env python3
"""Audit the integrated tree without a Rust toolchain.

More than fifty pull requests are open against one base. Each was written as
if it were alone. Merging several of them into one branch is only safe when
the cross-file tables still agree. The Rust gates prove most of those facts,
but this workspace has no `cargo`, and a merge can break a table without
breaking any single file. This script replays the invariants that a merge can
break, using only the Python standard library.

Checks (each name is also a stable finding prefix):

* `rpc_method_table_matches_registered_methods`: `api.rs` declarations and
  `METHOD_CLASSES` rows are the same names in the same order.
* `compat_gateway_tables_agree`: the Ethereum gateway table, the class table
  and `api.rs` agree on every served, pending and refused method.
* `gate_modules_are_registered`: every gate file is registered and wired.
* `test_modules_are_registered`: every test file is registered.
* `module_declarations_resolve`: no `mod name;` points at a missing file.
* `no_vacuous_tests`: no `assert!(true)` stands in for a test.
* `package_registry_is_complete`: the registry names WP-01 to WP-64.
* `binding_directive_stays_outside_repository`: the binding directive is not
  in the tree and is ignored by git.
* `root_python_scripts_are_english`: root helper scripts are source too.
* `integration_audit_is_wired_in_ci`: CI runs this script and its self-test.
* `gateway_filter_pool_is_wired`: the bounded filter table reaches the RPC
  handlers and has its acceptance test.
* `legacy_storage_ratchet_is_consistent`: the shrinking removal baseline has
  no new offender and no stale line.

Usage:

    python3 ops/scripts/integration_audit.py --self-test
    python3 ops/scripts/integration_audit.py [--root DIR]
    python3 ops/scripts/integration_audit.py --branches

`--self-test` injects one real violation per check into a temporary tree and
requires the check to report it. A check that cannot fail proves nothing.
Output is sorted, so two runs on the same tree print the same text.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# The identifier list of the `no-legacy-storage` gate (directive section 5.5).
# Kept here so a merge can be checked without compiling the Rust gate. This
# file lives in ops/, which that gate does not scan.
LEGACY_IDENTIFIERS = (
    "ContentManifest ErasureScheme ReedSolomon EncodedObject LrcLayout MsrError "
    "StorageRegistry StorageDealOpen OpenDeal AnswerCodingAudit "
    "AcceptReallocation OpenChallenge AnswerChallenge StorageProvider "
    "InMemoryStorageProvider BudStorageEdition GeneratedSpec MobileSelfProfile "
    "MobileSelfContentPolicy CustodyLedger ServerAdmission OneShareRegistry "
    "SingleScreenView PactBinding BudBitswap MemoryContentStore "
    "ContentDiscovery VideoRecipe ThreeRecipePublic bud_storageOpenDeal "
    "bud_storageRegisterManifest bud_storageQrFeedPreview"
).split()

LEGACY_PATHS = (
    "bud/",
    "budzero/bud-node/",
    "src/domain/storage_deal.rs",
    "src/domain/deal_open.rs",
    "src/chain/storage_maintenance.rs",
)

LEGACY_SELF = {
    "xtask/gates/src/gates/no_legacy_storage.rs",
    ".github/no-legacy-storage-baseline.txt",
}

GATEWAY_PREFIXES = ("eth_", "net_", "web3_", "debug_")

FILTER_METHODS = (
    "eth_newFilter",
    "eth_newBlockFilter",
    "eth_getFilterChanges",
    "eth_getFilterLogs",
    "eth_uninstallFilter",
)

# Built at runtime so this file carries no Turkish character itself. The
# repository is English (directive section 0.1).
TURKISH_PACKAGE_ID = re.compile(chr(0x0130) + r"P-\d+")


def read(root: Path, path: str) -> str:
    """Read a UTF-8 file, or return an empty string when it is absent."""
    full = root / path
    if not full.is_file():
        return ""
    try:
        return full.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def write(root: Path, path: str, text: str) -> None:
    full = root / path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(text, encoding="utf-8")


def declared_methods(root: Path) -> list[str]:
    """`#[method]`, `#[subscription]` and unsubscribe names, in source order."""
    api = read(root, "src/rpc/api.rs")
    pattern = re.compile(
        r'#\[(?:method|subscription)\(name = "([^"]+)"'
        r'|unsubscribe = "([^"]+)"'
    )
    found: list[tuple[int, str]] = []
    for match in pattern.finditer(api):
        found.append((match.start(), match.group(1) or match.group(2)))
    return [name for _, name in sorted(found)]


def class_rows(root: Path) -> list[tuple[str, str, str]]:
    """(name, listener, effect) for every production class-table row."""
    source = read(root, "src/rpc/method_class.rs")
    cut = source.find("#[cfg(test)]")
    text = source[: cut if cut > 0 else len(source)]
    pattern = re.compile(r'row\("([^"]+)",\s*(\w+),\s*(\w+)\)')
    return pattern.findall(text)


def gateway_rows(root: Path) -> list[tuple[str, str]]:
    """(name, Answer variant) for every row of the Ethereum gateway table."""
    source = read(root, "src/rpc/compat/ethereum/mod.rs")
    start = source.find("const METHODS")
    end = source.find("/// The row for a wire name")
    text = source[start:] if start >= 0 else ""
    if end > start >= 0:
        text = source[start:end]
    pattern = re.compile(r'MethodRow \{\s*name: "([^"]+)",\s*answer: Answer::(\w+)', re.S)
    return pattern.findall(text)


def check_rpc_method_table(root: Path) -> list[str]:
    declared = declared_methods(root)
    rows = [row[0] for row in class_rows(root)]
    problems: list[str] = []
    if not declared or not rows:
        return ["rpc_method_table_matches_registered_methods: api.rs or method_class.rs is empty"]
    duplicates = sorted({name for name in rows if rows.count(name) > 1})
    if duplicates:
        problems.append(f"duplicate class rows: {', '.join(duplicates)}")
    missing = sorted(set(declared) - set(rows))
    extra = sorted(set(rows) - set(declared))
    if missing:
        problems.append(f"declared without a class row: {', '.join(missing)}")
    if extra:
        problems.append(f"class rows without a declaration: {', '.join(extra)}")
    if declared != rows:
        problems.append("class rows are not in api.rs declaration order")
    return [f"rpc_method_table_matches_registered_methods: {p}" for p in problems]


EXPECTED_EFFECT = {
    "ChainRead": "Read",
    "MethodNotFound": "Refused",
    "EeUnavailable": "Refused",
    "BoundedFilter": "LocalAdmin",
}


def check_gateway_tables(root: Path) -> list[str]:
    rows = gateway_rows(root)
    declared = set(declared_methods(root))
    classes = {name: (listener, effect) for name, listener, effect in class_rows(root)}
    problems: list[str] = []
    if not rows:
        return ["compat_gateway_tables_agree: the gateway table is empty"]
    names = [name for name, _ in rows]
    if len(set(names)) != len(names):
        problems.append("the gateway table has a duplicate row")
    for name, variant in rows:
        is_pending = variant == "Pending"
        if is_pending:
            if name in declared:
                problems.append(f"{name} is pending but declared in api.rs")
            if name in classes:
                problems.append(f"{name} is pending but has a class row")
            continue
        if name not in declared:
            problems.append(f"{name} is served but not declared in api.rs")
        if name not in classes:
            problems.append(f"{name} is served but has no class row")
        expected = EXPECTED_EFFECT.get(variant)
        if expected is None:
            problems.append(f"{name} has an unknown answer {variant}")
        elif name in classes and classes[name][1] != expected:
            problems.append(
                f"{name} answers {variant} but its class effect is {classes[name][1]}"
            )
    for name in sorted(declared):
        if name.startswith(GATEWAY_PREFIXES) and name not in names:
            problems.append(f"{name} is declared but has no gateway row")
    for name in sorted(classes):
        if name.startswith(GATEWAY_PREFIXES) and name not in names:
            problems.append(f"{name} has a class row but no gateway row")
    return [f"compat_gateway_tables_agree: {p}" for p in problems]


def check_gate_modules(root: Path) -> list[str]:
    main = read(root, "xtask/gates/src/main.rs")
    modules = set(re.findall(r"pub mod ([a-z0-9_]+);", main))
    gate_dir = root / "xtask/gates/src/gates"
    files = {p.stem for p in gate_dir.glob("*.rs") if p.stem != "mod"}
    problems: list[str] = []
    if not modules or not files:
        return ["gate_modules_are_registered: no gate modules found"]
    for name in sorted(files - modules):
        problems.append(f"{name}.rs has no pub mod declaration")
    for name in sorted(modules - files):
        problems.append(f"pub mod {name} has no gate file")
    wired = set(re.findall(r"run: gates::([a-z0-9_]+)::run", main))
    if len(wired) * 2 < len(files):
        problems.append(
            f"only {len(wired)} Gate entries for {len(files)} gate modules; the scan is too narrow"
        )
    for name in sorted(wired - files):
        problems.append(f"Gate entry wires {name}, which has no gate file")
    return [f"gate_modules_are_registered: {p}" for p in problems]


def check_test_modules(root: Path) -> list[str]:
    mod = read(root, "src/tests/mod.rs")
    declared = set(re.findall(r"(?:pub )?mod ([a-z0-9_]+);", mod))
    test_dir = root / "src/tests"
    files = {p.stem for p in test_dir.glob("*.rs") if p.stem != "mod"}
    problems: list[str] = []
    if not files:
        return ["test_modules_are_registered: no test files found"]
    for name in sorted(files - declared):
        problems.append(f"{name}.rs is not registered in src/tests/mod.rs")
    for name in sorted(declared - files):
        problems.append(f"mod {name} has no test file")
    return [f"test_modules_are_registered: {p}" for p in problems]


def check_module_declarations(root: Path) -> list[str]:
    problems: list[str] = []
    sources = sorted((root / "src").rglob("*.rs")) if (root / "src").is_dir() else []
    for path in sources:
        text = path.read_text(encoding="utf-8")
        if "#[path" in text:
            continue
        if path.name in ("mod.rs", "lib.rs", "main.rs"):
            base = path.parent
        else:
            base = path.parent / path.stem
        for line in text.splitlines():
            if line.lstrip().startswith("//"):
                continue
            match = re.match(r"\s*(?:pub )?mod ([a-z0-9_]+);", line)
            if not match:
                continue
            name = match.group(1)
            if (base / f"{name}.rs").is_file() or (base / name / "mod.rs").is_file():
                continue
            rel = path.relative_to(root).as_posix()
            problems.append(f"{rel}: mod {name} has no file under {base.relative_to(root).as_posix()}")
    return [f"module_declarations_resolve: {p}" for p in problems]


def check_vacuous_tests(root: Path) -> list[str]:
    problems: list[str] = []
    roots = [root / "src", root / "xtask/gates/tests", root / "crates"]
    for directory in roots:
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.rs")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("//", 1)[0]
                if re.search(r"assert!\(\s*true\s*[,)]", code) or re.search(
                    r"assert_eq!\(\s*1\s*,\s*1\s*\)", code
                ):
                    rel = path.relative_to(root).as_posix()
                    problems.append(f"{rel}:{number} asserts a constant")
    return [f"no_vacuous_tests: {p}" for p in problems]


def check_package_registry(root: Path) -> list[str]:
    text = read(root, "docs/work/PACKAGES.md")
    problems: list[str] = []
    if not text:
        return ["package_registry_is_complete: docs/work/PACKAGES.md is absent"]
    present = set(re.findall(r"WP-(\d{2})\b", text))
    missing = [f"WP-{n:02d}" for n in range(1, 65) if f"{n:02d}" not in present]
    if missing:
        problems.append(f"registry rows missing: {', '.join(missing)}")
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix not in {".rs", ".md", ".toml", ".yml", ".yaml", ".py", ".txt"}:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if TURKISH_PACKAGE_ID.search(body):
            problems.append(f"non-English package id in {path.relative_to(root).as_posix()}")
    return [f"package_registry_is_complete: {p}" for p in problems]


def check_binding_directive(root: Path) -> list[str]:
    problems: list[str] = []
    if (root / "THE_BUDLUM_DIREKTIF.md").exists():
        problems.append("THE_BUDLUM_DIREKTIF.md is in the tree")
    if "THE_BUDLUM_DIREKTIF.md" not in read(root, ".gitignore"):
        problems.append(".gitignore does not name THE_BUDLUM_DIREKTIF.md")
    return [f"binding_directive_stays_outside_repository: {p}" for p in problems]


def check_ci_wiring(root: Path) -> list[str]:
    ci = read(root, ".github/workflows/ci.yml")
    problems: list[str] = []
    if "ops/scripts/integration_audit.py --self-test" not in ci:
        problems.append("CI does not run the audit self-test")
    if "ops/scripts/integration_audit.py --root" not in ci:
        problems.append("CI does not run the audit on the tree")
    return [f"integration_audit_is_wired_in_ci: {p}" for p in problems]


def check_filter_pool_wiring(root: Path) -> list[str]:
    server = read(root, "src/rpc/server.rs")
    gateway = read(root, "src/rpc/compat/ethereum/mod.rs")
    pool = read(root, "src/rpc/compat/ethereum/filters.rs")
    classes = {name: effect for name, _, effect in class_rows(root)}
    problems: list[str] = []
    if "pub mod filters;" not in gateway:
        problems.append("the gateway does not declare the filters module")
    if "eth_filters" not in server or "ethereum::filters::peer_of" not in server:
        problems.append("the RPC handlers do not use the bounded pool")
    if "ethereum::filter_error" not in server:
        problems.append("the RPC handlers do not map filter failures")
    if "fn eth_filters_are_bounded" not in pool:
        problems.append("the card's bounded-filter test is absent")
    for name in FILTER_METHODS:
        if f'#[method(name = "{name}", with_extensions)]' not in read(root, "src/rpc/api.rs"):
            problems.append(f"{name} does not receive the connection peer key")
        if classes.get(name) != "LocalAdmin":
            problems.append(f"{name} is not classified as node-local work")
    return [f"gateway_filter_pool_is_wired: {p}" for p in problems]


def check_legacy_ratchet(root: Path) -> list[str]:
    found: set[str] = set()
    for scan_root in ("src", "crates", "budzero", "xtask", "docs"):
        directory = root / scan_root
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if rel in LEGACY_SELF:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if any(identifier in text for identifier in LEGACY_IDENTIFIERS):
                found.add(rel)
    for banned in LEGACY_PATHS:
        if (root / banned.rstrip("/")).exists():
            found.add(banned)
    baseline = {
        line.strip()
        for line in read(root, ".github/no-legacy-storage-baseline.txt").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    problems: list[str] = []
    for name in sorted(found - baseline):
        problems.append(f"new offender: {name}")
    for name in sorted(baseline - found):
        problems.append(f"stale baseline line: {name}")
    return [f"legacy_storage_ratchet_is_consistent: {p}" for p in problems]


TURKISH_CHARACTERS = "\u015f\u011f\u0131\u00e7\u00f6\u00fc\u015e\u011e\u0130\u00c7\u00d6\u00dc"


def check_root_python_is_english(root: Path) -> list[str]:
    """Root-level helper scripts are source, so they must be English too."""
    problems: list[str] = []
    for path in sorted(root.glob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(character in line for character in TURKISH_CHARACTERS):
                problems.append(f"{path.name}:{number} carries a Turkish character")
    return [f"root_python_scripts_are_english: {p}" for p in problems]


CHECKS = (
    check_rpc_method_table,
    check_gateway_tables,
    check_gate_modules,
    check_test_modules,
    check_module_declarations,
    check_vacuous_tests,
    check_package_registry,
    check_binding_directive,
    check_root_python_is_english,
    check_ci_wiring,
    check_filter_pool_wiring,
    check_legacy_ratchet,
)


def findings(root: Path) -> list[str]:
    """Every finding, sorted so the report is deterministic."""
    out: list[str] = []
    for check in CHECKS:
        out.extend(check(root))
    return sorted(out)


def fixture(root: Path) -> None:
    """A small tree where every check passes."""
    write(
        root,
        "src/rpc/api.rs",
        '#[rpc(server)]\n'
        'pub trait BudlumApi {\n'
        '    #[method(name = "bud_chainId")]\n'
        '    async fn chain_id(&self) -> Result<String, ()>;\n'
        '    #[method(name = "eth_chainId")]\n'
        '    async fn eth_chain_id(&self) -> Result<String, ()>;\n'
        + "".join(
            f'    #[method(name = "{name}", with_extensions)]\n'
            f'    async fn stub_{i}(&self) -> Result<u8, ()>;\n'
            for i, name in enumerate(FILTER_METHODS)
        )
        + '}\n',
    )
    write(
        root,
        "src/rpc/method_class.rs",
        'const METHOD_CLASSES: &[MethodClass] = &[\n'
        '    row("bud_chainId", Public, Read),\n'
        '    row("eth_chainId", Public, Read),\n'
        + "".join(f'    row("{name}", Public, LocalAdmin),\n' for name in FILTER_METHODS)
        + '];\n'
        '#[cfg(test)]\nmod tests {}\n',
    )
    write(
        root,
        "src/rpc/compat/ethereum/mod.rs",
        'pub mod filters;\n'
        'const METHODS: &[MethodRow] = &[\n'
        '    MethodRow { name: "eth_chainId", answer: Answer::ChainRead },\n'
        + "".join(
            f'    MethodRow {{ name: "{name}", answer: Answer::BoundedFilter }},\n'
            for name in FILTER_METHODS
        )
        + '    MethodRow { name: "eth_subscribe", answer: Answer::Pending { package: "WP-28" } },\n'
        '    MethodRow { name: "eth_unsubscribe", answer: Answer::Pending { package: "WP-28" } },\n'
        '];\n'
        '/// The row for a wire name, or `None`.\n',
    )
    write(root, "src/rpc/compat/ethereum/filters.rs", 'fn eth_filters_are_bounded() {}\n')
    write(root, "src/rpc/compat/ethereum/tests.rs", '// gateway tests\n')
    write(
        root,
        "src/rpc/server.rs",
        'struct RpcServer { eth_filters: u8 }\n'
        'fn handle(&self) {\n'
        '    let peer = ethereum::filters::peer_of(ext);\n'
        '    let error = ethereum::filter_error("eth_newFilter", reason);\n'
        '}\n',
    )
    write(root, "src/lib.rs", "pub mod rpc;\npub mod clean;\n")
    write(root, "src/rpc/mod.rs", "pub mod api;\n")
    write(root, "src/clean.rs", "// A clean source file.\n")
    write(root, "src/tests/mod.rs", "mod example;\n")
    write(root, "src/tests/example.rs", "#[test]\nfn it_works() { assert_eq!(2, 1 + 1); }\n")
    write(
        root,
        "xtask/gates/src/main.rs",
        "mod gates {\n    pub mod example_gate;\n}\n"
        'const GATES: &[Gate] = &[Gate { name: "example-gate", '
        "run: gates::example_gate::run }];\n",
    )
    write(root, "xtask/gates/src/gates/example_gate.rs", "pub fn run() {}\n")
    write(root, "xtask/gates/tests/repository_locks.rs", "// gate tests\n")
    write(
        root,
        ".github/workflows/ci.yml",
        "jobs:\n  integration-audit:\n"
        "    steps:\n"
        "      - run: python3 ops/scripts/integration_audit.py --self-test\n"
        "      - run: python3 ops/scripts/integration_audit.py --root .\n",
    )
    write(root, ".github/no-legacy-storage-baseline.txt", "# empty\n")
    write(root, "docs/STORAGE.md", "# Storage\nThe target model.\n")
    write(
        root,
        "docs/work/PACKAGES.md",
        "# Package registry\n"
        + "".join(f"| WP-{n:02d} | open |\n" for n in range(1, 65)),
    )
    write(root, ".gitignore", "THE_BUDLUM_DIREKTIF.md\n")


def self_test() -> list[str]:
    """One injected violation per check. A check that cannot fail is a bug."""
    mutations = {
        check_rpc_method_table: (
            "src/rpc/method_class.rs",
            '    row("bud_chainId", Public, Read),\n',
            "",
        ),
        check_gateway_tables: (
            "src/rpc/compat/ethereum/mod.rs",
            'name: "eth_chainId", answer: Answer::ChainRead',
            'name: "eth_chainId", answer: Answer::Pending { package: "WP-28" }',
        ),
        check_gate_modules: (
            "xtask/gates/src/gates",
            None,
            None,
        ),
        check_test_modules: ("src/tests", None, None),
        check_module_declarations: (
            "src/lib.rs",
            "pub mod clean;\n",
            "pub mod clean;\npub mod missing_module;\n",
        ),
        check_vacuous_tests: (
            "src/tests/example.rs",
            "fn it_works()",
            "fn it_works() { assert!(true); }\nfn dummy(",
        ),
        check_package_registry: (
            "docs/work/PACKAGES.md",
            "| WP-64 | open |\n",
            "",
        ),
        check_binding_directive: (
            "THE_BUDLUM_DIREKTIF.md",
            None,
            "# binding directive\n",
        ),
        check_root_python_is_english: (
            "helper_tr.py",
            None,
            "# This line carries a Turkish character: \u00e7\n",
        ),
        check_ci_wiring: (
            ".github/workflows/ci.yml",
            "      - run: python3 ops/scripts/integration_audit.py --self-test\n",
            "",
        ),
        check_filter_pool_wiring: (
            "src/rpc/compat/ethereum/mod.rs",
            "pub mod filters;\n",
            "",
        ),
        check_legacy_ratchet: (
            "src/legacy_probe.rs",
            None,
            "// uses ContentManifest today\n",
        ),
    }
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="budlum-integration-audit-") as tmp:
        root = Path(tmp)
        fixture(root)
        clean = findings(root)
        if clean:
            problems.append(f"the clean fixture failed: {clean}")
        for check, (target, old, new) in mutations.items():
            fixture(root)
            if target == "xtask/gates/src/gates":
                write(root, "xtask/gates/src/gates/unregistered.rs", "pub fn run() {}\n")
            elif target == "src/tests":
                write(root, "src/tests/unregistered.rs", "// a test\n")
            elif old is None:
                write(root, target, new or "")
            else:
                body = read(root, target)
                if old not in body:
                    problems.append(f"{check.__name__}: fixture mutation did not apply")
                    continue
                write(root, target, body.replace(old, new, 1))
            reported = check(root)
            if not reported:
                problems.append(f"{check.__name__}: an injected violation passed")
    return problems


def branch_report(base: str = "main", remote: str = "origin") -> int:
    """Which remote arena branches are already ancestors of HEAD."""
    out = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname:short)", f"refs/remotes/{remote}"],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        print(out.stderr.strip(), file=sys.stderr)
        return 1
    names = sorted(
        name
        for name in out.stdout.split()
        if name.startswith(f"{remote}/arena/")
    )
    print(f"arena branches on {remote}: {len(names)}")
    integrated: list[str] = []
    outstanding: list[str] = []
    for name in names:
        done = subprocess.run(
            ["git", "merge-base", "--is-ancestor", name, "HEAD"],
            capture_output=True,
        )
        (integrated if done.returncode == 0 else outstanding).append(name)
    print(f"ancestors of HEAD (integrated here): {len(integrated)}")
    for name in integrated:
        print(f"     integrated  {name}")
    print(f"not ancestors of HEAD (still open): {len(outstanding)}")
    for name in outstanding:
        print(f"     open        {name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--branches", action="store_true")
    args = parser.parse_args()
    if args.branches:
        return branch_report()
    if args.self_test:
        problems = self_test()
        if problems:
            for problem in problems:
                print(f"FAIL: {problem}", file=sys.stderr)
            return 1
        print(f"integration audit canary OK: {len(CHECKS)} checks each rejected a real violation")
        return 0
    root = Path(args.root).resolve()
    found = findings(root)
    if found:
        for problem in found:
            print(f"FAIL: {problem}")
        print(f"integration audit: {len(found)} finding(s)")
        return 1
    print(f"integration audit OK: {len(CHECKS)} checks pass on {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
