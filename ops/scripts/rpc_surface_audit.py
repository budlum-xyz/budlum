#!/usr/bin/env python3
"""Compatibility audit of the JSON-RPC method surface.

Three files must say the same thing before the node starts:

* `src/rpc/api.rs` declares the wire names of every RPC method;
* `src/rpc/method_class.rs` classifies every served method by listener and
  effect, and `check_served_methods` refuses to start on a mismatch;
* each `src/rpc/compat/*/mod.rs` holds a second table of its own namespace's
  methods and what each one answers.

Open PRs add rows to all three independently. A clean `git merge` therefore
does not guarantee that the tables still agree, and a disagreement is a
runtime refusal at server start, not a compile error. This tool reads the
three tables from the live tree and reports every disagreement. It also
checks that every `pub mod x;` in `src/rpc/compat/mod.rs` and `src/rpc/mod.rs`
names a real file, and that Aptos REST route patterns are unique.

Usage:
    python3 ops/scripts/rpc_surface_audit.py \
        --out-json docs/audit/RPC_SURFACE_DATA_2026-11-06.json

Exit status is 1 when a disagreement is found, 0 otherwise.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
API = ROOT / "src/rpc/api.rs"
CLASSES = ROOT / "src/rpc/method_class.rs"
COMPAT_MOD = ROOT / "src/rpc/compat/mod.rs"
RPC_MOD = ROOT / "src/rpc/mod.rs"

METHOD_RE = re.compile(r'#\[method\(name\s*=\s*"([^"]+)"')
SUB_RE = re.compile(
    r'#\[subscription\(name\s*=\s*"([^"]+)"\s*=>\s*"([^"]+)"'
    r'(?:,\s*unsubscribe\s*=\s*"([^"]+)")?'
)
CLASS_ROW_RE = re.compile(r'\brow\(\s*"([^"]+)"', re.S)
COMPAT_ROW_RE = re.compile(r'MethodRow\s*\{[^}]*?name:\s*"([^"]+)"', re.S)
ENDPOINT_RE = re.compile(r'\b(?:read|refused)\(\s*Verb::\w+,\s*"([^"]+)"', re.S)
MOD_RE = re.compile(r"^\s*pub mod (\w+);", re.M)


def declared_methods(text: str) -> set[str]:
    out = {m.group(1) for m in METHOD_RE.finditer(text)}
    for m in SUB_RE.finditer(text):
        out.add(m.group(1))
        if m.group(3):
            out.add(m.group(3))
    return out


def class_rows(text: str) -> set[str]:
    return {m.group(1) for m in CLASS_ROW_RE.finditer(text)}


def compat_tables() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """JSON-RPC method names and REST route patterns, kept separate.

    A REST path is not a JSON-RPC method: requiring it in api.rs would be a
    false finding (the first version of this tool reported 18 of them).
    """
    rpc: dict[str, set[str]] = {}
    rest: dict[str, set[str]] = {}
    for mod in sorted((ROOT / "src/rpc/compat").glob("*/mod.rs")):
        text = mod.read_text()
        rpc[mod.parent.name] = {m.group(1) for m in COMPAT_ROW_RE.finditer(text)}
        rest[mod.parent.name] = {m.group(1) for m in ENDPOINT_RE.finditer(text)}
    return rpc, rest


def missing_module_files() -> list[str]:
    problems = []
    for mod_file, directory in (
        (RPC_MOD, ROOT / "src/rpc"),
        (COMPAT_MOD, ROOT / "src/rpc/compat"),
    ):
        text = mod_file.read_text()
        for name in MOD_RE.findall(text):
            as_file = directory / f"{name}.rs"
            as_dir = directory / name / "mod.rs"
            if not as_file.is_file() and not as_dir.is_file():
                problems.append(f"{mod_file.relative_to(ROOT)}: pub mod {name}; has no source")
    return problems


def config_drift() -> list[str]:
    """Chain ids, framework pins and scheme tables must not drift between
    the REST gateway, the coordinator envelope, the supply-chain policy and
    the golden vector.
    """
    problems = []
    expected_chain = "205"
    expected_commit = "81d89f428fe8e4b69d53b4916993e9a930afc37c"
    chain_files = [
        ROOT / "src/rpc/compat/aptos/mod.rs",
        ROOT / "src/execution/coordinator/foreign/aptos.rs",
    ]
    for path in chain_files:
        if not path.is_file():
            problems.append(f"{path.relative_to(ROOT)} is missing")
            continue
        text = path.read_text()
        if "APTOS_CHAIN_ID" not in text or expected_chain not in text:
            problems.append(f"{path.relative_to(ROOT)}: APTOS_CHAIN_ID is not {expected_chain}")
        if "0xBD" not in text and "MOVE_ALIAS_SCHEME_BYTE" not in text:
            problems.append(f"{path.relative_to(ROOT)}: the 0xBD alias byte is not named")
    for rel in [
        "src/execution/coordinator/foreign/aptos.rs",
        "execution/move/deny.toml",
        "tests/vectors/aptos/pinned_scheme_ids.json",
    ]:
        path = ROOT / rel
        if not path.is_file():
            problems.append(f"{rel} is missing")
        elif expected_commit not in path.read_text():
            problems.append(f"{rel} does not pin {expected_commit}")
    vector = ROOT / "tests/vectors/aptos/pinned_scheme_ids.json"
    if vector.is_file():
        data = json.loads(vector.read_text())
        if 0xBD in data.get("scheme_ids", []):
            problems.append("the pinned Scheme table uses the reserved 0xBD byte")
        if data.get("reserved_byte_is_used") is not False:
            problems.append("the golden vector does not record 0xBD as unused")
    return problems


def duplicate_endpoint_patterns() -> list[str]:
    problems = []
    aptos = ROOT / "src/rpc/compat/aptos/mod.rs"
    if not aptos.is_file():
        return problems
    patterns = ENDPOINT_RE.findall(aptos.read_text())
    seen: set[str] = set()
    for pattern in patterns:
        if pattern in seen:
            problems.append(f"duplicate Aptos REST route pattern: {pattern}")
        seen.add(pattern)
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-json", required=True)
    args = ap.parse_args()

    api = declared_methods(API.read_text())
    classes = class_rows(CLASSES.read_text())
    compat, rest = compat_tables()
    modules = missing_module_files()
    endpoints = duplicate_endpoint_patterns()
    drift = config_drift()

    declared_not_classified = sorted(api - classes)
    classified_not_declared = sorted(classes - api)
    compat_missing: dict[str, list[str]] = {}
    for namespace, names in compat.items():
        missing = sorted(n for n in names if n not in api or n not in classes)
        if missing:
            compat_missing[namespace] = missing

    # Directive 8.11.3 and 8.11.4 name these. A carried PR that silently
    # drops one is a compatibility defect, not a style choice.
    compat_expected = {
        "solana": {
            "getHealth", "getVersion", "getSlot", "getBlockHeight",
            "getGenesisHash", "getEpochInfo", "slotSubscribe", "slotUnsubscribe",
        },
        "aptos": {
            "/v1", "/v1/-/healthy", "/v1/accounts/{addr}",
            "/v1/accounts/{addr}/resources", "/v1/accounts/{addr}/resource/{type}",
            "/v1/accounts/{addr}/modules", "/v1/accounts/{addr}/module/{name}",
            "/v1/accounts/{addr}/transactions", "/v1/transactions",
            "/v1/transactions/simulate", "/v1/transactions/by_hash/{h}",
            "/v1/transactions/wait_by_hash/{h}", "/v1/transactions/by_version/{v}",
            "/v1/view", "/v1/estimate_gas_price", "/v1/blocks/by_height/{h}",
            "/v1/tables/{handle}/item", "/v1/accounts/{addr}/events/{creation_number}",
        },
    }
    rest_expected = compat_expected.pop("aptos")
    missing_named = {
        namespace: sorted(expected - compat.get(namespace, set()))
        for namespace, expected in compat_expected.items()
        if expected - compat.get(namespace, set())
    }
    missing_named["aptos (REST routes)"] = sorted(
        rest_expected - rest.get("aptos", set())
    )
    missing_named = {k: v for k, v in missing_named.items() if v}

    problems = (
        [f"declared without a class row: {n}" for n in declared_not_classified]
        + [f"class row without a declaration: {n}" for n in classified_not_declared]
        + [f"{ns}: compat method out of sync: {n}" for ns, ns2 in compat_missing.items() for n in ns2]
        + modules
        + endpoints
        + drift
    )

    data = {
        "api_methods": len(api),
        "class_rows": len(classes),
        "compat_namespaces": {k: len(v) for k, v in compat.items()},
        "rest_route_namespaces": {k: len(v) for k, v in rest.items()},
        "declared_not_classified": declared_not_classified,
        "classified_not_declared": classified_not_declared,
        "compat_missing": compat_missing,
        "missing_named_methods": missing_named,
        "missing_module_files": modules,
        "duplicate_endpoint_patterns": endpoints,
        "config_drift": drift,
        "problems": problems,
    }
    out = ROOT / args.out_json
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(
        f"api={len(api)} classes={len(classes)} "
        f"compat={ {k: len(v) for k, v in compat.items()} } "
        f"problems={len(problems)}"
    )
    for problem in problems[:40]:
        print("  " + problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
