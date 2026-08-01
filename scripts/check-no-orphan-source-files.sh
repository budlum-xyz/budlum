#!/usr/bin/env bash
# ============================================================================
# check-no-orphan-source-files.sh, a .rs file no `mod` declares is not code.
#
# src/network/proto_bridge.rs sat in the tree carrying:
#
#   use crate::consensus::pos::SlashingEvidence;
#   use crate::network::protocol::NetworkMessage;
#   use crate::{Block, BlockHeader, Transaction};
#
#   #[allow(clippy::all)]
#   pub mod pb {
#       include!(concat!(env!("OUT_DIR"), "/budlum.network.rs"));
#   }
#
# Nothing declared it. `mod proto_bridge;` appears in no file, so rustc never
# read it: not compiled, not linted, not covered, not counted. Its `pb` module
# was byte-identical to the one in proto_conversions.rs, which is the copy the
# tree actually uses.
#
# Why this matters beyond tidiness. An orphan file reads exactly like live
# code to a human: it has imports, it appears in grep results, it shows up in
# a review diff. Someone auditing the protobuf bridge could have read it,
# concluded something about the wire format, and been reasoning about a file
# the compiler had never seen. Worse, edits to it are silent -- a security fix
# applied to the wrong copy compiles fine and changes nothing.
#
# `cargo` itself will not complain: an unreferenced file is simply not part of
# the crate. Neither will clippy, nor dead-code analysis, nor coverage, since
# all of them work from what the compiler was given.
#
# Files under src/bin/ are exempt: Cargo auto-discovers them as binary targets
# without any `mod` declaration, which is the documented layout, not an
# accident.
#
# Usage:
#   bash scripts/check-no-orphan-source-files.sh              # gate
#   bash scripts/check-no-orphan-source-files.sh --self-test  # canary
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Roots to check. Each is a crate source tree where every .rs file should be
# reachable from a module declaration.
SCAN_ROOTS=(src budzero wallet-core)

scan() {
  local root="$1"
  [ -d "$root/src" ] || fail "no src directory at $root/src - wrong root?"

  python3 - "$root" "${SCAN_ROOTS[*]}" <<'PY'
import os, re, sys

root = sys.argv[1]
scan_roots = sys.argv[2].split()

# Cargo discovers these without a `mod` declaration.
def exempt(rel):
    parts = rel.replace(os.sep, '/').split('/')
    if os.path.basename(rel) in ('lib.rs', 'main.rs', 'mod.rs', 'build.rs'):
        return True
    # Cargo auto-discovers targets in these directories without any `mod`:
    #   <crate>/src/bin/*.rs   binaries
    #   <crate>/tests/*.rs     integration tests
    #   <crate>/benches/*.rs   benchmarks
    #   <crate>/examples/*.rs  examples
    # The first form sits under src/; the other three are siblings of it. An
    # earlier version of this rule only matched the src/ case and flagged four
    # perfectly ordinary budzero integration tests.
    for i, p in enumerate(parts[:-1]):
        if p == 'bin' and i > 0 and parts[i - 1] == 'src':
            return True
        if p in ('tests', 'benches', 'examples'):
            return True
    return False

MOD_DECL = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;', re.M)
# `#[path = "..."] mod x;` points a module at an arbitrary file.
PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')

declared = set()
path_targets = set()
files = []

for sub in scan_roots:
    base = os.path.join(root, sub)
    if not os.path.isdir(base):
        continue
    for dirpath, dirs, names in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ('target', '.git')]
        for name in names:
            if not name.endswith('.rs'):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            files.append((full, rel))
            text = open(full, encoding='utf-8', errors='replace').read()
            declared.update(MOD_DECL.findall(text))
            for target in PATH_ATTR.findall(text):
                path_targets.add(os.path.basename(target).removesuffix('.rs'))

if not files:
    print("FAIL: no .rs files found - wrong root, the gate would be vacuous", file=sys.stderr)
    sys.exit(1)

orphans = []
for full, rel in files:
    if exempt(rel):
        continue
    stem = os.path.basename(rel)[:-3]
    if stem not in declared and stem not in path_targets:
        lines = sum(1 for _ in open(full, encoding='utf-8', errors='replace'))
        orphans.append(f"{rel}  ({lines} lines)")

if orphans:
    print("FAIL: these .rs files are declared by no `mod` and are not compiled:", file=sys.stderr)
    for o in sorted(orphans):
        print(f"  - {o}", file=sys.stderr)
    print(
        "\nrustc never reads them, so they are not linted, not covered and not tested,\n"
        "while reading exactly like live code in grep and in review. Declare the module\n"
        "or delete the file.",
        file=sys.stderr)
    sys.exit(1)

print(f"Orphan-file gate OK: all {len(files)} .rs files are reachable from a module declaration.")
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  # 1. The case that shipped: a file nothing declares.
  rm -rf "$tmp/orphan"; mkdir -p "$tmp/orphan/src"
  printf 'pub mod real;\n' > "$tmp/orphan/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/orphan/src/real.rs"
  printf 'pub fn ghost() {}\n' > "$tmp/orphan/src/proto_bridge.rs"
  if ( scan "$tmp/orphan" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a file no mod declares was accepted!" >&2
    exit 1
  fi

  # 2. A tree where everything is declared must pass.
  rm -rf "$tmp/good"; mkdir -p "$tmp/good/src"
  printf 'pub mod real;\n' > "$tmp/good/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/good/src/real.rs"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a fully declared tree was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    exit 1
  fi

  # 3. src/bin/*.rs is auto-discovered by Cargo and must not be flagged.
  rm -rf "$tmp/bin"; mkdir -p "$tmp/bin/src/bin"
  printf 'pub mod real;\n' > "$tmp/bin/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/bin/src/real.rs"
  printf 'fn main() {}\n' > "$tmp/bin/src/bin/tool.rs"
  if ! ( scan "$tmp/bin" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: src/bin/*.rs was flagged as an orphan!" >&2
    exit 1
  fi

  # 4. A nested module declared from its parent must pass.
  rm -rf "$tmp/nested"; mkdir -p "$tmp/nested/src/deep"
  printf 'pub mod deep;\n' > "$tmp/nested/src/lib.rs"
  printf 'pub mod inner;\n' > "$tmp/nested/src/deep/mod.rs"
  printf 'pub fn a() {}\n' > "$tmp/nested/src/deep/inner.rs"
  if ! ( scan "$tmp/nested" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a nested declared module was flagged!" >&2
    exit 1
  fi

  # 5. `#[path = "..."]` reaches a file that no plain `mod name;` names.
  rm -rf "$tmp/pathattr"; mkdir -p "$tmp/pathattr/src"
  printf '#[path = "renamed.rs"]\npub mod alias;\n' > "$tmp/pathattr/src/lib.rs"
  printf 'pub fn a() {}\n' > "$tmp/pathattr/src/renamed.rs"
  if ! ( scan "$tmp/pathattr" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a #[path]-attached file was flagged as an orphan!" >&2
    exit 1
  fi

  # 6. A missing src must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no src was accepted!" >&2
    exit 1
  fi

  echo "orphan-file gate self-test OK: an undeclared file and a missing src are rejected; declared modules, nested modules, #[path] aliases and src/bin targets all pass."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
