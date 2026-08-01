#!/usr/bin/env bash
# ============================================================================
# check-consensus-maps-are-ordered.sh - every map folded into a hash must
# iterate in a defined order.
#
# A `root()` / `leaf_hash()` / `calculate_state_root()` walks a collection and
# feeds each entry into a digest. If that collection is a `HashMap` or
# `HashSet`, the iteration order is whatever the hasher's random seed decides
# for that process - so two honest nodes with identical state hash the same
# entries in different sequences and produce different roots.
#
# This is the single most-cited source of consensus divergence in the
# ecosystem: Thorchain halted on a Go map iteration, Cosmos SDK documents it
# as a standing hazard, and Tendermint's application guide lists
# "nondeterministic serialisation" first among the things that break replicated
# state machines. Rust has exactly the same exposure - `std::collections::HashMap`
# uses `RandomState`, reseeded per process.
#
# `determinism.yml` already runs the suite on three operating systems and
# compares digests. That catches a divergence that shows up *between the
# platforms the matrix happens to run*. It does not catch one that depends on
# a per-process random seed, because both runs are equally likely to agree by
# chance on a small map. This gate reads the source instead: if a hashing
# function iterates a collection, the collection's declared type must be
# ordered.
#
# The check is deliberately structural rather than exhaustive: it finds the
# `for x in self.FIELD.values()/.keys()/.iter()` shape inside a hashing
# function, resolves FIELD to its struct declaration, and fails when the
# declared type is `HashMap` or `HashSet`.
#
# Usage:
#   bash scripts/check-consensus-maps-are-ordered.sh              # gate
#   bash scripts/check-consensus-maps-are-ordered.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-.}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os, re, sys

root = sys.argv[1]

# Functions whose output is, or feeds, a consensus commitment.
HASHING = re.compile(
    r'\s*(?:pub(?:\([a-z()]+\))? )?fn '
    r'(root|calculate_state_root|leaf_hash|compute_hash|state_root|digest)\b'
)
# `for <binding> in self.<field>.values()` and friends.
ITER = re.compile(r'for\s+[^\s]+\s+in\s+(?:&)?self\.([a-z_][a-z0-9_]*)\.(?:values|keys|iter)\(\)')

findings = []
scanned = 0

for dirpath, _, filenames in os.walk(root):
    if any(part in dirpath for part in ('/target', '/.git')):
        continue
    for filename in filenames:
        if not filename.endswith('.rs'):
            continue
        path = os.path.join(dirpath, filename)
        try:
            lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
        except OSError:
            continue

        # field -> declared collection type, across the whole file
        declared = {}
        for line in lines:
            m = re.match(
                r'\s*(?:pub(?:\([a-z()]+\))? )?([a-z_][a-z0-9_]*)\s*:\s*'
                r'(BTreeMap|BTreeSet|HashMap|HashSet|Vec)\s*<',
                line,
            )
            if m:
                declared.setdefault(m.group(1), m.group(2))

        inside = False
        depth = 0
        fname = None
        start = 0
        for i, line in enumerate(lines):
            m = HASHING.match(line)
            if m and not inside:
                inside, depth, fname, start = True, 0, m.group(1), i
            if not inside:
                continue
            scanned += line.count('{')
            depth += line.count('{') - line.count('}')
            it = ITER.search(line)
            if it:
                field = it.group(1)
                kind = declared.get(field)
                if kind in ('HashMap', 'HashSet'):
                    findings.append((path, i + 1, fname, field, kind))
            if depth <= 0 and i > start:
                inside, fname = False, None

if not findings:
    print("Consensus-map ordering OK: every collection hashed into a commitment is ordered.")
    sys.exit(0)

print("FAIL: a hashing function iterates an unordered collection:", file=sys.stderr)
for path, line, fname, field, kind in findings:
    print(f"  {path}:{line}  fn {fname}() iterates self.{field}: {kind}<..>", file=sys.stderr)
print("", file=sys.stderr)
print("HashMap/HashSet iteration order comes from a per-process random seed, so", file=sys.stderr)
print("two honest nodes with identical state produce different digests. Use", file=sys.stderr)
print("BTreeMap/BTreeSet, or collect and sort before hashing.", file=sys.stderr)
sys.exit(1)
PY
}

self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap 'rm -rf "${SELF_TEST_TMP:-}"' EXIT
  local tmp="$SELF_TEST_TMP"
  mkdir -p "$tmp/src"

  # An ordered map inside a root() must pass.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    entries: BTreeMap<u64, u64>,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for entry in self.entries.values() {
            hasher.update(entry.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if ! (scan "$tmp" >/dev/null 2>&1); then
    echo "FAIL: self-test could not make an ordered tree pass" >&2
    exit 1
  fi

  # Swap the declaration to HashMap; the gate must notice.
  sed -i 's/BTreeMap<u64, u64>/HashMap<u64, u64>/' "$tmp/src/ok.rs"
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a HashMap hashed into a root was accepted!" >&2
    exit 1
  fi

  # The same HashMap outside a hashing function is fine - iteration order
  # only matters where it reaches a digest.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    entries: HashMap<u64, u64>,
}
impl Registry {
    pub fn total(&self) -> u64 {
        let mut sum = 0;
        for entry in self.entries.values() {
            sum += entry;
        }
        sum
    }
}
RS
  if ! (scan "$tmp" >/dev/null 2>&1); then
    echo "FAIL: gate flagged a HashMap that never reaches a digest" >&2
    exit 1
  fi

  echo "Consensus-map ordering self-test OK: a hashed HashMap is rejected, an ordered map and a non-hashing HashMap both pass."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "${1:-$ROOT}"
