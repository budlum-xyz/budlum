#!/usr/bin/env bash
# ============================================================================
# check-consensus-maps-are-ordered.sh, every map folded into a hash must
# iterate in a defined order.
#
# A `root()` / `leaf_hash()` / `calculate_state_root()` walks a collection and
# feeds each entry into a digest. If that collection is a `HashMap` or
# `HashSet`, the iteration order is whatever the hasher's random seed decides
# for that process, so two honest nodes with identical state hash the same
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
#
# The binding is matched with `.+?` rather than `[^\s]+` because the most
# common way to walk a map is `for (key, value) in ...`, and a no-space
# pattern cannot cross the space inside that tuple. With `[^\s]+` this gate
# saw `for e in self.x.iter()` and missed every `for (k, v) in self.x`, which
# is the shape almost every `root()` in this tree actually uses. A gate that
# matches nothing reports nothing.
#
# The bare `&self.field` form is included too: iterating a map directly is
# the same hazard as calling `.iter()` on it, and it is how most of these
# loops are written.
# Whitespace is allowed around every `.` because the joined window that
# recovers a wrapped `for` header leaves `self .entries .iter()`.
ITER = re.compile(
    r'for\s+.+?\s+in\s+(?:&)?self\s*\.\s*([a-z_][a-z0-9_]*)'
    r'(?:\s*\.\s*(?:values|keys|iter)\s*\(\))?\s*[{&]'
)

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
            # rustfmt splits a long `for` header across lines:
            #
            #     for (k, v) in self
            #         .entries
            #         .iter()
            #
            # Matching one line at a time sees `for (k, v) in self` and stops,
            # so the field name is never read and the loop is invisible. Join
            # the next two lines before searching.
            # Four lines, not three: rustfmt puts the opening brace of the
            # loop body on its own line after the receiver chain, and the
            # pattern needs that brace to know the header ended.
            #
            #     for (k, v) in self      <- i
            #         .entries            <- i+1
            #         .iter()             <- i+2
            #     {                       <- i+3
            window = ' '.join(
                l.strip() for l in lines[i:min(i + 4, len(lines))]
            )
            it = ITER.search(line) or ITER.search(window)
            if it:
                field = it.group(1)
                kind = declared.get(field)
                if kind in ('HashMap', 'HashSet'):
                    # Order matters only when the loop FOLDS into a shared
                    # accumulator. A loop that writes each entry to its own
                    # slot, `cached_leaves[pos] = ..` with `pos` from a sorted
                    # binary search, produces the same array whichever order it
                    # visits, because no two iterations touch the same cell.
                    #
                    # `calculate_state_root` does exactly that, and calling it
                    # a divergence would be an alarm that is not true. A gate
                    # that cries wolf teaches people to skip it, which costs
                    # more than the check is worth.
                    body = '\n'.join(lines[i:i + 40])
                    end = body.find('\n        }')
                    if end != -1:
                        body = body[:end]
                    folds = re.search(
                        r'\w+\s*\.\s*update\(|\w+\s*\.\s*push\(|'
                        r'\w+\s*[-+^|]=|\w+\s*=\s*\w+\s*[-+^|]',
                        body,
                    )
                    writes_own_slot = re.search(r'\w+\s*\[\s*\w+\s*\]\s*=', body)
                    if folds and not writes_own_slot:
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

  # The same HashMap outside a hashing function is fine, iteration order
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

  # Tuple destructuring is how almost every map in this tree is walked, and
  # the first version of this gate could not see it: the binding pattern was
  # matched with `[^\s]+`, which cannot cross the space in `(k, v)`. The gate
  # reported the tree clean because it was looking at nothing.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    entries: HashMap<u64, u64>,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in &self.entries {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a HashMap walked as (key, value) pairs was accepted!" >&2
    exit 1
  fi

  # And the same shape wrapped across lines by the formatter.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    entries: HashMap<u64, u64>,
}
impl Registry {
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (k, v) in self
            .entries
            .iter()
        {
            hasher.update(k.to_le_bytes());
            hasher.update(v.to_le_bytes());
        }
        hasher.finalize().into()
    }
}
RS
  if (scan "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a wrapped HashMap iterator was accepted!" >&2
    exit 1
  fi

  # A loop that writes each entry to its own slot is order-independent: no
  # two iterations touch the same cell, so the result is identical whichever
  # order the map yields. `calculate_state_root` does this, and calling it a
  # divergence would be an alarm that is not true.
  cat > "$tmp/src/ok.rs" <<'RS'
pub struct Registry {
    dirty: HashSet<u64>,
    leaves: Vec<[u8; 32]>,
}
impl Registry {
    pub fn calculate_state_root(&mut self) -> [u8; 32] {
        for key in &self.dirty {
            let pos = *key as usize;
            let mut h = Sha256::new();
            h.update(key.to_le_bytes());
            self.leaves[pos] = h.finalize().into();
        }
        self.leaves[0]
    }
}
RS
  if ! (scan "$tmp" >/dev/null 2>&1); then
    echo "FAIL: gate flagged a loop that writes each entry to its own slot" >&2
    exit 1
  fi

  echo "Consensus-map ordering self-test OK: a hashed HashMap, one walked as \
(key, value) pairs and one wrapped across lines are all rejected; an ordered \
map, a non-hashing HashMap and a write-to-own-slot loop all pass."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "${1:-$ROOT}"
