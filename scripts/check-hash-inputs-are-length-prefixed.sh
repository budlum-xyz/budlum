#!/usr/bin/env bash
# ============================================================================
# check-hash-inputs-are-length-prefixed.sh
#
# Two variable-length fields hashed back to back must carry their lengths.
#
# Why this gate exists.
#
# Four consensus digests hashed a validator's key set by appending the fields
# one after another with nothing between them:
#
#   hasher.update(&v.bls_public_key);   // Vec<u8>
#   hasher.update(&v.pop_signature);    // Vec<u8>
#   hasher.update(&v.pq_public_key);    // Vec<u8>
#
# Concatenation without lengths is not injective. A 96-byte BLS key followed
# by a 48-byte PoP produces exactly the bytes of a 144-byte BLS key followed
# by an empty PoP, so the two hash identically. Measured, not argued: the
# module doc in `src/crypto/key_set_preimage.rs` carries the demonstration.
#
# It was reachable. `Validator` is a `serde` struct with `#[serde(default)]`
# on all four key fields and it crosses the wire inside a snapshot, and
# neither `AccountState::from_snapshot` nor `from_snapshot_v2` re-derives the
# split; they copy the vectors verbatim. A snapshot carrying the PoP folded
# into the BLS key reproduces the honest state root, passes `verify()`, passes
# the state-root comparison in `apply_v2_snapshot`, and installs a validator
# with no PoP. `is_consensus_ready` then drops it from the active set, so the
# restoring node computes a different `set_hash` from its peers while both
# agree on the state root. A partition with no error naming its cause.
#
# The four sites were written at different times and none of them carried the
# reasoning, which is exactly how a tree accumulates four copies of one bug.
#
# What the gate checks.
#
# In production code, when a hasher update takes a field whose declared type
# is variable-length (`Vec<u8>`, `String`, `BoundedBytes`) and the immediately
# following update takes another variable-length value, the pair must be
# length-prefixed: a `len()` must appear on that line or the line above, or
# the field's declaration must carry `HASHLEN: exempt - <reason>`.
#
# A single variable-length field at the end of a preimage, followed by nothing
# or by a fixed-width value, is not flagged: there is nothing for it to trade
# bytes with. The failure needs two adjacent ambiguous boundaries.
#
# Known limits, stated so a pass is not read for more than it carries.
# The type is resolved by field name across the tree, so a name used by two
# structs with different types is treated as variable-length if either is.
# That errs toward flagging, which is the safe direction for a gate about
# consensus preimages. The gate also cannot see through a helper that takes
# the bytes as an argument; it measures the call sites it can read.
#
# Usage:
#   bash scripts/check-hash-inputs-are-length-prefixed.sh              # gate
#   bash scripts/check-hash-inputs-are-length-prefixed.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]

SCAN_ROOTS = ("src", "budzero", "wallet-core")
VARIABLE = {"Vec<u8>", "String", "BoundedBytes", "Vec<String>"}
MARKER = re.compile(r"HASHLEN:\s*exempt\b(.*)")


def balanced(src, open_at):
    depth, j = 0, open_at
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at:j + 1]
        j += 1
    return src[open_at:]


def strip_test_mods(src):
    out, i = [], 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{", src[i:])
        if not m:
            out.append(src[i:])
            return "".join(out)
        start, brace = i + m.start(), i + m.end() - 1
        out.append(src[i:start])
        depth, j = 0, brace
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        i = j + 1


def is_test_path(path):
    return (
        f"{os.sep}tests{os.sep}" in path
        or path.endswith("_tests.rs")
        or path.endswith(f"{os.sep}tests.rs")
    )


files = []
for scan_root in SCAN_ROOTS:
    base = os.path.join(root, scan_root)
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "node_modules")]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if name.endswith(".rs") and not is_test_path(path):
                files.append(path)

if not files:
    print(f"FAIL: no production .rs files found under {root}", file=sys.stderr)
    sys.exit(2)

sources = {}
for path in files:
    try:
        sources[path] = strip_test_mods(open(path, encoding="utf-8", errors="ignore").read())
    except OSError as exc:
        print(f"FAIL: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)

# Field name -> is any declaration of it variable-length, plus its doc comment.
variable_fields = {}
field_docs = {}
for path, src in sources.items():
    for m in re.finditer(r"pub struct (\w+)\s*\{", src):
        body = balanced(src, m.end() - 1)
        doc = []
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("//"):
                doc.append(stripped)
                continue
            fm = re.match(r"pub\s+(\w+)\s*:\s*([^,]+),?\s*$", stripped)
            if fm:
                name, ty = fm.group(1), fm.group(2).strip()
                if ty in VARIABLE:
                    variable_fields[name] = True
                    field_docs.setdefault(name, []).append("\n".join(doc))
                doc = []
                continue
            if stripped.startswith("#["):
                continue
            if stripped:
                doc = []

if not variable_fields:
    print(
        "FAIL: gate found no variable-length struct field to reason about - wrong root?",
        file=sys.stderr,
    )
    sys.exit(2)

UPDATE = re.compile(r"\.update\(\s*&?([A-Za-z_][\w.]*)")

# Method calls that convert a field to bytes rather than naming a new field.
# `self.block_hash.as_bytes()` ends in `as_bytes`, and taking the last path
# segment as the field name resolves it to a method, which no struct declares,
# so the pair was silently skipped. That is exactly how a name-based gate goes
# quiet: it does not report a miss, it reports nothing.
ACCESSORS = ("as_bytes", "as_slice", "as_str", "as_ref", "to_vec", "0")


def field_of(expr):
    """The struct field an update expression names, past any accessor call."""
    parts = expr.split(".")
    while len(parts) > 1 and parts[-1] in ACCESSORS:
        parts.pop()
    return parts[-1]

problems = []
checked_inputs = 0
adjacent_pairs = 0

for path, src in sources.items():
    lines = src.splitlines()
    # Index of every hasher update line, with the field it names.
    updates = []
    for i, line in enumerate(lines):
        # A doc comment illustrating the bug is not the bug. This file's own
        # module doc quotes the raw concatenation it exists to replace, and a
        # gate that reads its own explanation as a finding is a gate nobody
        # can write documentation against.
        if line.lstrip().startswith("//"):
            continue
        m = UPDATE.search(line)
        if not m:
            # rustfmt wraps a long call, and the argument then sits on the
            # next line:
            #
            #     hasher.update(
            #         entry.validator_address.as_bytes(),
            #     );
            #
            # Matching only within one line misses those, and a name-based
            # gate that misses does not report a miss: it reports nothing.
            # The sibling gate shipped with exactly this hole and passed the
            # function it was written for. Join the continuation before
            # giving up.
            if line.rstrip().endswith(".update("):
                joined = line.rstrip() + lines[i + 1].strip() if i + 1 < len(lines) else line
                m = UPDATE.search(joined)
                if m:
                    expr = m.group(1)
                    updates.append((i, joined, field_of(expr), expr))
            continue
        expr = m.group(1)
        updates.append((i, line, field_of(expr), expr))

    for _, _, field, _ in updates:
        if field in variable_fields:
            checked_inputs += 1

    for k in range(len(updates) - 1):
        i, line, field, expr = updates[k]
        j, next_line, next_field, _ = updates[k + 1]
        # Only adjacent updates: a gap means other bytes sit between them.
        #
        # Measured in *update calls*, not raw line distance. A wrapped call
        # spans three lines on its own, so a fixed line budget silently stops
        # treating two neighbouring updates as neighbours the moment rustfmt
        # breaks one of them. The lines between two consecutive updates are
        # checked for another hasher feed instead: if there is none, they are
        # adjacent however many lines the formatter used.
        between = "\n".join(lines[i + 1:j])
        if ".update(" in between:
            continue
        # Two updates are only neighbours if they feed the SAME hasher. The
        # state root builds a per-validator digest in `h` and folds the
        # results into `combined`; the last feed of one and the first feed of
        # the next are textually adjacent and hash into different accumulators,
        # so bytes cannot move between them. Comparing receivers keeps the
        # gate from inventing a collision across that boundary.
        def receiver_of(text):
            rm = re.search(r"([A-Za-z_][\w.]*)\s*\.update\(", text)
            return rm.group(1) if rm else None

        if receiver_of(line) != receiver_of(next_line):
            continue
        if field not in variable_fields or next_field not in variable_fields:
            continue
        adjacent_pairs += 1
        window = "\n".join(lines[max(0, i - 1):i + 1])
        if "len()" in window:
            continue
        exempt = None
        for doc in field_docs.get(field, []):
            found = MARKER.search(doc)
            if found:
                exempt = found
                break
        if exempt:
            continue
        rel = os.path.relpath(path, root)
        problems.append(
            f"{rel}:{i + 1}: `{expr}` is variable-length and the next hashed value "
            f"(`{next_field}`) is too, with no length between them. Concatenation "
            "without lengths is not injective: bytes can be moved from one field to "
            "the next and the digest will not change. Write the length first (see "
            "`crate::crypto::key_set_preimage`), or mark the field "
            "`HASHLEN: exempt - <reason>` in its declaration."
        )

# The measurement is the set of variable-length values reaching a hasher, not
# the subset that happens to be adjacent. Counting only adjacent pairs would
# make the gate report "nothing to measure" precisely when the tree is clean,
# which is the one moment a gate must not go quiet.
if not checked_inputs:
    print(
        "FAIL: gate found no variable-length hash input to measure - wrong "
        "root, or the update pattern changed shape.",
        file=sys.stderr,
    )
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"hash-input length gate OK: {checked_inputs} variable-length hash inputs "
    f"read, {adjacent_pairs} of them adjacent to another, each length-prefixed "
    "or declaring why it does not need to be"
)
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  expect_finding() {
    local dir="$1" what="$2" rc=0
    ( scan "$dir" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
      echo "GATE IS VACUOUS: $what passed!" >&2
      return 1
    fi
    if [ "$rc" -ne 1 ]; then
      echo "GATE IS BROKEN: $what exited $rc, which is not a finding." >&2
      echo "Exit 2 means the gate measured nothing; that is not a pass." >&2
      return 1
    fi
  }

  expect_pass() {
    local dir="$1" what="$2"
    if ! ( scan "$dir" ) >/dev/null 2>&1; then
      echo "GATE IS WRONG: $what was rejected!" >&2
      return 1
    fi
  }

  expect_broken() {
    local dir="$1" what="$2" rc=0
    ( scan "$dir" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
      echo "GATE MISREPORTS: $what exited $rc, expected 2 (measured nothing)." >&2
      return 1
    fi
  }

  mk() {
    local dir="$1" body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/src"
    printf '%s\n' "$body" >"$dir/src/lib.rs"
  }

  # 1. The bug this gate exists for, in the shape it had.
  mk "$tmp/raw" 'pub struct Validator {
    pub bls_public_key: Vec<u8>,
    pub pop_signature: Vec<u8>,
}
pub fn digest(v: &Validator, hasher: &mut Sha3_256) {
    hasher.update(&v.bls_public_key);
    hasher.update(&v.pop_signature);
}'
  expect_finding "$tmp/raw" "two variable-length fields hashed back to back" || return 1

  # 2. Length-prefixed: the fix, must pass.
  mk "$tmp/prefixed" 'pub struct Validator {
    pub bls_public_key: Vec<u8>,
    pub pop_signature: Vec<u8>,
}
pub fn digest(v: &Validator, hasher: &mut Sha3_256) {
    hasher.update((v.bls_public_key.len() as u64).to_le_bytes());
    hasher.update(&v.bls_public_key);
    hasher.update((v.pop_signature.len() as u64).to_le_bytes());
    hasher.update(&v.pop_signature);
}'
  expect_pass "$tmp/prefixed" "a length-prefixed pair" || return 1

  # 3. Declared exemption with a reason.
  mk "$tmp/exempt" 'pub struct Validator {
    /// HASHLEN: exempt - fixed 96 bytes, refused at every ingress.
    pub bls_public_key: Vec<u8>,
    pub pop_signature: Vec<u8>,
}
pub fn digest(v: &Validator, hasher: &mut Sha3_256) {
    hasher.update(&v.bls_public_key);
    hasher.update(&v.pop_signature);
}'
  expect_pass "$tmp/exempt" "a declared exemption with a reason" || return 1

  # 4. A variable-length field followed by a fixed-width one has nothing to
  #    trade bytes with, and must not be flagged, or the gate cries wolf on
  #    every preimage in the tree.
  mk "$tmp/single" 'pub struct Deal {
    pub note: String,
    pub amount: u64,
}
pub fn digest(d: &Deal, hasher: &mut Sha3_256) {
    hasher.update(&d.note);
    hasher.update(d.amount.to_le_bytes());
}
pub struct Pair {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}
pub fn other(p: &Pair, hasher: &mut Sha3_256) {
    hasher.update((p.a.len() as u64).to_le_bytes());
    hasher.update(&p.a);
    hasher.update((p.b.len() as u64).to_le_bytes());
    hasher.update(&p.b);
}'
  expect_pass "$tmp/single" "a variable-length field followed by a fixed one" || return 1

  # 5. Three in a row: the middle pair must be caught too, not just the first.
  mk "$tmp/three" 'pub struct Keys {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
}
pub fn digest(k: &Keys, hasher: &mut Sha3_256) {
    hasher.update((k.a.len() as u64).to_le_bytes());
    hasher.update(&k.a);
    hasher.update(&k.b);
    hasher.update(&k.c);
}'
  expect_finding "$tmp/three" "an unprefixed pair after a prefixed field" || return 1

  # 6. Test code is not production code. A fixture that hashes raw bytes is
  #    not a consensus preimage and must not be flagged.
  rm -rf "$tmp/testonly"
  mkdir -p "$tmp/testonly/src/tests"
  printf '%s\n' 'pub struct Keys {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}
pub fn digest(k: &Keys, hasher: &mut Sha3_256) {
    hasher.update((k.a.len() as u64).to_le_bytes());
    hasher.update(&k.a);
    hasher.update((k.b.len() as u64).to_le_bytes());
    hasher.update(&k.b);
}' >"$tmp/testonly/src/lib.rs"
  printf '%s\n' 'pub fn fixture(k: &Keys, hasher: &mut Sha3_256) {
    hasher.update(&k.a);
    hasher.update(&k.b);
}' >"$tmp/testonly/src/tests/fixture.rs"
  expect_pass "$tmp/testonly" "a raw concatenation inside src/tests" || return 1

  # 7. A `#[cfg(test)]` module inside a production file is also test code.
  mk "$tmp/cfgtest" 'pub struct Keys {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}
pub fn digest(k: &Keys, hasher: &mut Sha3_256) {
    hasher.update((k.a.len() as u64).to_le_bytes());
    hasher.update(&k.a);
    hasher.update((k.b.len() as u64).to_le_bytes());
    hasher.update(&k.b);
}
#[cfg(test)]
mod tests {
    pub fn fixture(k: &Keys, hasher: &mut Sha3_256) {
        hasher.update(&k.a);
        hasher.update(&k.b);
    }
}'
  expect_pass "$tmp/cfgtest" "a raw concatenation inside a cfg(test) module" || return 1

  # 8. Nothing to measure must be exit 2, never a pass. A tree with no
  #    variable-length field at all cannot have told us anything.
  mk "$tmp/nofields" 'pub struct Fixed {
    pub id: [u8; 32],
}
pub fn digest(f: &Fixed, hasher: &mut Sha3_256) {
    hasher.update(f.id);
}'
  expect_broken "$tmp/nofields" "a tree with no variable-length field" || return 1

  # 9. Variable-length fields that are never hashed adjacently are still
  #    measured, and the tree passes. Counting only adjacent pairs would make
  #    the gate report "nothing measured" precisely when the tree is clean,
  #    which is the one moment a gate must not go quiet. This is the shape the
  #    real tree took the moment the four call sites were fixed.
  mk "$tmp/nopairs" 'pub struct Deal {
    pub note: String,
    pub amount: u64,
}
pub fn digest(d: &Deal, hasher: &mut Sha3_256) {
    hasher.update(&d.note);
    hasher.update(d.amount.to_le_bytes());
}'
  expect_pass "$tmp/nopairs" "a tree whose variable-length fields are never adjacent" || return 1

  # 10. The blind spot that shipped in the sibling gate: rustfmt wraps a long
  #     call and the argument lands on the next line. A single-line match sees
  #     nothing and reports nothing, which is the worst failure a gate has.
  mk "$tmp/wrapped" 'pub struct Entry {
    pub name: String,
    pub sig: Vec<u8>,
}
pub fn leaf(e: &Entry, hasher: &mut Sha3_256) {
    hasher.update(
        e.name.as_bytes(),
    );
    hasher.update(&e.sig);
}'
  expect_finding "$tmp/wrapped" "a wrapped update() argument" || return 1

  # 11. Two updates that feed DIFFERENT hashers are not neighbours, however
  #     adjacent the lines are. The state root folds per-item digests into a
  #     second accumulator exactly like this.
  mk "$tmp/two_hashers" 'pub struct Item {
    pub name: String,
    pub sig: Vec<u8>,
}
pub fn root(items: &[Item]) -> [u8; 32] {
    let mut combined = Sha256::new();
    for item in items {
        let mut h = Sha256::new();
        h.update((item.name.len() as u64).to_le_bytes());
        h.update(item.name.as_bytes());
        h.update((item.sig.len() as u64).to_le_bytes());
        h.update(&item.sig);
        combined.update(h.finalize());
    }
    combined.finalize().into()
}'
  expect_pass "$tmp/two_hashers" "adjacent feeds into two different hashers" || return 1

  echo "hash-input length gate self-test OK: a raw pair, a mid-sequence raw \
pair and a tree with no variable-length field at all are rejected; a prefixed \
pair, a declared exemption, a trailing single field, a never-adjacent field \
and both flavours of test code all pass."
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  "")
    scan "$ROOT"
    ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
