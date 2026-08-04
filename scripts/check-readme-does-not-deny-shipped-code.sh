#!/usr/bin/env bash
# ============================================================================
# check-readme-does-not-deny-shipped-code.sh
#
# A maturity warning that describes an absent feature must not survive the
# feature arriving.
#
# Why this gate exists.
#
# `src/storage/README.md` carried, under "maturity warnings":
#
#     5. Redundancy is replication, not erasure coding. ShardRef carries only
#        (index, shard_id, size); there is no parity shard concept.
#
# By then `ShardRef` carried a `kind` of `Data` or `Parity`, `ContentManifest`
# carried an `ErasureScheme { k, n }`, and `src/storage/erasure.rs` was a real
# Reed-Solomon coder over GF(2^8) with sixteen tests, including one that walks
# all fifteen two-loss patterns of a `(4,6)` code. `docs/BUD_STORAGE_ROADMAP.md`
# recorded the same gap as "closed" in the same tree.
#
# Two documents, one repository, opposite answers. This is the mirror of the
# problem check-binding-claims-match-reality.sh catches. There, a capability
# flag claimed a binding the tree did not have and a caller would attempt
# something impossible. Here a warning denies a capability the tree does have,
# and the costs are just as real: a reader plans work already done, an auditor
# scopes around a module that needs review, and the warnings that are still
# true lose their authority by association. A list of caveats is only useful
# while every entry on it is accurate.
#
# What the gate checks.
#
# For each pair below, when the code evidence is present in the tree, the
# README must not still be asserting the absence. The pairs are written out by
# hand rather than inferred, because a phrase-matching heuristic over prose
# would fire on any sentence that happens to mention a type name, and a gate
# that cries wolf gets muted.
#
# What it deliberately does not check. It does not require the README to claim
# anything. Documenting a feature as unfinished, partially wired, or unsafe for
# mainnet is honest and this gate has no opinion about it. It objects only to
# the flat denial of something the tree contains.
#
# Usage:
#   bash scripts/check-readme-does-not-deny-shipped-code.sh
#   bash scripts/check-readme-does-not-deny-shipped-code.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]

# (readme, denial regex, evidence file, evidence regex, what to do about it)
PAIRS = [
    (
        os.path.join("src", "storage", "README.md"),
        r"parity shard kavram[ıi] yok",
        os.path.join("src", "storage", "manifest.rs"),
        r"ShardKind::Parity",
        "`ShardRef` carries a `kind` and `ShardKind::Parity` exists. If parity "
        "is present but unwired, say that; do not say the concept is absent.",
    ),
    (
        os.path.join("src", "storage", "README.md"),
        r"[Yy]edeklilik erasure coding de[ğg]il",
        os.path.join("src", "storage", "erasure.rs"),
        r"pub fn encode_object",
        "`src/storage/erasure.rs` computes real Reed-Solomon parity. The "
        "honest warning is that nothing calls it yet, not that redundancy is "
        "replication.",
    ),
]

problems = []
checked = 0

for readme_rel, denial_re, evidence_rel, evidence_re, advice in PAIRS:
    readme = os.path.join(root, readme_rel)
    evidence = os.path.join(root, evidence_rel)

    if not os.path.isfile(readme):
        problems.append(
            f"{readme_rel} is missing. If the module README moved, update this "
            "gate in the same commit so its claims stay watched."
        )
        continue
    if not os.path.isfile(evidence):
        # The feature genuinely is not there; the denial is accurate.
        checked += 1
        continue

    checked += 1
    readme_text = open(readme, encoding="utf-8").read()
    evidence_text = open(evidence, encoding="utf-8").read()
    # Comments can discuss a type without defining it; strip them so the
    # evidence is code rather than prose about code.
    evidence_code = re.sub(r"//[^\n]*", "", evidence_text)

    denies = re.search(denial_re, readme_text) is not None
    exists = re.search(evidence_re, evidence_code) is not None

    if denies and exists:
        problems.append(
            f"{readme_rel} still states that a feature is absent, and "
            f"{evidence_rel} contains it. {advice}"
        )

if not checked:
    print("FAIL: gate checked no pair", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(f"readme drift gate OK: {checked} claim/evidence pairs agree")
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
      return 1
    fi
  }

  build() {
    local dir="$1" readme_body="$2" manifest_body="$3" erasure_body="$4"
    rm -rf "$dir"
    mkdir -p "$dir/src/storage"
    printf '%s\n' "$readme_body" >"$dir/src/storage/README.md"
    printf '%s\n' "$manifest_body" >"$dir/src/storage/manifest.rs"
    printf '%s\n' "$erasure_body" >"$dir/src/storage/erasure.rs"
  }

  local DENIES="5. Yedeklilik erasure coding degil, replikasyon. parity shard kavrami yok."
  local HONEST="5. Erasure coding var, parity uretimi uretim akisina bagli degil."
  local HAS_PARITY="pub enum ShardKind { Data, Parity }
fn f() { let k = ShardKind::Parity; }"
  local NO_PARITY="pub struct ShardRef { pub index: u32 }"
  local HAS_CODER="pub fn encode_object(d: &[u8]) -> Vec<u8> { d.to_vec() }"
  local NO_CODER="pub fn nothing() {}"

  # 1. Denial with no feature: accurate, must pass.
  build "$tmp/accurate" "$DENIES" "$NO_PARITY" "$NO_CODER"
  if ! ( scan "$tmp/accurate" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: an accurate maturity warning was rejected!" >&2
    return 1
  fi

  # 2. Feature present, README corrected: must pass.
  build "$tmp/corrected" "$HONEST" "$HAS_PARITY" "$HAS_CODER"
  if ! ( scan "$tmp/corrected" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a corrected README was rejected!" >&2
    return 1
  fi

  # 3. The bug: the feature landed and the denial stayed.
  build "$tmp/stale" "$DENIES" "$HAS_PARITY" "$HAS_CODER"
  expect_finding "$tmp/stale" "a README denying a feature the tree contains" \
    || return 1

  # 4. Only the coder landed. One pair drifts, one does not; the gate must
  #    still report, rather than needing every pair to break at once.
  build "$tmp/half" "$DENIES" "$NO_PARITY" "$HAS_CODER"
  expect_finding "$tmp/half" "a single drifted pair among accurate ones" \
    || return 1

  # 5. Evidence that exists only inside a comment is prose, not code. A gate
  #    fooled by a mention would fire on any README that quotes a type name.
  build "$tmp/comment" "$DENIES" "$NO_PARITY" "// pub fn encode_object() {}"
  if ! ( scan "$tmp/comment" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a type named only inside a comment counted as" >&2
    echo "shipped code." >&2
    return 1
  fi

  echo "readme drift gate self-test OK: 5 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
