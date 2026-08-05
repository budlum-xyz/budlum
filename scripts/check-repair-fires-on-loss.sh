#!/usr/bin/env bash
# ============================================================================
# check-repair-fires-on-loss.sh, the repair trigger must be reachable.
#
# `StorageRegistry::objects_needing_repair` has existed since erasure coding
# landed. Nothing called it. A function that computes the repair band and is
# never invoked does not shorten any repair window; measured against the
# durability model, the window it leaves is unbounded, and an unbounded
# repair window turns every published durability figure into a statement
# about a system nobody is running.
#
# That is not a bug a test catches, because the arithmetic inside the
# function is correct and its unit tests pass. It is a wiring defect, and the
# only thing that catches a wiring defect is a check that asks whether the
# production path reaches the code.
#
# Four things are required here, each because leaving it out returns the
# system to a state it was measurably in:
#
#   1. The maintenance sweep reads the repair band. Without this the trigger
#      is exactly as unwired as it was.
#   2. The band is judged per object, against that object's own scheme. A
#      single margin applied to every object cannot be right for both
#      `(10,16)` and `LRC k=2000`: measured over a 24 hour window at 20%
#      annual per-shard loss, a fixed margin of 2 gives 1.8e-05 on the first
#      and ~1.0 on the second, so a constant means the wide codes reliably
#      start their repair too late.
#   3. Unrecoverable objects are surfaced separately. Below `k` there is
#      nothing to rebuild from, so folding them into the repair band would
#      report "a repair is coming" for objects where none can come.
#   4. A deal that matures unrenewed opens a reallocation ticket. The slash
#      path always did; the expiry path did not, so an honest operator
#      leaving at the end of its term dropped a shard silently. Measured at a
#      99% per-term renewal rate this walks `LRC k=2000` to `k` in 4 terms.
#
# Usage:
#   bash scripts/check-repair-fires-on-loss.sh              # gate
#   bash scripts/check-repair-fires-on-loss.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

# The files each check reads, resolved once so the canaries can repoint ROOT.
actor_file()      { echo "$ROOT/src/chain/chain_actor.rs"; }
registry_file()   { echo "$ROOT/src/domain/storage_deal.rs"; }
manifest_file()   { echo "$ROOT/src/storage/manifest.rs"; }
blockchain_file() { echo "$ROOT/src/chain/blockchain.rs"; }

# Strip comments before matching. Every one of these checks is documented in
# the same tree it inspects, and matching our own prose would make the gate
# pass on the strength of a sentence describing the thing being absent.
code_of() {
  local f="$1"
  [ -f "$f" ] || fail "expected file missing: $f"
  sed -e 's://.*::' "$f"
}

# 1. The maintenance sweep calls the repair-band scan.
check_sweep_reads_the_band() {
  local code
  code="$(code_of "$(actor_file)")"
  grep -q 'objects_below_own_repair_margin' <<<"$code" \
    || fail "the maintenance sweep does not read the repair band.
  \`objects_below_own_repair_margin\` is not called from chain_actor.rs, so
  the repair trigger is unwired and the effective repair window is unbounded."
}

# 2. The band is computed per object, from that object's own scheme.
check_margin_scales_with_the_scheme() {
  local code
  code="$(code_of "$(manifest_file)")"
  grep -q 'fn repair_margin' <<<"$code" \
    || fail "ContentManifest::repair_margin is gone.
  Without a per-scheme margin the sweep has to pick one number for every
  object, which is measurably wrong for the wide codes."

  # It must derive from the parity budget, not be a literal.
  grep -A 8 'fn repair_margin' <<<"$code" | grep -q 'parity_count' \
    || fail "repair_margin no longer derives from the parity budget.
  A constant margin means two different things on (10,16) and LRC k=2000."

  # Two definitions are required, and checking only that the name exists
  # somewhere would accept either one alone. `ErasureScheme::repair_margin`
  # holds the rule; `ContentManifest::repair_margin` forwards it, and exists
  # so no call site reaches through to `erasure` and substitutes its own
  # number. Measured while writing this gate: deleting the forwarder left the
  # name present once and the gate passed, while the tree no longer compiled.
  local definitions
  definitions="$(grep -c 'fn repair_margin' <<<"$code" || true)"
  [ "$definitions" -ge 2 ] || fail "repair_margin is defined $definitions time(s), expected 2.
  ErasureScheme holds the rule and ContentManifest forwards it. With only
  one of them, either the rule is gone or every caller has to reach through
  to \`erasure\` itself, which is how a per-scheme rule becomes a constant."

  grep -A 4 'fn repair_margin' <<<"$code" | grep -q 'self.erasure.repair_margin()' \
    || fail "ContentManifest::repair_margin does not forward to the scheme.
  A forwarder that computes its own answer is a second rule, and two rules
  drift."

  local reg
  reg="$(code_of "$(registry_file)")"
  grep -A 20 'fn objects_below_own_repair_margin' <<<"$reg" | grep -q 'repair_margin()' \
    || fail "the per-object scan does not ask each manifest for its margin."
}

# 3. Unrecoverable objects are reported on their own path.
check_unrecoverable_is_separate() {
  local code
  code="$(code_of "$(actor_file)")"
  grep -q 'unrecoverable_objects' <<<"$code" \
    || fail "the sweep does not surface unrecoverable objects.
  Objects below k cannot be repaired; reporting them inside the repair band
  would claim a repair is coming for objects where none can."
}

# 4. Maturing unrenewed opens a ticket.
check_expiry_opens_a_ticket() {
  local code
  code="$(code_of "$(blockchain_file)")"
  grep -q 'open_expiry_reallocation' <<<"$code" \
    || fail "expiring a deal does not open a reallocation ticket.
  The slash path opens one. Without this, an operator that serves its whole
  term and leaves drops a shard with nothing arranged to replace it."

  local reg
  reg="$(code_of "$(registry_file)")"
  grep -q 'fn open_expiry_reallocation' <<<"$reg" \
    || fail "StorageRegistry::open_expiry_reallocation is gone."
  grep -q 'fn renew_deal' <<<"$reg" \
    || fail "StorageRegistry::renew_deal is gone.
  Renewal is what makes the expiry ticket cheap: an incumbent still holding
  the bytes extends for no transfer, a replacement moves a whole shard."
}

run_all() {
  check_sweep_reads_the_band
  check_margin_scales_with_the_scheme
  check_unrecoverable_is_separate
  check_expiry_opens_a_ticket
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  real_root="$ROOT"
  canaries=0

  # Each canary copies the tree, removes exactly one thing, and requires the
  # matching check to fail. A check that stopped looking passes its gate
  # forever; this is the only way to notice.
  break_and_expect_failure() {
    local label="$1" file="$2" sed_prog="$3" check="$4"
    local work="$tmp/work"
    rm -rf "$work"
    mkdir -p "$work/src/chain" "$work/src/domain" "$work/src/storage"
    cp "$real_root/src/chain/chain_actor.rs" "$work/src/chain/"
    cp "$real_root/src/chain/blockchain.rs" "$work/src/chain/"
    cp "$real_root/src/domain/storage_deal.rs" "$work/src/domain/"
    cp "$real_root/src/storage/manifest.rs" "$work/src/storage/"
    sed -i "$sed_prog" "$work/$file"

    ROOT="$work"
    if ( "$check" ) >/dev/null 2>&1; then
      ROOT="$real_root"
      echo "VACUOUS GATE: $label was not detected!" >&2
      exit 1
    fi
    ROOT="$real_root"
    canaries=$((canaries + 1))
  }

  # Canary 1: the sweep stops reading the band, the exact state this gate
  # was written for.
  break_and_expect_failure \
    "an unwired repair trigger" \
    "src/chain/chain_actor.rs" \
    's|objects_below_own_repair_margin|CANARY_REMOVED_scan|g' \
    check_sweep_reads_the_band

  # Canary 2: the margin becomes a constant again.
  break_and_expect_failure \
    "a repair margin that ignores the scheme" \
    "src/storage/manifest.rs" \
    's|fn repair_margin|fn CANARY_REMOVED_margin|g' \
    check_margin_scales_with_the_scheme

  # Canary 3: the margin survives but stops reading the parity budget, which
  # is the subtler version of the same defect.
  break_and_expect_failure \
    "a repair margin detached from the parity budget" \
    "src/storage/manifest.rs" \
    's|self.parity_count()|2u32|g' \
    check_margin_scales_with_the_scheme

  # Canary 4: the forwarder is deleted and the rule left behind. Found by
  # sabotage: with only the name check, this passed while the tree failed to
  # compile, which is a gate reporting on code that does not exist.
  break_and_expect_failure \
    "a deleted ContentManifest::repair_margin forwarder" \
    "src/storage/manifest.rs" \
    '0,/fn repair_margin/{b};s|pub fn repair_margin|pub fn CANARY_REMOVED_forwarder|' \
    check_margin_scales_with_the_scheme

  # Canary 5: the forwarder survives but computes its own answer, which is
  # the subtler version: two rules that drift apart.
  break_and_expect_failure \
    "a forwarder that answers for itself instead of asking the scheme" \
    "src/storage/manifest.rs" \
    's|self.erasure.repair_margin()|2u32|' \
    check_margin_scales_with_the_scheme

  # Canary 6: unrecoverable objects get folded back into the band.
  break_and_expect_failure \
    "unrecoverable objects hidden inside the repair band" \
    "src/chain/chain_actor.rs" \
    's|unrecoverable_objects|CANARY_REMOVED_unrecoverable|g' \
    check_unrecoverable_is_separate

  # Canary 7: expiry stops opening a ticket, the asymmetry that was measured.
  break_and_expect_failure \
    "expiry that drops a shard without a ticket" \
    "src/chain/blockchain.rs" \
    's|open_expiry_reallocation|CANARY_REMOVED_expiry|g' \
    check_expiry_opens_a_ticket

  # Canary 8: renewal is removed, which makes every expiry cost a transfer.
  break_and_expect_failure \
    "expiry with no renewal path" \
    "src/domain/storage_deal.rs" \
    's|fn renew_deal|fn CANARY_REMOVED_renew|g' \
    check_expiry_opens_a_ticket

  # Canary 9: the per-object scan stops asking the manifest and hardcodes
  # one number, which is how a per-scheme rule quietly becomes a constant.
  break_and_expect_failure \
    "a per-object scan that stopped asking each scheme" \
    "src/domain/storage_deal.rs" \
    's|manifest.repair_margin()|2u32|g' \
    check_margin_scales_with_the_scheme

  # 10. The tree as committed must pass, or the gate rejects every pull
  #    request for reasons unrelated to its diff.
  run_all || { echo "BROKEN GATE: the committed tree was rejected!" >&2; exit 1; }

  echo "repair trigger gate self-test OK: $canaries canaries."
  echo "  An unwired trigger, a constant margin, a margin detached from parity,"
  echo "  a deleted forwarder, a forwarder that answers for itself, hidden"
  echo "  unrecoverable objects, a ticketless expiry, a missing renewal path"
  echo "  and a scan that stopped asking each scheme are all rejected;"
  echo "  the tree as committed passes."
  exit 0
fi

run_all
echo "Repair trigger OK: the sweep reads the repair band per object, reports"
echo "  unrecoverable objects separately, and a deal that matures unrenewed"
echo "  opens a reallocation ticket."
