#!/usr/bin/env bash
# ============================================================================
# check-threshold-rates-share-one-scale.sh
#
# A storage decision compares two rates. Only their ratio matters, so any
# common scale cancels, and that is exactly what makes the scale dangerous:
# applying it to one rate and not the other changes every threshold by the
# scale factor and changes nothing that looks wrong.
#
# This happened. `living_threshold.rs` carries a disk rate and a processor
# rate, both below one picodollar, both therefore multiplied by 1e6 to survive
# integer arithmetic. The first version multiplied the processor rate by 1e9
# instead, and the described-content threshold read 0.4 reads per half-life
# where the measurement says 418. Every test still passed, because the tests
# compared thresholds against each other and both sides moved together. It was
# caught by recomputing the same arithmetic outside Rust, not by the suite.
#
# So the rule is that the rates a threshold divides must be pinned to values
# an independent calculation reproduces, and the thresholds they produce must
# be pinned too.
#
# What the gate checks.
#
#   1. The module states, in its own comment, what each rate means in physical
#      units. A number whose unit lives only in the author's head cannot be
#      rechecked by the next person.
#   2. The rates are pinned to the values this project measured: 0.29 $/TB per
#      month of owned disk and 0.0025 $/hour of processor. Both are carried at
#      the same 1e6 scale, which is what makes 403 and 694 the right integers.
#   3. A test asserts the ordering of two thresholds that differ by a known
#      factor, so a scale applied to one side alone breaks it.
#   4. No floating point anywhere in the module. This decides whether bytes
#      are written; two nodes that round differently disagree about what the
#      network holds.
#   5. The arithmetic widens to u128 before multiplying. Bytes times a rate
#      times an epoch count leaves u64 for objects a network would hold.
#   6. *Every* rate pair in the module sits on one scale, not just the pinned
#      one. Checking that 403 and 694 appear somewhere says nothing about the
#      other `OperatorRates` literals in the file, and the first version of
#      this gate passed a module whose disagreement test carried the processor
#      rate at 1e9 while its disk rates sat at 1e6. That test then asserted
#      only that two answers differed, so a thousandfold error collapsed both
#      operators onto the same answer and the assertion, not the gate, is what
#      caught it. A rate pair whose two sides are more than a hundredfold
#      apart is a scale error, because real hardware does not differ by that
#      much: rented disk is about ten times owned disk, not a thousand.
#
# Usage:
#   bash scripts/check-threshold-rates-share-one-scale.sh              # gate
#   bash scripts/check-threshold-rates-share-one-scale.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

scan() {
  local target="$1"
  [ -f "$target" ] || fail "living-threshold module missing at $target"

  # 1. Both rates must be named with a physical unit in a comment.
  grep -q 'TB/month' "$target" ||
    fail "the disk rate is not stated in physical units; an integer whose unit is \
implicit cannot be rechecked"
  grep -q '\$/hour' "$target" ||
    fail "the processor rate is not stated in physical units"

  # 2. The pinned integers. These are 0.29 \$/TB/month and 0.0025 \$/hour, both
  #    at the same 1e6 scale. Wrong by a factor of a thousand once already.
  grep -qE 'disk_picodollars_per_byte_epoch: 403[^0-9_]' "$target" ||
    fail "the disk rate is not the measured 403 (0.29 \$/TB/month at 1e6 scale)"
  grep -qE 'cpu_picodollars_per_nano: 694[^0-9_]' "$target" ||
    fail "the processor rate is not the measured 694 (0.0025 \$/hour at 1e6 scale). \
A rate at a different scale from the disk rate moves every threshold by that factor \
and breaks no test, because the tests compare thresholds against each other"

  # 3. A test must order two thresholds that are known to differ, so a scale
  #    applied to one rate alone shows up.
  grep -q 'fn each_lever_has_its_own_crossing_point' "$target" ||
    fail "no test orders two levers' thresholds against each other"
  local body
  body="$(sed -n '/fn each_lever_has_its_own_crossing_point/,/^    }$/p' "$target")"
  printf '%s' "$body" | grep -q 'assert!' ||
    fail "the crossing-point test asserts nothing"

  # 4. Floating point is a fork waiting to happen.
  local floats
  floats="$(grep -nE '\b(f32|f64)\b' "$target" | grep -v '^\s*[0-9]*:\s*//' || true)"
  if [ -n "$floats" ]; then
    echo "FAIL: floating point in a module that decides whether bytes are written:" >&2
    printf '  %s\n' "$floats" >&2
    exit 1
  fi

  # 5. The products must widen before multiplying.
  grep -q 'u128::from' "$target" ||
    fail "the arithmetic does not widen to u128; bytes times a rate times an epoch \
count overflows u64 for objects a network would actually hold"

  # 6. Every rate pair, not only the pinned one, must share a scale.
  #
  #    Pinning 403 and 694 checks one literal. The module holds others, and
  #    one of them carried the processor rate a thousandfold off while this
  #    gate reported OK. Ratios are what the arithmetic uses, so a pair whose
  #    sides sit more than a hundredfold apart did not come from hardware.
  local pairs
  pairs="$(awk '
    /disk_picodollars_per_byte_epoch:/ {
      d = $0; sub(/.*disk_picodollars_per_byte_epoch:[ \t]*/, "", d);
      sub(/[^0-9_].*$/, "", d); gsub(/_/, "", d);
      disk = d; disk_line = NR; next
    }
    /cpu_picodollars_per_nano:/ {
      c = $0; sub(/.*cpu_picodollars_per_nano:[ \t]*/, "", c);
      sub(/[^0-9_].*$/, "", c); gsub(/_/, "", c);
      if (disk_line == NR - 1 && disk + 0 > 0 && c + 0 > 0) {
        hi = disk + 0; lo = c + 0;
        if (lo > hi) { t = hi; hi = lo; lo = t }
        if (hi > lo * 100) printf "line %d: disk %s against processor %s\n", NR, disk, c
      }
      disk_line = -1
    }
  ' "$target")"
  if [ -n "$pairs" ]; then
    echo "FAIL: a rate pair spans more than a hundredfold, which is a scale error \
rather than a hardware difference; rented disk is about ten times owned disk:" >&2
    printf '  %s\n' "$pairs" >&2
    exit 1
  fi

  # 7. A decaying estimate that cannot decay is a counter with extra steps.
  grep -q 'fn an_access_estimate_halves_every_half_life' "$target" ||
    fail "no test shows the access estimate actually decaying"

  # 8. The disagreement test must name the two answers it expects.
  #
  #    `assert_ne!` passes for any two distinct answers, including the pair
  #    the other way round, which is what a sign error in `decide` produces.
  grep -q 'fn operators_with_different_hardware_may_disagree' "$target" ||
    fail "no test shows two operators reaching different answers for one object"
  local disagree
  disagree="$(sed -n '/fn operators_with_different_hardware_may_disagree/,/^    }$/p' "$target")"
  printf '%s' "$disagree" | grep -q 'Decision::Hold' ||
    fail "the disagreement test does not name Hold as one of the two answers; \
asserting only that the answers differ passes for the pair the other way round, \
which is what a sign error produces"
  printf '%s' "$disagree" | grep -q 'Decision::Apply' ||
    fail "the disagreement test does not name Apply as one of the two answers"

  echo "Threshold rates OK: both rates carry a physical unit and one shared scale, \
their thresholds are ordered by a test, the estimate is shown to decay, the arithmetic \
widens, and there is no floating point."
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  local good="$tmp/good.rs"
  cat > "$good" <<'EOF'
fn rates() -> OperatorRates {
    OperatorRates {
        // 0.29 $/TB/month at 1e6 scale.
        disk_picodollars_per_byte_epoch: 403,
        // 0.0025 $/hour at 1e6 scale.
        cpu_picodollars_per_nano: 694,
    }
}

fn widen() -> u128 {
    u128::from(1u64)
}

#[test]
fn each_lever_has_its_own_crossing_point() {
    assert!(described_at > recompressed_at * 4);
}

#[test]
fn an_access_estimate_halves_every_half_life() {
    assert_eq!(a.rate_scaled(HL), start / 2);
}

#[test]
fn operators_with_different_hardware_may_disagree() {
    let cheap_disk = OperatorRates {
        disk_picodollars_per_byte_epoch: 40,
        cpu_picodollars_per_nano: 694,
    };
    let dear_disk = OperatorRates {
        disk_picodollars_per_byte_epoch: 4_030,
        cpu_picodollars_per_nano: 694,
    };
    assert_eq!(on_cheap, Decision::Hold);
    assert_eq!(on_dear, Decision::Apply);
}
EOF
  ( scan "$good" ) >/dev/null 2>&1 ||
    { echo "BROKEN GATE: a correct module was rejected!" >&2; ( scan "$good" ) >&2 || true; exit 1; }

  # The exact bug this gate exists for: one rate at a different scale.
  sed 's/cpu_picodollars_per_nano: 694,/cpu_picodollars_per_nano: 694_000,/' "$good" \
    > "$tmp/scale.rs"
  if ( scan "$tmp/scale.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a processor rate a thousand times off was accepted!" >&2
    exit 1
  fi

  # A rate with no unit stated.
  sed 's|// 0.29 \$/TB/month at 1e6 scale.||' "$good" > "$tmp/nounit.rs"
  if ( scan "$tmp/nounit.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a disk rate with no physical unit was accepted!" >&2
    exit 1
  fi

  # No test ordering two thresholds.
  sed 's/fn each_lever_has_its_own_crossing_point/fn unrelated/' "$good" > "$tmp/noorder.rs"
  if ( scan "$tmp/noorder.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: no threshold-ordering test was accepted!" >&2
    exit 1
  fi

  # An ordering test that asserts nothing.
  sed 's/    assert!(described_at > recompressed_at \* 4);/    let _ = described_at;/' \
    "$good" > "$tmp/noassert.rs"
  if ( scan "$tmp/noassert.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an ordering test asserting nothing was accepted!" >&2
    exit 1
  fi

  # Floating point.
  printf 'fn drift(x: f64) -> f64 { x * 0.5 }\n' > "$tmp/float.rs"
  cat "$good" >> "$tmp/float.rs"
  if ( scan "$tmp/float.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: floating point was accepted!" >&2
    exit 1
  fi

  # No widening.
  sed 's/    u128::from(1u64)/    1/' "$good" > "$tmp/narrow.rs"
  if ( scan "$tmp/narrow.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: arithmetic that never widens was accepted!" >&2
    exit 1
  fi

  # No decay test.
  sed 's/fn an_access_estimate_halves_every_half_life/fn something/' "$good" > "$tmp/nodecay.rs"
  if ( scan "$tmp/nodecay.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a module with no decay test was accepted!" >&2
    exit 1
  fi

  # The bug the pinned check missed: a second rate pair off by a thousand.
  # `good.rs` still holds the pinned 403/694, so the old gate reported OK.
  sed '/disk_picodollars_per_byte_epoch: 40,/{n;s/cpu_picodollars_per_nano: 694,/cpu_picodollars_per_nano: 694_000,/;}' \
    "$good" > "$tmp/secondscale.rs"
  if ( scan "$tmp/secondscale.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an unpinned rate pair a thousand times off was accepted!" >&2
    exit 1
  fi

  # A disagreement test that only asserts the answers differ.
  sed -e 's/    assert_eq!(on_cheap, Decision::Hold);/    assert_ne!(on_cheap, on_dear);/' \
      -e '/    assert_eq!(on_dear, Decision::Apply);/d' \
    "$good" > "$tmp/nameless.rs"
  if ( scan "$tmp/nameless.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a disagreement test naming neither answer was accepted!" >&2
    exit 1
  fi

  # No disagreement test at all.
  sed 's/fn operators_with_different_hardware_may_disagree/fn elsewhere/' \
    "$good" > "$tmp/noagree.rs"
  if ( scan "$tmp/noagree.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a module with no disagreement test was accepted!" >&2
    exit 1
  fi

  # Missing module.
  if ( scan "$tmp/absent.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing module was accepted!" >&2
    exit 1
  fi

  echo "threshold-rate gate self-test OK: a wrongly scaled pinned rate, a wrongly scaled \
unpinned rate, a rate with no unit, a missing or empty ordering test, a disagreement test \
that names neither answer, a missing disagreement test, floating point, narrow arithmetic, \
a missing decay test and an absent module are all rejected; a correct module passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT/src/storage/living_threshold.rs"
