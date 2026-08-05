#!/usr/bin/env bash
# ============================================================================
# check-derived-content-stays-byte-exact.sh
#
# Derived content is the only lever that reaches a zero multiplier inside the
# class that holds the bytes. Measured on a published scan of a comparable
# network: images are 58.4% of stored volume, video another 33.6%, and the
# classes that were already free are 40% of the objects but under a thousandth
# of the bytes. Storage is paid for in bytes.
#
# It is safe for exactly one reason, and it is the same reason generated
# content is safe: `manifest_id` is the hash of the bytes, so a node can
# recompute the derivation and compare. That reason stops holding the moment
# any of these drift, and each is invisible in review:
#
#   1. The region is expressed in pixels instead of blocks. A crop is
#      byte-exact only on block boundaries; measured directly on quantised DCT
#      coefficients, three block-aligned crops matched the master's
#      sub-rectangle exactly and two misaligned crops did not. A pixel box can
#      express the misaligned case, so the type would be advertising a
#      capability the format does not have.
#   2. The block size drops to 8. That is right for luma and wrong for 4:2:0
#      chroma, where the planes are halved and an 8-pixel luma-aligned crop can
#      still cut a chroma block in two.
#   3. Derivations start chaining. A crop of a crop has a dependency depth
#      nobody bounded, and every hop is another object that has to stay
#      retrievable. It is also unnecessary: a crop of a crop is expressible as
#      a crop of the original.
#   4. Floating point appears. Two nodes that disagree about whether an object
#      is valid is a fork, and this module decides validity.
#   5. The saving is reported as a bare ratio. Forty per cent of objects and
#      a tenth of a per cent of bytes are the same measurement, and this
#      project has already had to correct that claim once.
#
# Usage:
#   bash scripts/check-derived-content-stays-byte-exact.sh              # gate
#   bash scripts/check-derived-content-stays-byte-exact.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

target() { echo "$ROOT/src/storage/derived.rs"; }

# Comments are stripped before matching. This module documents every rule it
# enforces, and matching our own prose would let the gate pass on the strength
# of a sentence describing the thing that is missing.
code_of() {
  local f
  f="$(target)"
  [ -f "$f" ] || fail "derived content module missing: $f"
  sed -e 's://.*::' "$f"
}

# 1. The region is in blocks, and there is no pixel-coordinate field.
check_region_is_in_blocks() {
  local code
  code="$(code_of)"
  for field in block_x block_y block_w block_h; do
    grep -q "pub $field: u32" <<<"$code" \
      || fail "DerivedSpec has no \`$field\`.
  The box must be expressed in blocks. In pixels, a misaligned crop is
  representable, and a misaligned crop cannot be recomputed byte-exactly."
  done

  # A pixel-coordinate field would reintroduce exactly what blocks prevent.
  # `pixel_width`/`pixel_height` are derived accessors, not stored fields, so
  # the match is anchored to the field syntax.
  if grep -qE 'pub (pixel_x|pixel_y|pixel_w|pixel_h|x|y|w|h): u32' <<<"$code"; then
    fail "DerivedSpec carries a pixel-coordinate field.
  That makes an unrepresentable state representable again."
  fi
}

# 2. The block size is 16, the value that holds for subsampled chroma.
check_block_size_is_conservative() {
  local code
  code="$(code_of)"
  grep -qE 'DERIVED_BLOCK_PIXELS: u32 = 16;' <<<"$code" \
    || fail "DERIVED_BLOCK_PIXELS is not 16.
  8 is correct for luma and wrong for 4:2:0 chroma, where the planes are
  halved. 16 is what jpegtran uses, for this reason."
}

# 3. Chaining is refused.
check_derivations_do_not_chain() {
  local code
  code="$(code_of)"
  grep -q 'DerivationChain' <<<"$code" \
    || fail "there is no DerivationChain refusal.
  A derivation naming another derivation has an unbounded dependency depth."
  grep -q 'fn check_master_is_stored' <<<"$code" \
    || fail "check_master_is_stored is gone, so nothing enforces the refusal."
}

# 4. No floating point. Same rule, same reason, as the generator module.
check_no_floating_point() {
  local code
  code="$(code_of)"
  if grep -qE '\b(f32|f64)\b' <<<"$code"; then
    fail "floating point in the derived content module.
  Two nodes that produce different answers disagree about whether an object
  is valid, which is a fork. This module decides validity."
  fi
  # `0.5`, `1.0` and friends: a literal is as much of a float as a type is.
  if grep -qE '[^0-9a-zA-Z_.][0-9]+\.[0-9]+' <<<"$code"; then
    fail "a floating-point literal in the derived content module."
  fi
}

# 5. The saving is reported as two numbers, never one ratio.
check_saving_is_two_numbers() {
  local code
  code="$(code_of)"
  grep -q 'fn stored_versus_independent' <<<"$code" \
    || fail "stored_versus_independent is gone.
  It exists so a caller quoting the saving quotes both numbers. A ratio on
  its own is the shape of claim this project already had to correct: 40% of
  objects and 0.1% of bytes are the same measurement."

  grep -A 4 'fn stored_versus_independent' <<<"$code" | grep -qE '\(u64, u64\)' \
    || fail "stored_versus_independent no longer returns a pair.
  A single number is the claim shape the function exists to prevent."
}

# 6. The commitment covers the bounds, not only the box.
check_commitment_covers_the_bounds() {
  local code
  code="$(code_of)"
  grep -q 'BDLM_DERIVED_CONTENT_V1' <<<"$code" \
    || fail "the derivation commitment has no domain tag."
  for field in master_blocks_w master_blocks_h; do
    grep -A 14 'fn derivation_commitment_tag' <<<"$code" | grep -q "$field" \
      || fail "the commitment omits \`$field\`.
  The declared bounds are what a verifier checks the box against, so two
  specs with different bounds must not share a commitment."
  done
}

run_all() {
  check_region_is_in_blocks
  check_block_size_is_conservative
  check_derivations_do_not_chain
  check_no_floating_point
  check_saving_is_two_numbers
  check_commitment_covers_the_bounds
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  real_root="$ROOT"
  canaries=0

  break_and_expect_failure() {
    local label="$1" sed_prog="$2" check="$3"
    local work="$tmp/work"
    rm -rf "$work"
    mkdir -p "$work/src/storage"
    cp "$real_root/src/storage/derived.rs" "$work/src/storage/"
    sed -i "$sed_prog" "$work/src/storage/derived.rs"

    ROOT="$work"
    if ( "$check" ) >/dev/null 2>&1; then
      ROOT="$real_root"
      echo "VACUOUS GATE: $label was not detected!" >&2
      exit 1
    fi
    ROOT="$real_root"
    canaries=$((canaries + 1))
  }

  # 1. A pixel box, which can express the crop that cannot be recomputed.
  break_and_expect_failure \
    "a region expressed in pixels" \
    's|pub block_x: u32|pub x: u32|' \
    check_region_is_in_blocks

  # 2. The block size drops to the luma-only value.
  break_and_expect_failure \
    "a block size that ignores subsampled chroma" \
    's|DERIVED_BLOCK_PIXELS: u32 = 16;|DERIVED_BLOCK_PIXELS: u32 = 8;|' \
    check_block_size_is_conservative

  # 3. Chaining stops being refused.
  break_and_expect_failure \
    "derivations allowed to chain" \
    's|DerivationChain|CANARY_removed_chain_refusal|g' \
    check_derivations_do_not_chain

  # 4. The enforcement is removed while the error variant stays, which is how
  #    a refusal becomes decorative.
  break_and_expect_failure \
    "a chain refusal nothing enforces" \
    's|fn check_master_is_stored|fn CANARY_removed_enforcement|' \
    check_derivations_do_not_chain

  # 5. A float type appears.
  break_and_expect_failure \
    "a floating-point type" \
    's|pub block_w: u32|pub block_w: f64|' \
    check_no_floating_point

  # 6. A float literal, which the type check alone would miss.
  break_and_expect_failure \
    "a floating-point literal" \
    's|DERIVED_BLOCK_PIXELS: u32 = 16;|DERIVED_BLOCK_PIXELS: u32 = 16; const CANARY: f64 = 0.5;|' \
    check_no_floating_point

  # 7. The saving collapses to one number.
  break_and_expect_failure \
    "a saving reported as a single number" \
    's|fn stored_versus_independent|fn CANARY_removed_pair|' \
    check_saving_is_two_numbers

  # 8. The commitment stops covering the declared bounds.
  break_and_expect_failure \
    "a commitment that omits the master bounds" \
    's|&self.master_blocks_w.to_le_bytes(),||' \
    check_commitment_covers_the_bounds

  # 9. The domain tag goes, which would let this hash collide with another
  #    context's.
  break_and_expect_failure \
    "a derivation commitment with no domain tag" \
    's|BDLM_DERIVED_CONTENT_V1|CANARY_untagged|' \
    check_commitment_covers_the_bounds

  # 10. The tree as committed must pass, or the gate rejects every pull
  #     request for reasons unrelated to its diff.
  run_all || { echo "BROKEN GATE: the committed tree was rejected!" >&2; exit 1; }

  echo "derived content gate self-test OK: $canaries canaries."
  echo "  A pixel box, a luma-only block size, chaining, an unenforced chain"
  echo "  refusal, a float type, a float literal, a single-number saving, a"
  echo "  commitment missing the bounds and one missing its domain tag are all"
  echo "  rejected; the tree as committed passes."
  exit 0
fi

run_all
echo "Derived content OK: the region is in blocks of 16 pixels, derivations do"
echo "  not chain, no floating point decides validity, the saving is reported"
echo "  as two numbers, and the commitment covers the declared bounds."
