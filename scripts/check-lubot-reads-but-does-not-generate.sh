#!/usr/bin/env bash
# ============================================================================
# check-lubot-reads-but-does-not-generate.sh
#
# Lubot consumes text, images, audio and video frames. It does not produce
# them. That is a scope decision rather than a technical limit, which is
# exactly why it needs a gate: a limit defends itself when someone crosses it,
# a decision does not.
#
# The pressure is obvious once the reading side exists. `PerceptionKind` lists
# `Image` and `Video`, and adding `ImageOutput` beside `ImageInput` looks like
# symmetry rather than a new product. It is a new product: generation needs
# its own economics, its own abuse model, and an answer to who owns the
# output. None of those are settled, and shipping the surface before they are
# would commit the chain to all three by accident.
#
# Three further properties are checked because each one, if it drifts, turns
# the reading path into something it was not reviewed as:
#
#   1. Per-modality ceilings in per-modality units. A single shared ceiling
#      has to be bytes, and bytes are the wrong unit for three of the four: a
#      compressed image is small on disk and enormous once decoded. Collapsing
#      them either overprices text or underprices images, and underpricing an
#      input is how a cheap request becomes expensive for the operator.
#   2. Fail-closed defaults. A model that declared no modality must refuse
#      every read. The opposite default means a model whose declaration was
#      lost silently accepts everything.
#   3. The decoder boundary stays stated. Text reaches a model without
#      decoding; the other three do not, and a decoder is both where malformed
#      input becomes unbounded work and where two operators can disagree about
#      what an image contains.
#
# Usage:
#   bash scripts/check-lubot-reads-but-does-not-generate.sh              # gate
#   bash scripts/check-lubot-reads-but-does-not-generate.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

target() { echo "$ROOT/src/lubot/perception.rs"; }

# Comments are stripped before matching. This module documents the very
# boundary it enforces, and matching our own prose would let the gate pass on
# the strength of a sentence describing the thing that went missing.
code_of() {
  local f
  f="$(target)"
  [ -f "$f" ] || fail "perception module missing: $f"
  sed -e 's://.*::' "$f"
}

# 1. No generating variant, and no generating entry point.
check_no_generation_surface() {
  local code
  code="$(code_of)"

  # Variants named for producing rather than consuming.
  if grep -qE '^\s*(Image|Video|Audio|Text)?(Output|Generation|Render|Synthesis)\b' <<<"$code"; then
    fail "PerceptionKind gained a generating variant.
  Lubot reads; it does not produce images or video. Generation needs its own
  economics, its own abuse model and an answer to who owns the output, and
  none of those are settled. Adding the variant commits the chain to all
  three by accident."
  fi

  # Functions that would produce media rather than admit a read.
  if grep -qE '\bpub (async )?fn [a-z_]*(generate|render|synthesi[sz]e|produce)_[a-z_]*(image|video|audio|frame)' <<<"$code"; then
    fail "the perception module gained a media-producing function.
  This module admits reads. A producing surface belongs to a different
  feature with different economics."
  fi
}

# 2. Every modality keeps its own ceiling, in its own unit.
check_per_modality_budget() {
  local code
  code="$(code_of)"

  for konst in MAX_TEXT_INPUT_BYTES MAX_IMAGE_INPUT_PIXELS \
               MAX_AUDIO_INPUT_MILLIS MAX_VIDEO_INPUT_FRAMES; do
    grep -q "$konst" <<<"$code" \
      || fail "$konst is gone.
  Each modality is bounded in the unit it is actually measured in. One shared
  ceiling would have to be bytes, which is wrong for three of the four."
  done

  grep -q 'fn perception_unit' <<<"$code" \
    || fail "perception_unit is gone: nothing names the unit a ceiling is expressed in,
  so an operator cannot be told which quota it exceeded."

  # The four names must be distinct, or the units have quietly merged.
  local units
  units="$(grep -A 8 'fn perception_unit' <<<"$code" \
    | grep -oE '"(bytes|pixels|milliseconds|frames)"' | sort -u | wc -l)"
  [ "$units" -eq 4 ] || fail "perception_unit reports $units distinct units, expected 4.
  If the units have collapsed, either text is overpriced or images are
  underpriced."
}

# 3. A model that declared nothing reads nothing.
check_fail_closed_default() {
  local code
  code="$(code_of)"

  grep -q 'fn none()' <<<"$code" \
    || fail "ModalitySet::none is gone: there is no way to express a model that reads nothing."

  grep -A 4 'fn none()' <<<"$code" | grep -q 'Self(0)' \
    || fail "ModalitySet::none no longer starts empty.
  The default has to fail closed: a model whose declaration was lost must
  stop working rather than accept every modality."

  grep -q 'ModalityNotDeclared' <<<"$code" \
    || fail "the undeclared-modality refusal is gone.
  A text model handed an image does not fail cleanly, it reads the bytes as
  text and answers confidently, which is worse than an error."
}

# 4. The decoder boundary is still stated.
check_decoder_boundary() {
  local code
  code="$(code_of)"

  grep -q 'fn needs_decoder' <<<"$code" \
    || fail "needs_decoder is gone.
  A decoder is where malformed input becomes unbounded work and where two
  operators can disagree about what an image contains. Anything built on top
  has to know which modalities cross that line."

  grep -A 4 'fn needs_decoder' <<<"$code" | grep -q 'Self::Text' \
    || fail "needs_decoder no longer singles out text.
  Text is the only modality that reaches a model without a decoding step."
}

run_all() {
  check_no_generation_surface
  check_per_modality_budget
  check_fail_closed_default
  check_decoder_boundary
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
    mkdir -p "$work/src/lubot"
    cp "$real_root/src/lubot/perception.rs" "$work/src/lubot/"
    sed -i "$sed_prog" "$work/src/lubot/perception.rs"

    ROOT="$work"
    if ( "$check" ) >/dev/null 2>&1; then
      ROOT="$real_root"
      echo "VACUOUS GATE: $label was not detected!" >&2
      exit 1
    fi
    ROOT="$real_root"
    canaries=$((canaries + 1))
  }

  # 1. The variant that looks like symmetry and is a new product.
  break_and_expect_failure \
    "a generating variant added beside the reading ones" \
    's|^\( *\)Video,|\1Video,\n\1ImageOutput,|' \
    check_no_generation_surface

  # 2. The same thing arriving as a function instead of a variant.
  break_and_expect_failure \
    "a media-producing entry point" \
    's|pub const fn perception_unit|pub fn generate_image_frame(\&self) -> u8 { 0 }\n    pub const fn perception_unit|' \
    check_no_generation_surface

  # 3. A ceiling disappears.
  break_and_expect_failure \
    "a modality with no ceiling" \
    's|MAX_VIDEO_INPUT_FRAMES|CANARY_REMOVED_frames|g' \
    check_per_modality_budget

  # 4. The units collapse into one.
  break_and_expect_failure \
    "units merged into a single measure" \
    's|"pixels"|"bytes"|; s|"milliseconds"|"bytes"|; s|"frames"|"bytes"|' \
    check_per_modality_budget

  # 5. The empty set stops being empty, so an undeclared model reads
  #    everything.
  break_and_expect_failure \
    "a default that fails open" \
    's|Self(0)|Self(u32::MAX)|' \
    check_fail_closed_default

  # 6. The undeclared-modality refusal is removed.
  break_and_expect_failure \
    "a model allowed to read a modality it never declared" \
    's|ModalityNotDeclared|CANARY_REMOVED_refusal|g' \
    check_fail_closed_default

  # 7. The decoder boundary is erased.
  break_and_expect_failure \
    "an erased decoder boundary" \
    's|fn needs_decoder|fn CANARY_REMOVED_decoder|' \
    check_decoder_boundary

  # 8. The boundary survives in name but stops distinguishing text.
  break_and_expect_failure \
    "a decoder boundary that no longer singles out text" \
    's|!matches!(self, Self::Text)|true|' \
    check_decoder_boundary

  # 9. The tree as committed must pass, or the gate rejects every pull
  #    request for reasons unrelated to its diff.
  run_all || { echo "BROKEN GATE: the committed tree was rejected!" >&2; exit 1; }

  echo "lubot perception gate self-test OK: $canaries canaries."
  echo "  A generating variant, a producing function, a missing ceiling,"
  echo "  merged units, a fail-open default, a dropped refusal and an erased"
  echo "  decoder boundary are all rejected; the tree as committed passes."
  exit 0
fi

run_all
echo "Lubot perception OK: reads text, images, audio and video frames; produces"
echo "  none of them. Each modality is bounded in its own unit, an undeclared"
echo "  modality is refused, and the decoder boundary is stated."
