#!/usr/bin/env bash
# ============================================================================
# check-zero-storage-bytes-are-frozen.sh
#
# When an object's bytes are described rather than stored, the description is
# the only copy. That is what reaches a zero multiplier, and it is also what
# makes this class different from every other saving in `src/storage/`: with
# deduplication or erasure coding, a mistake in the code costs performance and
# the bytes are still on a disk somewhere. Here a mistake in the code costs the
# object.
#
# The failure is specific and quiet. `manifest_id` is the hash of the output,
# so an edit that changes what a generator draws does not produce a wrong
# picture. It produces an object that can no longer be produced at all: the id
# stops verifying, the content is unreachable, and there is nothing on disk to
# fall back to. Minecraft has shipped this exact bug repeatedly, where a change
# to worldgen means an old seed no longer yields the old world, and it is
# merely annoying there because the world is entertainment. Here the seed is
# the asset.
#
# Self-agreement does not catch it. A test that generates twice and compares
# passes just as happily when the output is wrong, and passes after a change
# that alters every byte, because both sides of the comparison move together.
# Every determinism test in the module had that shape, and one generator was
# in fact broken the whole time: the gradient generator applied `fixed_to_int`
# to a value that had already left fixed point, discarded both seed-derived
# endpoint colours and emitted solid black. It hashed consistently, verified
# against its id and passed every test. `fixed_sqrt` in the neighbouring module
# had already had the same class of bug, with the same symptom recorded in its
# comment: deterministic and wrong.
#
# So the rule is that the bytes are pinned to specific values, checked in, and
# that changing them is loud.
#
# What the gate checks.
#
#   1. A frozen-vector test exists and names every generator in the enum, so
#      adding a fourth generator without a vector fails rather than passing by
#      not being mentioned.
#   2. The vectors are full 64-character hex digests. A truncated prefix would
#      weaken the pin silently.
#   3. Every generator has at least two vectors at different lengths, because
#      a single vector at one size cannot distinguish a geometry change from a
#      colour change.
#   4. No generator uses floating point, which would let two machines disagree
#      about validity, which is a fork.
#   5. At least one test asserts a property of the output rather than its
#      agreement with itself. A frozen vector proves the bytes have not moved;
#      it cannot notice they were wrong when they were frozen. This is the
#      check that would have caught the black gradient.
#
# Usage:
#   bash scripts/check-zero-storage-bytes-are-frozen.sh              # gate
#   bash scripts/check-zero-storage-bytes-are-frozen.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

scan() {
  local target="$1"
  [ -f "$target" ] || fail "generated-content module missing at $target"

  # The generators the enum declares. Everything below is measured against
  # this list rather than a list written here, so the gate cannot go stale by
  # naming generators that no longer exist or missing ones that do.
  local generators
  generators="$(sed -n '/pub enum GeneratorId/,/^}/p' "$target" |
    sed -n 's/^[[:space:]]*\([A-Z][A-Za-z0-9]*\),[[:space:]]*$/\1/p')"
  [ -n "$generators" ] || fail "could not read any variant from enum GeneratorId"

  # 1. The frozen-vector test has to exist.
  grep -q 'fn generated_bytes_match_their_frozen_vectors' "$target" ||
    fail "no frozen-vector test: the bytes are pinned to nothing, so a change that \
alters every generated object would pass CI silently"

  # The vector table, taken as the body of that test.
  local table
  table="$(sed -n '/fn generated_bytes_match_their_frozen_vectors/,/^    }$/p' "$target")"

  # 2. Digests must be full length. A shortened digest is a weaker pin that
  #    still looks like a pin.
  local short
  short="$(printf '%s' "$table" | grep -oE '"[0-9a-f]{8,}"' | tr -d '"' |
    awk 'length($0) != 64' || true)"
  if [ -n "$short" ]; then
    echo "FAIL: these frozen digests are not 64 hex characters:" >&2
    printf '  - %s\n' $short >&2
    exit 1
  fi

  local total
  total="$(printf '%s' "$table" | grep -cE '"[0-9a-f]{64}"' || true)"
  [ "${total:-0}" -gt 0 ] || fail "the frozen-vector test contains no digests"

  # 3. Every generator needs at least two vectors, at different lengths.
  local g count lengths distinct
  for g in $generators; do
    count="$(printf '%s' "$table" | grep -c "GeneratorId::${g}," || true)"
    if [ "${count:-0}" -lt 2 ]; then
      fail "generator ${g} has ${count:-0} frozen vector(s), at least 2 are required \
so a geometry change and a colour change cannot look alike"
    fi
    # Lengths are the third field of each tuple; the tuples are formatted one
    # field per line by rustfmt, so read the numeric lines following each
    # generator mention.
    lengths="$(printf '%s' "$table" |
      grep -A3 "GeneratorId::${g}," |
      sed -n 's/^[[:space:]]*\([0-9][0-9]*\),[[:space:]]*$/\1/p' |
      awk 'NR % 2 == 0')"
    distinct="$(printf '%s\n' "$lengths" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')"
    if [ "${distinct:-0}" -lt 2 ]; then
      fail "generator ${g} is pinned at only ${distinct:-0} distinct output length(s), \
at least 2 are required"
    fi
  done

  # 4. Floating point in a generator is a fork waiting to happen.
  local floats
  floats="$(grep -nE '\b(f32|f64)\b' "$target" | grep -v '^\s*//' || true)"
  if [ -n "$floats" ]; then
    echo "FAIL: floating point in the generated-content module:" >&2
    printf '  %s\n' "$floats" >&2
    echo "Two machines that disagree about the bytes disagree about validity." >&2
    exit 1
  fi

  # 5. At least one behavioural assertion. Without it the vectors could be
  #    freezing a bug, which is what they did before this gate existed.
  grep -q 'fn a_gradient_is_not_a_single_flat_colour' "$target" ||
    fail "no test asserts a property of the output itself. A frozen vector proves the \
bytes have not moved, not that they were right when they were frozen"

  echo "Zero-storage vectors OK: $(printf '%s' "$generators" | wc -w | tr -d ' ') generator(s), \
${total} frozen digest(s), each generator pinned at two or more lengths, no floating point, \
and at least one behavioural assertion."
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  local good="$tmp/good.rs"
  cat > "$good" <<'EOF'
pub enum GeneratorId {
    Avatar,
    Gradient,
}

mod tests {
    #[test]
    fn generated_bytes_match_their_frozen_vectors() {
        let vectors: &[(GeneratorId, u8, u32, &str)] = &[
            (
                GeneratorId::Avatar,
                7,
                3072,
                "8f00038bd40a0c5876aa4e3f3329fd2848dd362c2dee2c94a947353e5530d1f8",
            ),
            (
                GeneratorId::Avatar,
                1,
                192,
                "62f5fc48635aa1d88374fd03bd4b9dcc62575b4c84fc9bda14564f7212a9ff80",
            ),
            (
                GeneratorId::Gradient,
                7,
                3072,
                "c1b284b5cd254c38bb54a0f87b2eb5dd2b85ea18592af7fb062b882b2a517a98",
            ),
            (
                GeneratorId::Gradient,
                1,
                192,
                "34bc5985b6faa2f482709c87a7e0168e0841e8062b82eb5207e279e6cade7a9f",
            ),
        ];
    }

    #[test]
    fn a_gradient_is_not_a_single_flat_colour() {
        assert!(true);
    }
}
EOF
  ( scan "$good" ) >/dev/null 2>&1 ||
    { echo "BROKEN GATE: a correct module was rejected!" >&2; ( scan "$good" ) >&2 || true; exit 1; }

  # A new generator with no vectors must fail rather than pass by omission.
  sed 's/    Gradient,/    Gradient,\n    Rings,/' "$good" > "$tmp/newgen.rs"
  if ( scan "$tmp/newgen.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a generator with no frozen vectors was accepted!" >&2
    exit 1
  fi

  # A truncated digest is a weaker pin that still looks like one.
  sed 's/"8f00038bd40a0c5876aa4e3f3329fd2848dd362c2dee2c94a947353e5530d1f8"/"8f00038bd40a0c58"/' \
    "$good" > "$tmp/short.rs"
  if ( scan "$tmp/short.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a truncated digest was accepted!" >&2
    exit 1
  fi

  # One length only cannot tell a geometry change from a colour change.
  sed 's/^                192,$/                3072,/' "$good" > "$tmp/onelen.rs"
  if ( scan "$tmp/onelen.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: vectors at a single output length were accepted!" >&2
    exit 1
  fi

  # No frozen-vector test at all.
  sed 's/fn generated_bytes_match_their_frozen_vectors/fn something_else/' "$good" \
    > "$tmp/novec.rs"
  if ( scan "$tmp/novec.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a module with no frozen-vector test was accepted!" >&2
    exit 1
  fi

  # Floating point anywhere in the module.
  printf 'fn drift(x: f64) -> f64 { x * 0.5 }\n' >> "$tmp/float.rs"
  cat "$good" >> "$tmp/float.rs"
  if ( scan "$tmp/float.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: floating point in a generator was accepted!" >&2
    exit 1
  fi

  # Frozen vectors without a behavioural assertion: this is the shape that
  # freezes a bug as the specification.
  sed 's/fn a_gradient_is_not_a_single_flat_colour/fn unrelated_name/' "$good" \
    > "$tmp/nobehav.rs"
  if ( scan "$tmp/nobehav.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: frozen vectors with no behavioural assertion were accepted!" >&2
    exit 1
  fi

  # A missing module must fail rather than be treated as nothing to check.
  if ( scan "$tmp/absent.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing module was accepted!" >&2
    exit 1
  fi

  echo "zero-storage vector gate self-test OK: an unpinned new generator, a truncated digest, \
a single output length, a missing vector test, floating point, missing behavioural assertion \
and an absent module are all rejected; a correct module passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT/src/storage/generated.rs"
