#!/usr/bin/env bash
# ============================================================================
# check-reduction-claims-state-both-units.sh
#
# A storage saving stated in one unit is not a smaller claim than one stated
# in both. It is a different claim, and usually the wrong one.
#
# Measured, on a published crawl of a comparable content-addressed network
# (Trautwein et al., ACM POMACS 2024): NFT metadata JSON is 40.2% of the files
# and 0.09% of the bytes. A factor of 447 between the two units, on the same
# corpus. Storage is billed in bytes.
#
# This tree carried levers weighted by the wrong unit for several rounds. The
# individual measurements were all correct: the shared dictionary really does
# save 49% to 92% on small structured objects, deduplication really does reach
# 67% on templated corpora. What was wrong was their weight. Reweighted by
# volume the whole-corpus figure is a 72.6% reduction, below the pessimistic
# end of the 74.8%-93.3% range that had been quoted, and the range was wide
# only because the weights were guesses.
#
# So: "40% of your objects are stored free" and "0.1% of your bytes are stored
# free" are the same measurement. Each alone misleads a reader, in opposite
# directions. This gate requires that a document making one kind of claim
# makes the other in the same document, and that the code reporting a saving
# returns both numbers rather than a ratio.
#
# It is deliberately narrow. It does not try to parse claims or check
# arithmetic; it checks that the two units travel together, which is the part
# that was actually going wrong.
#
# Usage:
#   bash scripts/check-reduction-claims-state-both-units.sh              # gate
#   bash scripts/check-reduction-claims-state-both-units.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Documents that discuss storage savings and are read by someone deciding
# whether to trust the numbers.
CLAIM_DOCS=(
  "docs/BUD_STORAGE_ROADMAP.md"
)

# Does this text talk about a share of objects/files?
mentions_object_unit() {
  grep -qiE '(share of (files|objects))|((files|objects)[^.]{0,40}%)|(% of (the )?(files|objects))' "$1"
}

# Does it talk about a share of bytes/volume?
mentions_byte_unit() {
  grep -qiE '(share of (bytes|volume))|((bytes|volume)[^.]{0,40}%)|(% of (the )?(bytes|volume))|(billed in bytes)' "$1"
}

# 1. A document that quantifies objects must also quantify bytes.
check_docs_state_both_units() {
  local doc path
  for doc in "${CLAIM_DOCS[@]}"; do
    path="$ROOT/$doc"
    [ -f "$path" ] || fail "claim document missing: $path"

    if mentions_object_unit "$path" && ! mentions_byte_unit "$path"; then
      fail "$doc quantifies a share of objects and never a share of bytes.
  Measured: the same corpus is 40.2% of files and 0.09% of bytes for one
  class. Storage is billed in bytes, so the object figure alone overstates
  the saving by up to a factor of 447."
    fi

    if mentions_byte_unit "$path" && ! mentions_object_unit "$path"; then
      fail "$doc quantifies a share of bytes and never a share of objects.
  The byte figure alone understates how much of what a user uploads is
  covered. Both units or neither."
    fi
  done
}

# 2. The measurement that produced the rule has to stay in the document that
#    states the rule, or the rule is an assertion.
check_the_measurement_is_recorded() {
  local path="$ROOT/docs/BUD_STORAGE_ROADMAP.md"
  [ -f "$path" ] || fail "roadmap missing: $path"

  grep -q '10.1145/3656015' "$path" \
    || fail "the corpus composition measurement has no citation in the roadmap.
  The rule this gate enforces rests on a specific published crawl. Without
  the reference the rule is an assertion, and the next person to reweight
  the numbers has nothing to check them against."

  grep -qE '\b447\b' "$path" \
    || fail "the roadmap no longer records the size of the discrepancy.
  447 is the factor between the two units for one class, and it is the whole
  reason this rule exists."

  # The factor has to follow from the table above it, not merely appear.
  #
  # Checking that the string 447 is present says nothing about whether the
  # two percentages it divides still say what they said. The same shape of
  # hole let a wrongly scaled rate through check-threshold-rates-share-one-
  # scale.sh: that gate grepped for the correct number, found it in one
  # place, and never looked at the others. So this one recomputes.
  local json_row files_pct bytes_pct factor
  json_row="$(grep -m1 -E '^\| *JSON' "$path" || true)"
  [ -n "$json_row" ] \
    || fail "the corpus table has no JSON row.
  The 447 the rule rests on is the ratio of that row's two percentages, and
  without the row the number is an assertion."

  files_pct="$(printf '%s' "$json_row" | awk -F'|' '{gsub(/[ %]/,"",$3); print $3}')"
  bytes_pct="$(printf '%s' "$json_row" | awk -F'|' '{gsub(/[ %]/,"",$4); print $4}')"

  case "$files_pct" in ''|*[!0-9.]*) fail "the JSON row's file share is not a number: '$files_pct'";; esac
  case "$bytes_pct" in ''|*[!0-9.]*) fail "the JSON row's byte share is not a number: '$bytes_pct'";; esac
  [ "$(awk -v b="$bytes_pct" 'BEGIN{print (b>0)?1:0}')" = "1" ] \
    || fail "the JSON row's byte share is zero, so there is no ratio to state."

  factor="$(awk -v f="$files_pct" -v b="$bytes_pct" 'BEGIN{printf "%.0f", f/b}')"
  [ "$factor" = "447" ] \
    || fail "the roadmap states a factor of 447 but its own table divides to $factor.
  The JSON row reads $files_pct% of files against $bytes_pct% of bytes. One of the
  two was edited without the other, and a reader checking the arithmetic finds
  the document disagreeing with itself. Whichever is right, both have to say it."
}

# 3. Code that reports a saving returns both numbers.
check_code_reports_a_pair() {
  local f="$ROOT/src/storage/derived.rs"
  [ -f "$f" ] || fail "derived content module missing: $f"

  local code
  code="$(sed -e 's://.*::' "$f")"
  grep -q 'fn stored_versus_independent' <<<"$code" \
    || fail "stored_versus_independent is gone.
  It is the one place in the tree that reports a storage saving to a caller,
  and it returns a pair so the caller cannot quote a ratio by accident."

  grep -A 4 'fn stored_versus_independent' <<<"$code" | grep -qE '\(u64, u64\)' \
    || fail "stored_versus_independent no longer returns a pair."
}

run_all() {
  check_docs_state_both_units
  check_the_measurement_is_recorded
  check_code_reports_a_pair
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  real_root="$ROOT"
  canaries=0

  stage() {
    local work="$tmp/work"
    rm -rf "$work"
    mkdir -p "$work/docs" "$work/src/storage"
    cp "$real_root/docs/BUD_STORAGE_ROADMAP.md" "$work/docs/"
    cp "$real_root/src/storage/derived.rs" "$work/src/storage/"
    echo "$work"
  }

  expect_failure() {
    local label="$1" check="$2" work="$3"
    ROOT="$work"
    if ( "$check" ) >/dev/null 2>&1; then
      ROOT="$real_root"
      echo "VACUOUS GATE: $label was not detected!" >&2
      exit 1
    fi
    ROOT="$real_root"
    canaries=$((canaries + 1))
  }

  # 1. A document that counts objects and never bytes: the claim shape that
  #    was actually being made here.
  work="$(stage)"
  cat > "$work/docs/BUD_STORAGE_ROADMAP.md" <<'DOC'
# Roadmap
Generated and derived content covers 40% of the objects a user uploads,
so most of what you store costs nothing.
DOC
  expect_failure "an objects-only claim" check_docs_state_both_units "$work"

  # 2. The mirror image: bytes with no object figure. Wrong in the other
  #    direction, and just as much a half-truth.
  work="$(stage)"
  cat > "$work/docs/BUD_STORAGE_ROADMAP.md" <<'DOC'
# Roadmap
The free classes are 0.1% of the bytes, so this lever is not worth having.
DOC
  expect_failure "a bytes-only claim" check_docs_state_both_units "$work"

  # 3. The citation goes, leaving the rule as an assertion.
  work="$(stage)"
  sed -i 's|10.1145/3656015|CANARY_no_citation|' "$work/docs/BUD_STORAGE_ROADMAP.md"
  expect_failure "a rule with no measurement behind it" \
    check_the_measurement_is_recorded "$work"

  # 4. The discrepancy figure goes, which is what makes the rule non-obvious.
  work="$(stage)"
  sed -i 's|\b447\b|several|g' "$work/docs/BUD_STORAGE_ROADMAP.md"
  expect_failure "a rule with the discrepancy erased" \
    check_the_measurement_is_recorded "$work"

  # 5. The reporting function collapses to a single number.
  work="$(stage)"
  sed -i 's|fn stored_versus_independent|fn CANARY_removed|' "$work/src/storage/derived.rs"
  expect_failure "a saving reported as one number" check_code_reports_a_pair "$work"

  # 6. It keeps its name but stops returning a pair, which is the drift
  #    version of the same defect.
  work="$(stage)"
  sed -i 's|-> (u64, u64)|-> u64|' "$work/src/storage/derived.rs"
  expect_failure "a reporting function that stopped returning a pair" \
    check_code_reports_a_pair "$work"

  # 7. The table is edited and the factor is not. This is the case the gate
  #    used to pass: 447 is still in the document, the row it comes from now
  #    divides to 4, and the two contradict each other.
  work="$(stage)"
  sed -i '/^| *JSON/s#0\.09%#9.0%#' "$work/docs/BUD_STORAGE_ROADMAP.md"
  expect_failure "a factor that no longer follows from its own table" \
    check_the_measurement_is_recorded "$work"

  # 8. The mirror image: the table stands and the factor is edited.
  work="$(stage)"
  sed -i 's|factor of 447\.|factor of 999.|' "$work/docs/BUD_STORAGE_ROADMAP.md"
  expect_failure "a factor edited away from its own table" \
    check_the_measurement_is_recorded "$work"

  # 9. The row disappears, leaving the factor with nothing behind it.
  work="$(stage)"
  sed -i '/^| *JSON/d' "$work/docs/BUD_STORAGE_ROADMAP.md"
  expect_failure "a factor with no table row behind it" \
    check_the_measurement_is_recorded "$work"

  # 10. A document that states both units must PASS, or the gate is just a
  #     ban on discussing savings.
  work="$(stage)"
  cat > "$work/docs/BUD_STORAGE_ROADMAP.md" <<'DOC'
# Roadmap
See DOI 10.1145/3656015: one class is 40.2% of the files and 0.09% of the
bytes, a factor of 447. Storage is billed in bytes.
DOC
  ROOT="$work"
  if ! ( check_docs_state_both_units ) >/dev/null 2>&1; then
    ROOT="$real_root"
    echo "BROKEN GATE: a claim stating both units was rejected!" >&2
    exit 1
  fi
  ROOT="$real_root"

  # 11. The tree as committed must pass.
  run_all || { echo "BROKEN GATE: the committed tree was rejected!" >&2; exit 1; }

  echo "reduction claim gate self-test OK: $canaries canaries."
  echo "  An objects-only claim, a bytes-only claim, a missing citation, an"
  echo "  erased discrepancy, a factor that no longer divides out of its own"
  echo "  table, a factor edited away from a correct table, a missing table row,"
  echo "  a deleted reporting function and one that stopped returning a pair are"
  echo "  all rejected; a claim stating both units passes, and so does the tree"
  echo "  as committed."
  exit 0
fi

run_all
echo "Reduction claims OK: the documents state both units, the measurement"
echo "  behind the rule is cited, and the code reports a saving as a pair."
