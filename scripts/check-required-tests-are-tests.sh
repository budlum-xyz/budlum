#!/usr/bin/env bash
# ============================================================================
# check-required-tests-are-tests.sh - a gate's required test must be a test.
#
# Eight gates name the tests they require by hand:
#
#   required_tests=(
#     total_bud_committed_counts_stake_and_unbonding
#     ...
#   )
#
# and then assert each name appears as passing in a `cargo test` log. That is
# a good gate, and it has one hole: it verifies the name RAN, by looking for
# it in the log. If the function loses its `#[test]` attribute, it never runs,
# never appears in the log, and the gate fails loudly - which is correct.
#
# But the reverse is not covered. A gate whose log-scan is satisfied for the
# wrong reason, or a required name that was never a test to begin with, or a
# name that is silently renamed on one side only, leaves the required list
# describing something the tree does not contain. The list becomes a document
# rather than a check.
#
# This actually happened. Merging the hardening branches moved a `#[test]`
# attribute onto the wrong function in `src/core/account.rs`:
#
#     #[test]
#     fn every_whitelisted_governance_parameter_can_be_applied() { ... }
#
#     fn total_bud_committed_counts_stake_and_unbonding() { ... }   <-- no attribute
#
# `total_bud_committed_counts_stake_and_unbonding` is a *required* name in
# `check-economy-invariants.sh`. It stopped being a test, so the supply-
# accounting invariant it pins stopped being checked. Only `-D dead-code`
# caught it, and only because nothing else called the function - a required
# test that happened to be called from somewhere would have gone unnoticed.
#
# So: every name in every `required_tests=(...)` must be attached to a
# `#[test]` or `#[tokio::test]` somewhere in the workspace.
#
# Scope is the whole workspace, not `src/`. `check-wallet-core-gate.sh` names
# 36 tests that live in `wallet-core/`, a separate crate; a scan rooted at
# `src/` reports all 36 as missing and is wrong 36 times.
#
# Usage:
#   bash scripts/check-required-tests-are-tests.sh              # gate
#   bash scripts/check-required-tests-are-tests.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-.}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Collect every function name carrying a test attribute, across every crate.
#
# The attribute and the `fn` are usually on adjacent lines but not always:
# `#[should_panic]`, `#[ignore]` or a doc line can sit between them, so this
# looks ahead a few lines rather than exactly one.
collect_marked_tests() {
  local root="$1"
  find "$root" -name '*.rs' \
    -not -path '*/target/*' \
    -not -path '*/.git/*' \
    -print0 \
  | xargs -0 awk '
      /#\[(tokio::)?test\]/ { pending = 5; next }
      pending > 0 {
        if (match($0, /fn [a-z_][a-z0-9_]*/)) {
          print substr($0, RSTART + 3, RLENGTH - 3)
          pending = 0
        } else {
          pending--
        }
      }
    ' | sort -u
}

# Pull the identifiers out of a `required_tests=( ... )` array.
# Only a line that is exactly `required_tests=(` opens a list, and only a line
# that is exactly `)` closes it. The loose version of this matched the string
# where it appears inside a comment - including in this file - and then ran to
# the end of the script collecting shell keywords as test names.
collect_required_names() {
  local script="$1"
  awk '
    /^[[:space:]]*required_tests=\([[:space:]]*$/ { inside = 1; next }
    inside && /^[[:space:]]*\)[[:space:]]*$/      { inside = 0; next }
    inside                                        { print $1 }
  ' "$script" | grep -E '^[a-z_][a-z0-9_]*$' || true
}

check_required() {
  local root="$1"
  local marked
  marked="$(collect_marked_tests "$root")"

  [ -n "$marked" ] || fail "no #[test] functions found under $root - wrong root?"

  local scripts_with_lists=0
  local total=0
  local missing_total=0
  local script name

  for script in "$root"/scripts/check-*.sh; do
    [ -e "$script" ] || continue
    local names
    names="$(collect_required_names "$script")"
    [ -n "$names" ] || continue
    scripts_with_lists=$((scripts_with_lists + 1))

    local missing=()
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      total=$((total + 1))
      if ! grep -qxF "$name" <<<"$marked"; then
        missing+=("$name")
      fi
    done <<<"$names"

    if [ "${#missing[@]}" -gt 0 ]; then
      echo "FAIL: $(basename "$script") requires tests that are not tests:" >&2
      printf '  - %s\n' "${missing[@]}" >&2
      missing_total=$((missing_total + ${#missing[@]}))
    fi
  done

  # Guard against the gate passing on a tree where it found nothing to check.
  [ "$scripts_with_lists" -gt 0 ] \
    || fail "no scripts/check-*.sh declares required_tests=() under $root - wrong root?"

  if [ "$missing_total" -gt 0 ]; then
    echo "" >&2
    echo "A name in required_tests=() that carries no #[test] attribute is a" >&2
    echo "gate describing a test the tree does not have. Restore the attribute," >&2
    echo "or remove the name and say why in the same commit." >&2
    exit 1
  fi

  echo "Required-test gate OK: $total required names across $scripts_with_lists gate scripts all carry #[test]."
}

self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap 'rm -rf "${SELF_TEST_TMP:-}"' EXIT
  local tmp="$SELF_TEST_TMP"

  mkdir -p "$tmp/scripts" "$tmp/src" "$tmp/other-crate/src"

  # Built with printf rather than a heredoc so this file does not itself
  # contain a literal `required_tests=(` list: the gate scans every
  # `scripts/check-*.sh`, including this one, and a fixture written in plain
  # text would be read as a real declaration.
  {
    printf 'required_tests=(\n'
    printf '  a_real_test\n'
    printf '  a_test_in_another_crate\n'
    printf ')\n'
  } > "$tmp/scripts/check-example-gate.sh"

  cat > "$tmp/src/lib.rs" <<'RS'
#[test]
fn a_real_test() {}
RS

  # A required test living in a second crate must count. A scan rooted at
  # `src/` would miss this and fail the whole tree, which is the mistake this
  # canary exists to keep out.
  cat > "$tmp/other-crate/src/lib.rs" <<'RS'
#[tokio::test]
async fn a_test_in_another_crate() {}
RS

  if ! (check_required "$tmp" >/dev/null 2>&1); then
    echo "FAIL: self-test could not make a correct tree pass" >&2
    exit 1
  fi

  # Drop the attribute off one required test - exactly the account.rs bug.
  cat > "$tmp/src/lib.rs" <<'RS'
fn a_real_test() {}
RS
  if (check_required "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a required name with no #[test] was accepted!" >&2
    exit 1
  fi

  # A tree with no test attributes at all must fail rather than pass empty.
  rm -f "$tmp/other-crate/src/lib.rs"
  if (check_required "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a tree with no tests was accepted!" >&2
    exit 1
  fi

  # And a tree where no gate declares a list must fail too, so the gate
  # cannot pass by finding nothing to check.
  cat > "$tmp/src/lib.rs" <<'RS'
#[test]
fn a_real_test() {}
RS
  rm -f "$tmp/scripts/check-example-gate.sh"
  if (check_required "$tmp" >/dev/null 2>&1); then
    echo "VACUOUS GATE: a tree with no required_tests=() was accepted!" >&2
    exit 1
  fi

  echo "Required-test gate self-test OK: a stripped attribute, an empty tree and a listless tree are all rejected; a two-crate tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

check_required "${1:-$ROOT}"
