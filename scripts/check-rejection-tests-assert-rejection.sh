#!/usr/bin/env bash
# ============================================================================
# check-rejection-tests-assert-rejection.sh - a test named for a rejection must
# assert one.
#
# A test name is a claim, and it is the claim a reader trusts when they are
# counting coverage rather than reading bodies. Three tests in this tree made a
# claim their bodies contradicted:
#
#   pow_empty_block_rejected_by_validation
#       asserted `result.is_some()` - that production *succeeded*. PoW does not
#       reject empty blocks at all; validate_block never looks at the
#       transaction list. The name described a rule the engine does not have.
#
#   pos_double_producer_address_rejected
#       asserted both blocks must succeed, with the comment "normal -
#       sequential". The name promised the double-sign case; the body asserted
#       the opposite and the real equivocation path went uncovered here.
#
#   import_qc_blob_rejects_empty_signature_set  (and three siblings)
#       never called import_qc_blob. They recomputed the quorum arithmetic
#       inline and compared it against `blob.pq_signatures.len()`. Deleting
#       import_qc_blob outright would have left all four green - and the raw
#       count they blessed is exactly what the production fix had stopped
#       trusting, because duplicate entries inflate it.
#
# That last one is the dangerous shape: the file header cites a security audit
# section, so the tests read as proof the finding was closed.
#
# This gate reads every `#[test]` whose name promises a refusal and requires
# the body to contain a matching negative assertion. It cannot tell whether the
# assertion is about the right thing - no static check can - but it does catch
# the case where there is no negative assertion at all, which is how all three
# of the above got in.
#
# Usage:
#   bash scripts/check-rejection-tests-assert-rejection.sh              # gate
#   bash scripts/check-rejection-tests-assert-rejection.sh --self-test  # canary
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Names that are allowed to promise a refusal without asserting one, each with
# the reason it is exempt. Empty on purpose: an entry here is a standing claim
# that a test named for a rejection is better off not checking one, which is a
# hard thing to argue. Anything added needs its reason in the same commit.
ALLOWED=()

# Trees to scan. `src/` is the L1; budzero and wallet-core carry 294 tests
# between them and were outside the first version of this gate for no reason
# other than that the three offenders happened to live in src/. A gate that
# only looks where the last bug was found is a gate that finds the last bug.
SCAN_ROOTS=(src budzero wallet-core)

scan() {
  local root="$1"
  [ -d "$root/src" ] || fail "no src directory at $root/src - wrong root?"

  python3 - "$root" "${SCAN_ROOTS[*]}" "${ALLOWED[@]+"${ALLOWED[@]}"}" <<'PY'
import os, re, sys

root = sys.argv[1]
scan_roots = sys.argv[2].split()
allowed = set(sys.argv[3:])

# A name promising that something does not go through.
# Deliberately narrower than "any name that sounds negative".
#
# The first draft matched `_cannot_`, `_unreachable` and `_stays_closed` too,
# and every single hit was a correct test written in an idiom the gate had not
# been taught: `..._cannot_exceed_...` pins a capped value, `..._stays_closed`
# asserts a config still says deny, `status_document_lists_...` reads a
# document. Widening the evidence pattern to cover them would have meant
# matching the word "cap" as proof of a refusal -- which makes the gate mean
# nothing.
#
# So the promise pattern only keeps the shapes where a body without a negative
# assertion is unambiguously wrong: a name saying something *was rejected,
# refused, denied or must fail*. That is exactly the set the three real
# offenders fell into, and it costs no coverage of them.
PROMISE = re.compile(
    r'\bfn\s+([a-z0-9_]*'
    r'(?:_reject(?:s|ed)?|_refus(?:e|es|ed)|_denied|_denies'
    r'|_is_not_accepted|_must_fail|_must_be_refused|_forbidden)'
    r'[a-z0-9_]*)\s*\('
)

# Evidence that the body actually checks a refusal.
#
# Deliberately broad. The first version of this gate only knew `is_err` and
# `assert!(!..)`, and flagged seventeen tests that were all doing the job
# properly in an idiom it had not been taught -- `matches!(result,
# Rejected(_))`, `assert_eq!(score, 0)` for a fork-choice refusal,
# `assert!(pm.is_banned(..))`, an unchanged value after a rejected proposal.
# A gate that cries wolf on correct code gets switched off, so the rule is:
# recognise every honest way to say "this did not go through", and only fail
# when the body contains no refusal-shaped assertion at all.
NEGATIVE = re.compile(
    # Result / Option refusals
    r'is_err\(\)|unwrap_err\(|expect_err\(|is_none\(\)|'
    r'\bErr\s*\(|matches!\s*\([^,]+,\s*(?:Err|None)|'
    # Explicitly negated or inequality assertions
    r'assert!\s*\(\s*!|assert_ne!|debug_assert!\s*\(\s*!|'
    # Panic-based refusals
    r'should_panic|catch_unwind|\.is_err\b|'
    # Status enums that name the refusal
    r'(?:Rejected|Refused|Denied|Invalid|Unauthorized|Forbidden|Expired|'
    r'NotAccepted|Slashed|Banned|Failed)\b|'
    # "nothing happened": a zero/empty/unchanged outcome is the refusal
    r'assert_eq!\s*\([^;]*?,\s*(?:0|false|None|vec!\[\]|"")\s*[,)]|'
    r'\.is_empty\(\)|is_banned\(|is_jailed\(|'
    # "nothing changed": the value is compared against a snapshot taken before
    # the attempt. This is how a refusal gets asserted when the operation
    # returns nothing observable -- a mint that did not happen, a proposal that
    # did not apply, a tip that was not paid. The snapshot may sit on either
    # side of the comparison, so the whole assertion is searched.
    r'assert_eq!\s*\([^;]*\b[a-z_]*(?:before|initial|unchanged|original|prior)\b|'
    # Policy locks. `_stays_closed` tests assert that a closed configuration is
    # still closed, and the natural way to write that is a positive
    # `contains("unknown-git = \"deny\"")`. Requiring a negation there would
    # mean rewriting a correct test to satisfy a regex.
    r'"deny"|stays_closed|must keep denying|'
    # Bound checks: `_cannot_exceed` is asserted by pinning the capped value.
    r'cannot_exceed|_cap\b|saturat',
    re.IGNORECASE,
)

scanned = 0
offenders = []

for sub in scan_roots:
  base = os.path.join(root, sub)
  if not os.path.isdir(base):
      continue
  for dirpath, dirs, files in os.walk(base):
    # Build output is not source.
    dirs[:] = [d for d in dirs if d not in ('target', '.git')]
    for name in files:
        if not name.endswith('.rs'):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        with open(path, encoding='utf-8', errors='replace') as fh:
            lines = fh.read().split('\n')

        for i, line in enumerate(lines):
            m = PROMISE.search(line)
            if not m:
                continue
            # Must be an actual test, not a helper or a production function.
            window = lines[max(0, i - 6):i]
            if not any('#[test]' in w for w in window):
                continue
            fn = m.group(1)
            if fn in allowed:
                continue
            scanned += 1

            # Body: from here to the next line that starts a sibling item at
            # the same or lower indentation.
            indent = len(line) - len(line.lstrip())
            body = []
            for j in range(i + 1, len(lines)):
                nxt = lines[j]
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent:
                    if re.match(r'\s*(fn |#\[|\}\s*$)', nxt):
                        break
                body.append(nxt)
            if not NEGATIVE.search('\n'.join(body)):
                offenders.append(f"{rel}:{i + 1}  {fn}")

if scanned == 0:
    print("FAIL: no test named for a rejection was found at all - the gate would be vacuous",
          file=sys.stderr)
    sys.exit(1)

if offenders:
    print("FAIL: these tests are named for a rejection but assert none:", file=sys.stderr)
    for o in offenders:
        print(f"  - {o}", file=sys.stderr)
    print(
        "\nA name is the claim a reader trusts when counting coverage. Either assert the\n"
        "refusal (is_err / unwrap_err / assert!(!..) / should_panic), or rename the test\n"
        "to what it actually checks.",
        file=sys.stderr)
    sys.exit(1)

print(f"Rejection-test gate OK: all {scanned} tests named for a refusal assert one.")
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  mk() {
    local dir="$1"; shift
    rm -rf "$dir"; mkdir -p "$dir/src"
    printf '%s\n' "$@" > "$dir/src/lib.rs"
  }

  # 1. The shape that shipped: a name promising rejection over a body asserting
  #    success.
  mk "$tmp/liar" \
    '#[test]' \
    'fn pow_empty_block_rejected_by_validation() {' \
    '    let result = produce();' \
    '    assert!(result.is_some(), "must succeed");' \
    '}'
  if ( scan "$tmp/liar" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a test named _rejected asserting is_some() was accepted!" >&2
    exit 1
  fi

  # 2. `_refuses` with a purely positive body must also fail.
  mk "$tmp/refuses" \
    '#[test]' \
    'fn the_chain_refuses_a_short_fork() {' \
    '    assert_eq!(chain.len(), 3);' \
    '}'
  if ( scan "$tmp/refuses" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a _refuses test with no negative assertion was accepted!" >&2
    exit 1
  fi

  # 3. A tree with no such tests must fail rather than pass for having no
  #    offenders - otherwise deleting every rejection test turns the gate green.
  mk "$tmp/none" \
    '#[test]' \
    'fn a_block_is_produced() {' \
    '    assert!(true);' \
    '}'
  if ( scan "$tmp/none" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no rejection tests at all was accepted!" >&2
    exit 1
  fi

  # 4. A missing src must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no src directory was accepted!" >&2
    exit 1
  fi

  # 5. A properly asserted rejection must pass.
  mk "$tmp/good" \
    '#[test]' \
    'fn import_rejects_an_empty_set() {' \
    '    let result = import(empty());' \
    '    assert!(result.is_err(), "must be refused");' \
    '}'
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a test that does assert its rejection was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    exit 1
  fi

  # 6. A non-test function whose name mentions rejection is not a test.
  mk "$tmp/notatest" \
    'fn rejects_everything() -> bool { false }' \
    '#[test]' \
    'fn import_rejects_an_empty_set() {' \
    '    assert!(import(empty()).is_err());' \
    '}'
  if ! ( scan "$tmp/notatest" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a plain function was treated as a test!" >&2
    exit 1
  fi

  # 7. assert!(!..) counts as a negative assertion.
  mk "$tmp/bang" \
    '#[test]' \
    'fn onboarding_rejects_below_floor_as_active() {' \
    '    assert!(!registry.is_active(&staker), "below floor must not be active");' \
    '}'
  if ! ( scan "$tmp/bang" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: assert!(!..) was not recognised as asserting a refusal!" >&2
    exit 1
  fi

  echo "rejection-test gate self-test OK: a _rejected test asserting success, a _refuses test with no negative assertion, a tree with no rejection tests and a missing src are all rejected; is_err and assert!(!..) pass and a plain function is ignored."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
