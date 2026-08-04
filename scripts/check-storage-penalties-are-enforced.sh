#!/usr/bin/env bash
# ============================================================================
# check-storage-penalties-are-enforced.sh
#
# A penalty recorded and never checked is not a penalty.
#
# Why this gate exists.
#
# Two rules were added to the storage layer, and both have the same failure
# mode: the data can exist, the tests can pass, and nothing on the path an
# operator actually walks ever consults it.
#
#   * An operator that misses a challenge sits out six hours. The record lives
#     in `StorageRegistry.operator_cooldowns`; the check has to happen in
#     `open_storage_deal_with_escrow`, because that is the layer that knows
#     wall time. A cooldown written and never read is a map that costs every
#     node storage and protects nobody.
#
#   * A mobile operator may hold a second or third copy and never the first.
#     The class lives in `StorageRegistry.operator_classes`; the check belongs
#     in `open_deal`, next to the other reasons a deal is refused.
#
# This is the `capability-modules-are-wired` problem in miniature, and it has
# bitten this tree before: `mobile_self.rs` held the rule that critical
# content needs a paid replica, had tests, and was never called.
#
# What the gate checks.
#
#   1. The cooldown is in seconds, not epochs. An epoch here is
#      `slot_duration_secs * epoch_length_slots`, both governance parameters,
#      so a punishment written as "67 epochs" silently becomes four hours or
#      twelve the next time either is tuned.
#   2. It really is six hours.
#   3. `begin_operator_cooldown` extends and never shortens. A replayed or
#      reordered failure carrying an older timestamp must not pull the
#      deadline in.
#   4. There is a prune. The map is hashed into the state root, so without one
#      it grows with every failure the network ever saw.
#   5. Both maps reach `root()`. They decide who may open a deal, so two nodes
#      disagreeing about them would accept different blocks.
#   6. The cooldown is enforced where wall time is known.
#   7. The primary-replica rule is enforced in `open_deal`.
#   8. The named regressions exist and are real `#[test]` functions.
#
# Usage:
#   bash scripts/check-storage-penalties-are-enforced.sh
#   bash scripts/check-storage-penalties-are-enforced.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
deal = os.path.join(root, "src", "domain", "storage_deal.rs")
chain = os.path.join(root, "src", "chain", "blockchain.rs")

for path in (deal, chain):
    if not os.path.isfile(path):
        print(f"FAIL: expected source file missing: {path}", file=sys.stderr)
        sys.exit(2)


def strip_comments(src):
    return re.sub(r"//[^\n]*", "", src)


def body_of(src, header_re):
    m = re.search(header_re, src)
    if not m:
        return None
    i = src.index("{", m.end() - 1) if "{" not in m.group(0) else m.end() - 1
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
        j += 1
    return None


deal_src = open(deal, encoding="utf-8").read()
deal_code = strip_comments(deal_src)
chain_code = strip_comments(open(chain, encoding="utf-8").read())

problems = []
checked = 0

# 1/2. The cooldown is in seconds and is six hours.
checked += 1
m = re.search(
    r"pub const MISSED_CHALLENGE_COOLDOWN_SECS\s*:\s*u64\s*=\s*([^;]+);", deal_code
)
if not m:
    problems.append(
        "no `MISSED_CHALLENGE_COOLDOWN_SECS`. The cooldown must be a named "
        "constant in seconds; an epoch is two governance parameters "
        "multiplied together, so a punishment counted in epochs changes "
        "length whenever either is tuned."
    )
else:
    checked += 1
    expr = m.group(1).strip()
    try:
        value = eval(expr, {"__builtins__": {}}, {})
    except Exception:
        value = None
    if value != 6 * 60 * 60:
        problems.append(
            f"`MISSED_CHALLENGE_COOLDOWN_SECS` is `{expr}`, which is not six "
            "hours (21600 seconds). If the policy changed, change this gate "
            "in the same commit so the number stays deliberate."
        )

# 3. Extending, never shortening.
checked += 1
begin = body_of(deal_code, r"pub fn begin_operator_cooldown\s*\(")
if begin is None:
    problems.append("no `begin_operator_cooldown`; nothing records the penalty.")
elif ".max(" not in begin:
    problems.append(
        "`begin_operator_cooldown` does not take the later of the existing "
        "deadline and the new one. A failure replayed with an older timestamp "
        "would then shorten a running cooldown, so failing twice would cost "
        "less than failing once."
    )

# 4. The map is bounded.
checked += 1
if not re.search(r"fn prune_expired_cooldowns\s*\(", deal_code):
    problems.append(
        "no `prune_expired_cooldowns`. The map is hashed into the state root, "
        "so without a prune every node pays storage forever to remember a "
        "six-hour punishment."
    )

# 5. Both maps reach the state root.
checked += 1
root_fn = body_of(deal_code, r"pub fn root\s*\(")
if root_fn is None:
    problems.append("cannot find `StorageRegistry::root` to check what it commits to.")
else:
    for field in ("operator_cooldowns", "operator_classes"):
        checked += 1
        if field not in root_fn:
            problems.append(
                f"`root()` does not hash `{field}`. It decides who may open a "
                "deal, so two nodes disagreeing about it would accept "
                "different blocks."
            )

# 6. The cooldown is enforced where wall time is known.
checked += 1
escrow = body_of(chain_code, r"pub fn open_storage_deal_with_escrow\s*\(")
if escrow is None:
    problems.append(
        "cannot find `open_storage_deal_with_escrow`. If it was renamed, "
        "update this gate in the same commit so the enforcement stays watched."
    )
elif "operator_cooldown_until" not in escrow:
    problems.append(
        "`open_storage_deal_with_escrow` never calls "
        "`operator_cooldown_until`. The cooldown would be recorded, hashed "
        "into the state root, and never once stop anybody."
    )
else:
    # Calling it is not the same as asking about the right operator. A call
    # that passes a placeholder address, or a zero timestamp, satisfies every
    # name-based check and lets every operator through.
    checked += 1
    call = re.search(
        r"operator_cooldown_until\s*\(([^)]*)\)", escrow, re.S
    )
    if call is None:
        problems.append(
            "`operator_cooldown_until` appears in "
            "`open_storage_deal_with_escrow` but not as a call this gate can "
            "read. Keep it a direct call so its arguments stay checkable."
        )
    else:
        args = call.group(1)
        if "operator" not in args:
            problems.append(
                "`open_storage_deal_with_escrow` asks about somebody other "
                "than the operator opening the deal. Every operator would "
                "pass. The first argument has to be `&operator`."
            )
        if not re.search(r"now|unix|secs", args):
            problems.append(
                "`open_storage_deal_with_escrow` does not pass a current "
                "timestamp to `operator_cooldown_until`. A fixed or zero "
                "time reports every cooldown as expired."
            )

# 7. The primary-replica rule is enforced.
checked += 1
open_deal = body_of(deal_code, r"pub fn open_deal\s*\(")
if open_deal is None:
    problems.append("cannot find `StorageRegistry::open_deal`.")
else:
    checked += 1
    if "may_hold_primary" not in open_deal:
        problems.append(
            "`open_deal` does not call `may_hold_primary`. A phone could then "
            "take `replica_index = 0`, which is the copy a reader reaches "
            "first and a repair rebuilds from."
        )
    checked += 1
    if "replica_index == 0" not in open_deal:
        problems.append(
            "`open_deal` does not single out `replica_index == 0`. The rule is "
            "about the primary specifically: a mobile operator may hold a "
            "second or third copy, and a check that refuses every replica is a "
            "ban on mobile storage rather than the rule."
        )

# 8. The regressions exist as real tests.
checked += 1
for test in (
    "a_missed_challenge_locks_the_operator_out_for_six_hours",
    "the_cooldown_lifts_when_it_expires",
    "a_second_failure_never_shortens_a_running_cooldown",
    "expired_cooldowns_are_pruned",
    "a_cooldown_changes_the_registry_root",
    "a_mobile_operator_cannot_take_the_primary_replica",
    "a_mobile_operator_may_take_a_secondary_replica",
    "an_undeclared_operator_defaults_to_always_on",
    "a_declared_class_changes_the_registry_root",
):
    if not re.search(
        r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + test + r"\s*\(", deal_src
    ):
        problems.append(f"required regression test `{test}` is missing or is not a `#[test]`.")

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(f"storage penalty gate OK: {checked} checks, both rules are enforced")
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

  # Fixtures come from python: the test bodies contain `#[test]`, and bash
  # expands `[` as a glob inside `${var//pattern/...}`, so a substitution
  # there silently does nothing and the canary asserts against an unmodified
  # fixture.
  build() {
    python3 - "$1" "$2" <<'PYB'
import os
import sys

root, mode = sys.argv[1], sys.argv[2]
for sub in ("src/domain", "src/chain"):
    os.makedirs(os.path.join(root, sub), exist_ok=True)

const = "pub const MISSED_CHALLENGE_COOLDOWN_SECS: u64 = 6 * 60 * 60;"
if mode == "epochs":
    const = "pub const MISSED_CHALLENGE_COOLDOWN_EPOCHS: u64 = 67;"
elif mode == "wrong_length":
    const = "pub const MISSED_CHALLENGE_COOLDOWN_SECS: u64 = 60;"

begin = """    pub fn begin_operator_cooldown(&mut self, o: Address, now: u64) -> u64 {
        let until = now + MISSED_CHALLENGE_COOLDOWN_SECS;
        let e = self.operator_cooldowns.entry(o).or_insert(until);
        *e = (*e).max(until);
        *e
    }
"""
if mode == "shortens":
    begin = """    pub fn begin_operator_cooldown(&mut self, o: Address, now: u64) -> u64 {
        let until = now + MISSED_CHALLENGE_COOLDOWN_SECS;
        self.operator_cooldowns.insert(o, until);
        until
    }
"""

prune = """    pub fn prune_expired_cooldowns(&mut self, now: u64) -> usize { 0 }
"""
if mode == "no_prune":
    prune = ""

root_fn = """    pub fn root(&self) -> [u8; 32] {
        for (o, u) in &self.operator_cooldowns { hash(o, u); }
        for (o, c) in &self.operator_classes { hash(o, c); }
        [0u8; 32]
    }
"""
if mode == "root_misses_cooldown":
    root_fn = """    pub fn root(&self) -> [u8; 32] {
        for (o, c) in &self.operator_classes { hash(o, c); }
        [0u8; 32]
    }
"""

od_checks = """        if replica_index == 0 && !self.operator_class(&operator).may_hold_primary() {
            return Err(StorageError::MobileOperatorCannotHoldPrimary(operator));
        }
"""
if mode == "no_primary_rule":
    od_checks = ""
elif mode == "bans_all_replicas":
    od_checks = """        if !self.operator_class(&operator).may_hold_primary() {
            return Err(StorageError::MobileOperatorCannotHoldPrimary(operator));
        }
"""

tests = ""
names = [
    "a_missed_challenge_locks_the_operator_out_for_six_hours",
    "the_cooldown_lifts_when_it_expires",
    "a_second_failure_never_shortens_a_running_cooldown",
    "expired_cooldowns_are_pruned",
    "a_cooldown_changes_the_registry_root",
    "a_mobile_operator_cannot_take_the_primary_replica",
    "a_mobile_operator_may_take_a_secondary_replica",
    "an_undeclared_operator_defaults_to_always_on",
    "a_declared_class_changes_the_registry_root",
]
if mode == "missing_test":
    names = names[:-1]
for n in names:
    tests += "#[test]\nfn %s() {}\n" % n

open(os.path.join(root, "src/domain/storage_deal.rs"), "w").write(
    "%s\nimpl StorageRegistry {\n%s%s%s"
    "    pub fn open_deal(&mut self) -> Result<u64, StorageError> {\n%s        Ok(0)\n    }\n}\n%s"
    % (const, begin, prune, root_fn, od_checks, tests)
)

enforce = "self.state.storage_registry.operator_cooldown_until(&operator, now_unix)"
if mode == "unenforced":
    enforce = "None::<u64>"
elif mode == "wrong_operator":
    # Calls the right function about the wrong address: every operator passes.
    enforce = "self.state.storage_registry.operator_cooldown_until(&Address::zero(), now_unix)"
elif mode == "frozen_clock":
    # Asks at time zero, so every cooldown reads as already expired.
    enforce = "self.state.storage_registry.operator_cooldown_until(&operator, 0)"
open(os.path.join(root, "src/chain/blockchain.rs"), "w").write(
    "impl Blockchain {\n"
    "    pub fn open_storage_deal_with_escrow(&mut self) -> Result<u64, String> {\n"
    "        let c = %s;\n        Ok(0)\n    }\n}\n" % enforce
)
PYB
  }

  # 1. The corrected shape must pass.
  build "$tmp/good" good
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected penalty layer was rejected!" >&2
    return 1
  fi

  # 2. The cooldown counted in epochs, which drift with governance.
  build "$tmp/epochs" epochs
  expect_finding "$tmp/epochs" "a cooldown measured in epochs" || return 1

  # 3. The cooldown quietly shortened to a minute.
  build "$tmp/short" wrong_length
  expect_finding "$tmp/short" "a cooldown that is not six hours" || return 1

  # 4. A replayed older failure pulls the deadline in.
  build "$tmp/shortens" shortens
  expect_finding "$tmp/shortens" "a cooldown that can be shortened" || return 1

  # 5. The map grows forever.
  build "$tmp/noprune" no_prune
  expect_finding "$tmp/noprune" "an unbounded cooldown map" || return 1

  # 6. A consensus-visible map outside the root.
  build "$tmp/rootgap" root_misses_cooldown
  expect_finding "$tmp/rootgap" "cooldowns missing from the state root" || return 1

  # 7. Recorded and never read: the failure this gate exists for.
  build "$tmp/unenforced" unenforced
  expect_finding "$tmp/unenforced" "a cooldown nothing checks" || return 1

  # 8. The primary rule disappears.
  build "$tmp/noprimary" no_primary_rule
  expect_finding "$tmp/noprimary" "a missing primary-replica rule" || return 1

  # 9. The rule overreaches into a ban on mobile storage entirely. A check
  #    that refuses everything is not the rule, and it would be just as
  #    invisible in a green test run.
  build "$tmp/banall" bans_all_replicas
  expect_finding "$tmp/banall" "a rule refusing every mobile replica" || return 1

  # 10. The call is there and asks about the wrong address. Every name-based
  #     check passes and every operator walks through.
  build "$tmp/wrongop" wrong_operator
  expect_finding "$tmp/wrongop" "a cooldown check on the wrong operator" || return 1

  # 11. The call is there and asks at time zero, so every cooldown reads as
  #     expired. The same shape, through the other argument.
  build "$tmp/frozen" frozen_clock
  expect_finding "$tmp/frozen" "a cooldown check against a frozen clock" || return 1

  # 12. A regression test disappears.
  build "$tmp/notest" missing_test
  expect_finding "$tmp/notest" "a missing regression test" || return 1

  echo "storage penalty gate self-test OK: 12 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
