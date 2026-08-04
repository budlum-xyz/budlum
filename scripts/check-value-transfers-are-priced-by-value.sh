#!/usr/bin/env bash
# ============================================================================
# check-value-transfers-are-priced-by-value.sh
#
# A transfer fee that cannot see the amount is not a fee on the transfer.
#
# Why this gate exists.
#
# `validate_transaction_with_context` required exactly one thing of a fee:
#
#     if tx.fee < self.base_fee { reject }
#
# `tx.amount` appeared twice in that function, in the overflow guard and in the
# balance check, and nowhere in pricing. Someone moving one base unit and
# someone moving a quadrillion paid the same. This is the transfer twin of the
# storage deal that charged the same for a 1 KiB shard and a 16 MiB one, and it
# has the same shape: the number the price should depend on was in hand and
# went unread.
#
# What the gate checks, and why each check is here rather than trusted.
#
#   1. `RegistryParams` carries the three proportional rates, and they are
#      distinct fields. `bridge_fee_ppm` is the protocol's cut on an outbound
#      transfer; `bridge_relayer_fee_ppm` is compensation paid to a relayer out
#      of an arriving asset. Collapsing them into one number would silently
#      redirect revenue into a third party's pocket.
#
#   2. Every rate is validated below 100%. A cut at or above 100% debits the
#      sender everything and credits the recipient nothing.
#
#   3. The fee actually consults the amount. A `required_transfer_fee` that
#      ignored its `amount` argument would satisfy every name-based check while
#      restoring the exact bug this closes.
#
#   4. The combination is `max`, not `+`. Charging the floor *and* the
#      percentage means every large transfer pays the floor twice, which is not
#      what the economic model describes.
#
#   5. Rounding is up. Integer division is how a real charge becomes zero, and
#      a zero-cost transfer at a nonzero rate is a free ride the network still
#      pays for. A genuinely free transfer is a zero rate.
#
#   6. The rates are governance-tunable, in *both* places that decide it. The
#      whitelist in governance.rs says which keys are allowed; a second `match`
#      in account.rs decides which keys actually apply. Adding a rate to the
#      first and forgetting the second gives a parameter governance accepts and
#      then rejects with "unknown registry parameter", which is exactly what
#      happened here and what `every_whitelisted_governance_parameter_can_be_
#      applied` caught in CI.
#
#   7. The named regressions exist and are real `#[test]` functions.
#
# What the gate deliberately does not require. It does not require any rate to
# be nonzero. Launching with flat fees is an economic decision. Being unable to
# express a proportional fee at all is not.
#
# Usage:
#   bash scripts/check-value-transfers-are-priced-by-value.sh
#   bash scripts/check-value-transfers-are-priced-by-value.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
params = os.path.join(root, "src", "registry", "params.rs")
account = os.path.join(root, "src", "core", "account.rs")
governance = os.path.join(root, "src", "core", "governance.rs")

for path in (params, account, governance):
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


params_src = open(params, encoding="utf-8").read()
params_code = strip_comments(params_src)
account_code = strip_comments(open(account, encoding="utf-8").read())
gov_code = strip_comments(open(governance, encoding="utf-8").read())

problems = []
checked = 0

# 1. The three rates exist and are separate fields.
RATES = ("transfer_fee_ppm", "swap_fee_ppm", "bridge_fee_ppm")
for rate in RATES:
    checked += 1
    if not re.search(r"pub " + rate + r"\s*:\s*u64", params_code):
        problems.append(
            f"`RegistryParams` has no `{rate}`. A proportional cut that cannot "
            "be expressed as a parameter ends up as a literal at whichever "
            "call site lands first."
        )

checked += 1
if "bridge_relayer_fee_ppm" in params_code and "bridge_fee_ppm" not in params_code:
    problems.append(
        "`bridge_fee_ppm` is gone while `bridge_relayer_fee_ppm` remains. Those "
        "are different things: one is the protocol's cut on an outbound "
        "transfer, the other is compensation paid to a relayer out of an "
        "arriving asset. Merging them redirects revenue."
    )

# 2. Each rate is bounded below 100%.
validate = body_of(params_code, r"pub fn validate\s*\(")
if validate is None:
    problems.append("cannot find `RegistryParams::validate` to check the rate bounds.")
else:
    for rate in RATES:
        checked += 1
        if rate not in validate:
            problems.append(
                f"`validate` does not bound `{rate}`. A cut at or above 100% "
                "debits the sender everything and credits the recipient nothing."
            )

# 3/4/5. The fee reads the amount, combines with max, and rounds up.
prop = body_of(params_code, r"pub fn proportional_fee\s*\(")
req = body_of(params_code, r"pub fn required_transfer_fee\s*\(")

checked += 1
if prop is None:
    problems.append(
        "no `proportional_fee` in RegistryParams; the fee has no single home "
        "and each call site will spell the arithmetic its own way."
    )
else:
    checked += 1
    if "amount" not in prop:
        problems.append(
            "`proportional_fee` never mentions `amount`. A fee that ignores the "
            "value moved is exactly the bug this gate exists to prevent."
        )
    checked += 1
    if "div_ceil" not in prop:
        problems.append(
            "`proportional_fee` does not round up. Integer division sends any "
            "charge below one base unit to zero, so the smallest transfers ride "
            "free and splitting a large one becomes profitable. A genuinely "
            "free transfer is written as a zero rate."
        )
    checked += 1
    if "u128" not in prop:
        problems.append(
            "`proportional_fee` does not widen to `u128`. `amount * rate` leaves "
            "`u64` well inside the range of amounts this function exists to "
            "price."
        )

checked += 1
if req is None:
    problems.append("no `required_transfer_fee`; nothing combines the floor with the cut.")
else:
    checked += 1
    if ".max(" not in req:
        problems.append(
            "`required_transfer_fee` does not take the larger of the floor and "
            "the cut. Adding them charges the floor twice on every large "
            "transfer, which is not the model."
        )
    checked += 1
    if re.search(r"base_fee\s*(?:\.saturating_add|\+)", req):
        problems.append(
            "`required_transfer_fee` adds the floor to the proportional cut. It "
            "must take the larger of the two."
        )

# 3b. The validation path must actually apply it. A parameter nothing reads is
#     a parameter that does nothing.
checked += 1
validate_tx = body_of(account_code, r"pub fn validate_transaction_with_context\s*\(")
if validate_tx is None:
    problems.append(
        "cannot find `validate_transaction_with_context`. If it was renamed, "
        "update this gate in the same commit so the fee check stays watched."
    )
elif "required_transfer_fee" not in validate_tx:
    problems.append(
        "`validate_transaction_with_context` does not call "
        "`required_transfer_fee`. The rate exists and nothing enforces it, "
        "which reads as a working proportional fee to anyone grepping for one."
    )

# 6. Governance can move the rates, in both places that decide it.
for rate in RATES:
    checked += 1
    if f'"{rate}"' not in gov_code:
        problems.append(
            f"`{rate}` is not on the governance whitelist. An economic rate that "
            "can only change by shipping a binary is not a parameter."
        )
    checked += 1
    apply_fn = body_of(account_code, r"fn apply_registry_parameter_update\s*\(")
    if apply_fn is None:
        problems.append(
            "cannot find `apply_registry_parameter_update`; if it moved, update "
            "this gate in the same commit so the second half of the whitelist "
            "stays watched."
        )
    elif f'"{rate}"' not in apply_fn:
        problems.append(
            f"`{rate}` is whitelisted but `apply_registry_parameter_update` has "
            "no arm for it. Governance would accept the proposal and then fail "
            "to apply it with `unknown registry parameter`. Two matches decide "
            "this, and both have to know the key."
        )

# 7. The regressions must exist as real tests.
checked += 1
for test in (
    "a_larger_transfer_requires_a_larger_fee",
    "the_default_rate_leaves_the_flat_fee_untouched",
    "splitting_a_transfer_does_not_reduce_the_total_fee",
    "a_priced_transfer_is_never_free_through_rounding",
    "an_enormous_transfer_saturates_rather_than_wrapping",
    "a_proportional_rate_at_or_above_one_hundred_percent_is_refused",
    "the_three_proportional_rates_are_independent",
):
    if not re.search(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + test + r"\s*\(", params_src):
        problems.append(f"required regression test `{test}` is missing or is not a `#[test]`.")

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(f"value pricing gate OK: {checked} checks, transfers are priced by value")
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

  # Fixtures are built by python: the test bodies contain `#[test]`, and bash
  # treats `[` as a glob inside `${var//pattern/...}`, so a substitution there
  # silently does nothing and the canary asserts against an unmodified tree.
  build() {
    python3 - "$@" <<'PYB'
import os
import sys

root, mode = sys.argv[1], sys.argv[2]
for sub in ("src/registry", "src/core"):
    os.makedirs(os.path.join(root, sub), exist_ok=True)

fields = """    pub transfer_fee_ppm: u64,
    pub swap_fee_ppm: u64,
    pub bridge_fee_ppm: u64,
    pub bridge_relayer_fee_ppm: u64,
"""
if mode == "merged_bridge":
    fields = """    pub transfer_fee_ppm: u64,
    pub swap_fee_ppm: u64,
    pub bridge_relayer_fee_ppm: u64,
"""

validate = """    pub fn validate(&self) -> Result<(), String> {
        for (n, r) in [("transfer_fee_ppm", self.transfer_fee_ppm),
                       ("swap_fee_ppm", self.swap_fee_ppm),
                       ("bridge_fee_ppm", self.bridge_fee_ppm)] {
            if r >= PPM_DENOMINATOR { return Err(n.into()); }
        }
        Ok(())
    }
"""
if mode == "unbounded":
    validate = """    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
"""

prop = """    pub fn proportional_fee(&self, amount: u64, rate_ppm: u64) -> u64 {
        let scaled = u128::from(amount).saturating_mul(u128::from(rate_ppm));
        u64::try_from(scaled.div_ceil(u128::from(PPM_DENOMINATOR))).unwrap_or(u64::MAX)
    }
"""
if mode == "ignores_amount":
    prop = """    pub fn proportional_fee(&self, _a: u64, rate_ppm: u64) -> u64 {
        let scaled = u128::from(rate_ppm);
        u64::try_from(scaled.div_ceil(u128::from(PPM_DENOMINATOR))).unwrap_or(u64::MAX)
    }
"""
elif mode == "truncates":
    prop = """    pub fn proportional_fee(&self, amount: u64, rate_ppm: u64) -> u64 {
        let scaled = u128::from(amount).saturating_mul(u128::from(rate_ppm));
        u64::try_from(scaled / u128::from(PPM_DENOMINATOR)).unwrap_or(u64::MAX)
    }
"""

req = """    pub fn required_transfer_fee(&self, amount: u64, base_fee: u64) -> u64 {
        base_fee.max(self.proportional_fee(amount, self.transfer_fee_ppm))
    }
"""
if mode == "adds":
    req = """    pub fn required_transfer_fee(&self, amount: u64, base_fee: u64) -> u64 {
        base_fee.saturating_add(self.proportional_fee(amount, self.transfer_fee_ppm))
    }
"""

tests = ""
names = [
    "a_larger_transfer_requires_a_larger_fee",
    "the_default_rate_leaves_the_flat_fee_untouched",
    "splitting_a_transfer_does_not_reduce_the_total_fee",
    "a_priced_transfer_is_never_free_through_rounding",
    "an_enormous_transfer_saturates_rather_than_wrapping",
    "a_proportional_rate_at_or_above_one_hundred_percent_is_refused",
    "the_three_proportional_rates_are_independent",
]
if mode == "missing_test":
    names = names[:-1]
for n in names:
    tests += "#[test]\nfn %s() {}\n" % n

open(os.path.join(root, "src/registry/params.rs"), "w").write(
    "pub struct RegistryParams {\n%s}\nimpl RegistryParams {\n%s%s%s}\n%s"
    % (fields, validate, prop, req, tests)
)

apply_line = "self.registry.params().required_transfer_fee(tx.amount, self.base_fee)"
if mode == "unapplied":
    apply_line = "self.base_fee"

# The second match: which keys governance can actually apply. A rate on the
# whitelist with no arm here is accepted and then refused at apply time.
arms = ['"transfer_fee_ppm"', '"swap_fee_ppm"', '"bridge_fee_ppm"']
if mode == "half_governed":
    arms = arms[:2]
apply_match = "".join("            %s => {}\n" % a for a in arms)
open(os.path.join(root, "src/core/account.rs"), "w").write(
    "impl AccountState {\n"
    "    pub fn validate_transaction_with_context(&self) -> Result<(), String> {\n"
    "        let required = %s;\n        Ok(())\n    }\n"
    "    fn apply_registry_parameter_update(&mut self, key: &str) -> Result<(), String> {\n"
    "        match key {\n%s"
    "            other => return Err(format!(\"unknown registry parameter: {other}\")),\n"
    "        }\n        Ok(())\n    }\n}\n" % (apply_line, apply_match)
)

wl = '"transfer_fee_ppm", "swap_fee_ppm", "bridge_fee_ppm",'
if mode == "not_governed":
    wl = '"transfer_fee_ppm", "swap_fee_ppm",'
open(os.path.join(root, "src/core/governance.rs"), "w").write(
    "pub const GOVERNANCE_PARAMETER_WHITELIST: &[&str] = &[%s];\n" % wl
)
PYB
  }

  # 1. The corrected shape must pass.
  build "$tmp/good" good
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected pricing was rejected!" >&2
    return 1
  fi

  # 2. The fee ignores the amount: the original bug, wearing the right name.
  build "$tmp/ignores" ignores_amount
  expect_finding "$tmp/ignores" "a fee function that ignores the amount" || return 1

  # 3. The rate exists but nothing applies it.
  build "$tmp/unapplied" unapplied
  expect_finding "$tmp/unapplied" "a rate no validation path reads" || return 1

  # 4. Floor and cut added instead of max.
  build "$tmp/adds" adds
  expect_finding "$tmp/adds" "a floor added to the cut rather than maxed" || return 1

  # 5. Rounding reverts to truncation.
  build "$tmp/trunc" truncates
  expect_finding "$tmp/trunc" "truncation that prices small transfers free" || return 1

  # 6. The rates lose their bounds.
  build "$tmp/unbounded" unbounded
  expect_finding "$tmp/unbounded" "rates with no 100% bound" || return 1

  # 7. The protocol cut is merged into the relayer's compensation.
  build "$tmp/merged" merged_bridge
  expect_finding "$tmp/merged" "the protocol cut merged into relayer pay" || return 1

  # 8. A rate drops off the governance whitelist.
  build "$tmp/ungoverned" not_governed
  expect_finding "$tmp/ungoverned" "a rate governance cannot move" || return 1

  # 9. A regression test disappears.
  build "$tmp/notest" missing_test
  expect_finding "$tmp/notest" "a missing regression test" || return 1

  # 10. A rate reaches the governance whitelist and not the match that applies
  #     it. Governance accepts the proposal, then fails with "unknown registry
  #     parameter". Two matches decide this and both have to know the key; the
  #     first version of this change knew only one, and CI caught it.
  build "$tmp/halfgov" half_governed
  expect_finding "$tmp/halfgov" "a rate whitelisted but never applied" || return 1

  echo "value pricing gate self-test OK: 10 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
