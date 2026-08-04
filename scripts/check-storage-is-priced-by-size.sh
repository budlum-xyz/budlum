#!/usr/bin/env bash
# ============================================================================
# check-storage-is-priced-by-size.sh
#
# A storage price that ignores how much is stored is not a price.
#
# Why this gate exists.
#
# `StorageEconomicsParams` carried `fee_per_epoch`, and the client fee was
#
#     total_fee = epochs * fee_per_epoch
#
# with no byte count anywhere in it. A 1 KiB shard and a 16 MiB shard cost the
# same to store for the same time. The client picks the size, so this is not
# an attack, it is ordinary use: write large data at the small-data price and
# the operator carries the difference. The three places that read the field
# were all affected, escrow at deal-open, reward accrual, and the boost weight
# each operator is paid by.
#
# What made it worth a gate rather than a one-line fix is that the byte count
# was never missing. `open_deal` already receives the manifest and already
# looks the shard up in it to check membership, so `ShardRef.size` was in hand
# at the moment the price was computed and simply went unread. The failure was
# not a gap in the data, it was an expression that did not use it, and that
# is exactly the kind of thing that reappears when someone adds a fourth call
# site later.
#
# `storage_deal_leaf_hash` had the matching hole: it committed to the rate and
# not to the size, so the number the price was computed from was outside the
# commitment.
#
# What the gate checks.
#
#   1. `StorageEconomicsParams` does not carry a size-free `fee_per_epoch`.
#   2. It carries `fee_per_byte_epoch`, and `StorageDeal` carries the
#      `shard_bytes` it was priced at.
#   3. Every fee computation goes through `total_fee`. A call site that
#      multiplies the rate by epochs on its own is the old bug returning.
#   4. `storage_deal_leaf_hash` commits to `shard_bytes`.
#   5. Rounding is up, not down. Truncation is how a price silently becomes
#      zero, which is free storage the operator still has to serve and answer
#      challenges for. A deal that is genuinely free says so with a zero rate.
#   6. The named regression tests exist and are real `#[test]` functions.
#
# Usage:
#   bash scripts/check-storage-is-priced-by-size.sh              # gate
#   bash scripts/check-storage-is-priced-by-size.sh --self-test  # canary
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

deal_src = open(deal, encoding="utf-8").read()
chain_src = open(chain, encoding="utf-8").read()


def code(src):
    return re.sub(r"//[^\n]*", "", src)


deal_code = code(deal_src)
chain_code = code(chain_src)
both = deal_code + "\n" + chain_code

problems = []
checked = 0

# 1. The size-free field must be gone, everywhere, not just renamed at the
#    definition.
checked += 1
if re.search(r"\bfee_per_epoch\b", both):
    problems.append(
        "`fee_per_epoch` is still present. That field priced a deal by "
        "duration alone, so a 1 KiB and a 16 MiB shard cost the same. The "
        "per-byte rate is `fee_per_byte_epoch`."
    )

# 2. The rate and the size the deal was priced at must both exist.
checked += 1
if "fee_per_byte_epoch" not in deal_code:
    problems.append(
        "`StorageEconomicsParams` has no `fee_per_byte_epoch`. Storage has to "
        "be priced by the bytes it holds."
    )
checked += 1
if not re.search(r"pub shard_bytes\s*:\s*u64", deal_code):
    problems.append(
        "`StorageDeal` has no `shard_bytes` field. The deal outlives the "
        "caller's manifest, so the size the price was agreed at has to travel "
        "with it rather than being looked up again later."
    )

# 3. Nobody may recompute a fee by hand. One home for the expression.
checked += 1
if not re.search(r"fn total_fee\s*\(", deal_code):
    problems.append("no `total_fee` in storage_deal.rs; the price has no single home.")

checked += 1
handmade = re.findall(
    r"fee_per_byte_epoch\s*(?:as u128\s*)?\)?\s*\.?\s*(?:saturating_)?mul|"
    r"(?:saturating_mul|\*)\s*\(?\s*[a-z_.]*fee_per_byte_epoch",
    both,
)
# The one legitimate multiplication is inside total_fee itself.
body = re.search(r"fn total_fee\s*\([^)]*\)[^{]*\{(.*?)\n    \}", deal_code, re.S)
allowed = len(
    re.findall(
        r"fee_per_byte_epoch\s*(?:as u128\s*)?\)?\s*\.?\s*(?:saturating_)?mul|"
        r"(?:saturating_mul|\*)\s*\(?\s*[a-z_.]*fee_per_byte_epoch",
        body.group(1) if body else "",
    )
)
if len(handmade) > allowed:
    problems.append(
        f"the rate is multiplied out at {len(handmade) - allowed} site(s) "
        "outside `total_fee`. Every fee must go through it, or the call sites "
        "drift apart the way the three readers of `fee_per_epoch` did."
    )

# 4. The commitment must cover the size the price came from.
checked += 1
leaf = re.search(r"fn storage_deal_leaf_hash[^{]*\{(.*?)\n\}", deal_code, re.S)
if not leaf:
    problems.append("cannot find `storage_deal_leaf_hash` to check what it commits to.")
elif "shard_bytes" not in leaf.group(1):
    problems.append(
        "`storage_deal_leaf_hash` does not commit to `shard_bytes`. The size "
        "is what the price is computed from, so leaving it out lets the agreed "
        "number move without the commitment noticing."
    )

# 5. Rounding must be up. `/ FEE_RATE_SCALE` truncates a small honest price to
#    zero, and zero is free storage that still has to be served.
checked += 1
if body:
    if "div_ceil" not in body.group(1):
        problems.append(
            "`total_fee` does not round up. Integer division sends any deal "
            "priced below one base unit to zero, and a zero fee is free "
            "storage the operator must still serve and answer challenges for. "
            "A genuinely free deal is written as a zero rate."
        )

# 6. The regressions must exist as real tests.
checked += 1
required = [
    "a_larger_shard_costs_more_for_the_same_duration",
    "a_longer_deal_costs_more_for_the_same_shard",
    "a_priced_deal_is_never_free_through_rounding",
    "a_zero_rate_stays_free",
    "an_unpayable_deal_saturates_rather_than_wrapping",
    "opening_a_deal_records_the_shard_size_it_was_priced_at",
    "the_deal_leaf_commits_to_the_shard_size",
]
for name in required:
    if not re.search(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + name + r"\s*\(", deal_src):
        problems.append(
            f"required regression test `{name}` is missing or is not a `#[test]`."
        )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(f"storage pricing gate OK: {checked} checks, storage is priced by size")
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
      echo "GATE IS BROKEN: $what exited $rc, not a finding." >&2
      return 1
    fi
  }

  build() {
    local dir="$1" deal_body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/src/domain" "$dir/src/chain"
    printf '%s\n' "$deal_body" >"$dir/src/domain/storage_deal.rs"
    printf '%s\n' 'fn nothing() {}' >"$dir/src/chain/blockchain.rs"
  }

  local TESTS=""
  for name in a_larger_shard_costs_more_for_the_same_duration \
              a_longer_deal_costs_more_for_the_same_shard \
              a_priced_deal_is_never_free_through_rounding \
              a_zero_rate_stays_free \
              an_unpayable_deal_saturates_rather_than_wrapping \
              opening_a_deal_records_the_shard_size_it_was_priced_at \
              the_deal_leaf_commits_to_the_shard_size; do
    TESTS="${TESTS}#[test]
fn ${name}() {}
"
  done

  local GOOD="pub struct StorageEconomicsParams {
    pub fee_per_byte_epoch: u64,
}
pub struct StorageDeal {
    pub shard_bytes: u64,
}
impl StorageEconomicsParams {
    pub fn total_fee(&self, shard_bytes: u64, epochs: u64) -> u64 {
        let scaled = (self.fee_per_byte_epoch as u128)
            .saturating_mul(shard_bytes as u128)
            .saturating_mul(epochs as u128);
        u64::try_from(scaled.div_ceil(FEE_RATE_SCALE)).unwrap_or(u64::MAX)
    }
}
pub fn storage_deal_leaf_hash(deal: &StorageDeal) -> [u8; 32] {
    hash(&[&deal.shard_bytes.to_le_bytes()])
}
${TESTS}"

  # 1. The corrected shape must pass.
  build "$tmp/good" "$GOOD"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected pricing was rejected!" >&2
    return 1
  fi

  # 2. The original bug: a duration-only price.
  build "$tmp/flat" "${GOOD//fee_per_byte_epoch/fee_per_epoch}"
  expect_finding "$tmp/flat" "a size-free \`fee_per_epoch\`" || return 1

  # 3. The deal stops recording the size it was priced at.
  build "$tmp/nosize" "${GOOD//pub shard_bytes: u64,/}"
  expect_finding "$tmp/nosize" "a deal with no recorded shard size" || return 1

  # 4. Rounding reverts to truncation, which prices small deals at zero.
  build "$tmp/trunc" "${GOOD//scaled.div_ceil(FEE_RATE_SCALE)/scaled \/ FEE_RATE_SCALE}"
  expect_finding "$tmp/trunc" "truncating division that prices small deals free" \
    || return 1

  # 5. The leaf stops committing to the size the price came from.
  build "$tmp/leaf" "${GOOD//&deal.shard_bytes.to_le_bytes()/\&deal.deal_id.to_le_bytes()}"
  expect_finding "$tmp/leaf" "a leaf hash that omits the priced size" || return 1

  # 6. A regression test is dropped.
  build "$tmp/notest" "${GOOD//fn a_zero_rate_stays_free() {}/fn something_else() {}}"
  expect_finding "$tmp/notest" "a missing regression test" || return 1

  # 7. A test is renamed to a non-test function, the shape that silently
  #    un-tested an economy invariant once before. Built with python rather
  #    than `${var//...}`: `#[test]` contains `[`, which bash reads as a glob
  #    in the pattern half, so the substitution silently does nothing and the
  #    canary would assert against an unmodified fixture.
  rm -rf "$tmp/nottest"
  mkdir -p "$tmp/nottest/src/domain" "$tmp/nottest/src/chain"
  printf '%s\n' 'fn nothing() {}' >"$tmp/nottest/src/chain/blockchain.rs"
  printf '%s' "$GOOD" | python3 -c 'import sys
src = sys.stdin.read()
stripped = src.replace(
    "#[test]\nfn a_zero_rate_stays_free() {}",
    "fn a_zero_rate_stays_free() {}",
)
if stripped == src:
    sys.exit("canary fixture unchanged: the #[test] attribute was not removed")
sys.stdout.write(stripped)' >"$tmp/nottest/src/domain/storage_deal.rs"
  expect_finding "$tmp/nottest" "a required test that is no longer a #[test]" \
    || return 1

  echo "storage pricing gate self-test OK: 7 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
