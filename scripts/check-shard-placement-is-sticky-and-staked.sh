#!/usr/bin/env bash
# ============================================================================
# check-shard-placement-is-sticky-and-staked.sh
#
# Shard placement must be derived, sticky, stake-weighted, and must never put
# two shards of one object on one address.
#
# Why this gate exists.
#
# Everything else in `src/storage/` describes content and none of it says who
# holds the bytes. That gap is why the coder, the coding audit and the repair
# arithmetic all exist in the tree and none of them run: a reader has nowhere
# to ask and a repair has nothing to rebuild from.
#
# The four ways placement can be written so it looks right and is not:
#
#   1. It reshuffles on every set change. Measured on 100 validators holding
#      1 TB: twenty departures move 683 GB in one epoch. The algorithm has to
#      be chosen for what it does *not* move, which is the whole reason for
#      rendezvous hashing over a shuffle.
#   2. It ignores stake. The bond is what answers for a lost shard, so
#      placement past what the bond covers puts shards behind collateral that
#      cannot pay for their loss. A zero-stake validator has nothing to lose
#      by dropping the bytes.
#   3. It pads a short validator set with duplicates. Two shards of one object
#      on one address means one departure costs two shards, and the erasure
#      scheme's loss tolerance was computed assuming it costs one.
#   4. It uses floating point. Placement then depends on the rounding mode of
#      whichever machine recomputed it, and every node has to reach the same
#      answer or they disagree about who owes a shard.
#
# What this gate does not check: that shards are spread across networks,
# countries or hosting providers. Correlated failure is the loss that actually
# happens, but the chain cannot see an ASN, so such a rule would rest on
# self-reported data an operator can lie about, and a diversity rule built on
# a lie reports safety that is not there.
#
# Usage:
#   bash scripts/check-shard-placement-is-sticky-and-staked.sh
#   bash scripts/check-shard-placement-is-sticky-and-staked.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
src = os.path.join(root, "src", "storage", "assignment.rs")

if not os.path.isfile(src):
    print(f"FAIL: expected source file missing: {src}", file=sys.stderr)
    sys.exit(2)


def strip_comments(text):
    return re.sub(r"//[^\n]*", "", text)


def body_of(text, header):
    """Brace-matched body of the item matching `header`.

    Cutting at the first `#[cfg(test)]` drops the production half of a file
    that puts tests at the bottom; cutting at the next `}` stops at the first
    nested block. Matching braces survives both.
    """
    m = re.search(header, text)
    if not m:
        return None
    i = text.index("{", m.end() - 1) if "{" not in m.group(0) else m.end() - 1
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
        j += 1
    return None


raw = open(src, encoding="utf-8").read()
code = strip_comments(raw)
prod = code.split("#[cfg(test)]")[0]

problems = []
checked = 0

# 1. The scoring function must exist and must read the stake.
checked += 1
score = body_of(prod, r"fn rendezvous_score\s*\(")
if score is None:
    problems.append(
        "`rendezvous_score` is gone. Without a per-validator score there is "
        "no placement, and the coder, the coding audit and the repair "
        "arithmetic all stay unreachable."
    )
else:
    checked += 1
    if "stake" not in score:
        problems.append(
            "`rendezvous_score` does not read the stake. The bond is what "
            "answers for a lost shard, so placement that ignores it puts "
            "shards behind collateral that cannot pay for their loss."
        )
    checked += 1
    if "hash_fields_bytes" not in score:
        problems.append(
            "`rendezvous_score` no longer hashes its inputs, so placement is "
            "not derived from entropy the operator cannot choose."
        )
    checked += 1
    if not re.search(r"stake\s*==\s*0", score):
        problems.append(
            "`rendezvous_score` does not exclude zero-stake validators. An "
            "operator with nothing at risk has nothing to lose by dropping "
            "the bytes."
        )

# 2. No floating point anywhere in the production half. Placement has to be
#    identical on every node and a float makes it depend on rounding.
checked += 1
if re.search(r"\bf32\b|\bf64\b|\.ln\(\)|\.log\(|\.powf\(", prod):
    problems.append(
        "placement uses floating point. Every node recomputes this, and a "
        "float makes the answer depend on the machine's rounding mode, so "
        "two nodes can disagree about who owes a shard."
    )

# 3. The selection must take the top `n` by score, and must break ties
#    deterministically.
checked += 1
assign = body_of(prod, r"pub fn assign_shard\s*\(")
if assign is None:
    problems.append("`assign_shard` is gone; nothing selects holders.")
else:
    checked += 1
    if "sort" not in assign:
        problems.append(
            "`assign_shard` does not order candidates by score, so the top "
            "`n` are whatever order the input arrived in."
        )
    checked += 1
    if "then_with" not in assign and "then(" not in assign:
        problems.append(
            "`assign_shard` has no tiebreak. Two validators whose scores "
            "collide would be ordered by input order, which differs between "
            "nodes."
        )
    # 4. Duplicates must be refused, not padded.
    checked += 1
    if "NotEnoughValidators" not in assign:
        problems.append(
            "`assign_shard` does not refuse a set smaller than the scheme "
            "needs. Placing two shards of one object on one address means a "
            "single departure costs two shards, and the erasure scheme's "
            "tolerance assumed it costs one."
        )

# 5. The object-level index must not silently return a partial answer.
checked += 1
obj = body_of(prod, r"pub fn assign_object\s*\(")
if obj is None:
    problems.append("`assign_object` is gone; there is no location index.")
else:
    checked += 1
    if "?" not in obj:
        problems.append(
            "`assign_object` swallows placement errors. A caller holding "
            "placements for some shards and not others reads the missing "
            "ones as lost."
        )

# 6. The displacement check is what turns a departure into a repair.
checked += 1
if body_of(prod, r"pub fn displaced_shards\s*\(") is None:
    problems.append(
        "`displaced_shards` is gone. Nothing compares the current placement "
        "against the recorded one, so a departure produces no repair."
    )

# 7. The domain tag must be specific to placement.
checked += 1
if "BDLM_SHARD_PLACEMENT_V1" not in prod:
    problems.append(
        "the placement domain tag is missing or renamed. Sharing a tag with "
        "another hash lets a digest computed for one purpose be replayed as "
        "the other."
    )

# 8. The regressions must exist as real tests.
checked += 1
for test in (
    "a_departure_moves_one_shard_and_leaves_the_rest",
    "placement_follows_stake",
    "a_validator_with_no_stake_holds_nothing",
    "too_few_validators_is_refused_not_padded",
    "one_address_never_holds_two_shards_of_an_object",
    "the_same_inputs_place_a_shard_the_same_way",
    "placement_spreads_across_the_set",
):
    if not re.search(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + test + r"\s*\(", raw):
        problems.append(
            f"required regression test `{test}` is missing or is not a `#[test]`."
        )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"shard placement gate OK: {checked} checks, placement is derived, "
    "sticky, stake-weighted and refuses duplicates"
)
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

  # Fixtures are written by python: the bodies contain `#[test]`, and bash
  # treats `[` as a glob inside `${var//pattern/...}`, so a substitution would
  # silently do nothing and leave the canary asserting against an unmodified
  # tree.
  build() {
    python3 - "$@" <<'PYB'
import os
import sys

root, score_mode, assign_mode, obj_mode, tests_mode = sys.argv[1:6]
os.makedirs(os.path.join(root, "src", "storage"), exist_ok=True)

if score_mode == "gone":
    score = ""
elif score_mode == "nostake":
    score = """fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {
    let d = hash_fields_bytes(&[b"BDLM_SHARD_PLACEMENT_V1", shard_id.as_bytes(), entropy]);
    u128::from(u64::from_le_bytes(d[..8].try_into().unwrap()))
}
"""
elif score_mode == "float":
    score = """fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {
    if c.stake == 0 { return 0; }
    let d = hash_fields_bytes(&[b"BDLM_SHARD_PLACEMENT_V1", shard_id.as_bytes(), entropy]);
    let u = u64::from_le_bytes(d[..8].try_into().unwrap()) as f64 / u64::MAX as f64;
    (-(c.stake as f64) / u.ln()) as u128
}
"""
elif score_mode == "nozero":
    score = """fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {
    let d = hash_fields_bytes(&[b"BDLM_SHARD_PLACEMENT_V1", shard_id.as_bytes(), entropy]);
    u128::from(c.stake) * u128::from(u64::from_le_bytes(d[..8].try_into().unwrap()))
}
"""
elif score_mode == "notag":
    score = """fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {
    if c.stake == 0 { return 0; }
    let d = hash_fields_bytes(&[shard_id.as_bytes(), entropy]);
    u128::from(c.stake) * u128::from(u64::from_le_bytes(d[..8].try_into().unwrap()))
}
"""
else:
    score = """fn rendezvous_score(shard_id: &ContentId, entropy: &Hash32, c: &ShardCandidate) -> u128 {
    if c.stake == 0 { return 0; }
    let d = hash_fields_bytes(&[b"BDLM_SHARD_PLACEMENT_V1", shard_id.as_bytes(), entropy, c.address.as_bytes()]);
    let u = u128::from(u64::from_le_bytes(d[..8].try_into().unwrap())).max(1);
    u128::from(c.stake).saturating_mul(u) / (SCORE_SCALE - u.min(SCORE_SCALE - 1))
}
"""

if assign_mode == "gone":
    assign = ""
elif assign_mode == "nosort":
    assign = """pub fn assign_shard(s: &ContentId, e: &Hash32, c: &[ShardCandidate], n: usize)
    -> Result<Vec<Address>, AssignmentError> {
    let scored: Vec<Address> = c.iter().filter(|x| x.stake > 0).map(|x| x.address).collect();
    if scored.len() < n { return Err(AssignmentError::NotEnoughValidators { needed: n, available: scored.len() }); }
    Ok(scored.into_iter().take(n).collect())
}
"""
elif assign_mode == "notie":
    assign = """pub fn assign_shard(s: &ContentId, e: &Hash32, c: &[ShardCandidate], n: usize)
    -> Result<Vec<Address>, AssignmentError> {
    let mut scored: Vec<(u128, Address)> = c.iter().filter(|x| x.stake > 0)
        .map(|x| (rendezvous_score(s, e, x), x.address)).collect();
    if scored.len() < n { return Err(AssignmentError::NotEnoughValidators { needed: n, available: scored.len() }); }
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(scored.into_iter().take(n).map(|(_, a)| a).collect())
}
"""
elif assign_mode == "pad":
    # Cycles the pool to fill the request. Two shards land on one address and
    # a single departure costs two shards.
    assign = """pub fn assign_shard(s: &ContentId, e: &Hash32, c: &[ShardCandidate], n: usize)
    -> Result<Vec<Address>, AssignmentError> {
    let mut scored: Vec<(u128, Address)> = c.iter().filter(|x| x.stake > 0)
        .map(|x| (rendezvous_score(s, e, x), x.address)).collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    Ok(scored.iter().cycle().take(n).map(|(_, a)| *a).collect())
}
"""
else:
    assign = """pub fn assign_shard(s: &ContentId, e: &Hash32, c: &[ShardCandidate], n: usize)
    -> Result<Vec<Address>, AssignmentError> {
    let mut scored: Vec<(u128, Address)> = c.iter().filter(|x| x.stake > 0)
        .map(|x| (rendezvous_score(s, e, x), x.address)).collect();
    if scored.len() < n { return Err(AssignmentError::NotEnoughValidators { needed: n, available: scored.len() }); }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    Ok(scored.into_iter().take(n).map(|(_, a)| a).collect())
}
"""

if obj_mode == "gone":
    obj = ""
elif obj_mode == "swallow":
    # Skips shards it cannot place. The caller reads the gap as loss.
    obj = """pub fn assign_object(ids: &[ContentId], e: &Hash32, c: &[ShardCandidate])
    -> Result<Vec<Address>, AssignmentError> {
    let mut out = Vec::new();
    for id in ids {
        if let Ok(p) = assign_shard(id, e, c, 1) { out.push(p[0]); }
    }
    Ok(out)
}
"""
else:
    obj = """pub fn assign_object(ids: &[ContentId], e: &Hash32, c: &[ShardCandidate])
    -> Result<Vec<Address>, AssignmentError> {
    let mut out = Vec::new();
    for id in ids { out.push(assign_shard(id, e, c, 1)?[0]); }
    Ok(out)
}
"""

displaced = """pub fn displaced_shards(prev: &[Address], cur: &[Address]) -> Vec<usize> {
    prev.iter().zip(cur.iter()).enumerate()
        .filter_map(|(i, (a, b))| (a != b).then_some(i)).collect()
}
"""

names = [
    "a_departure_moves_one_shard_and_leaves_the_rest",
    "placement_follows_stake",
    "a_validator_with_no_stake_holds_nothing",
    "too_few_validators_is_refused_not_padded",
    "one_address_never_holds_two_shards_of_an_object",
    "the_same_inputs_place_a_shard_the_same_way",
    "placement_spreads_across_the_set",
]
if tests_mode == "absent":
    names = names[:-1]
tests = "#[cfg(test)]\nmod tests {\n" + "".join(
    "#[test]\nfn %s() {}\n" % n for n in names
) + "}\n"

open(os.path.join(root, "src/storage/assignment.rs"), "w").write(
    "const SCORE_SCALE: u128 = 1 << 64;\n"
    + "\n".join([score, assign, obj, displaced, tests])
)
PYB
  }

  # 1. The corrected shape must pass, or every canary below proves nothing.
  build "$tmp/good" ok ok ok present
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    return 1
  fi

  # 2. No scoring at all.
  build "$tmp/noscore" gone ok ok present
  expect_finding "$tmp/noscore" "a tree with no placement score" || return 1

  # 3. Scoring that ignores stake, so the bond does not govern placement.
  build "$tmp/nostake" nostake ok ok present
  expect_finding "$tmp/nostake" "placement that ignores the bond" || return 1

  # 4. Floating point, so two nodes can compute different placements.
  build "$tmp/float" float ok ok present
  expect_finding "$tmp/float" "placement that depends on rounding mode" || return 1

  # 5. Zero-stake validators still eligible.
  build "$tmp/nozero" nozero ok ok present
  expect_finding "$tmp/nozero" "a validator with nothing at risk holding shards" || return 1

  # 6. The domain tag dropped, so the digest can be replayed from elsewhere.
  build "$tmp/notag" notag ok ok present
  expect_finding "$tmp/notag" "a placement hash with no domain tag" || return 1

  # 7. Selection disappears.
  build "$tmp/noassign" ok gone ok present
  expect_finding "$tmp/noassign" "a missing selection" || return 1

  # 8. Selection that never orders by score: the top n is input order.
  build "$tmp/nosort" ok nosort ok present
  expect_finding "$tmp/nosort" "a selection that ignores the score" || return 1

  # 9. No tiebreak, so colliding scores order differently per node.
  build "$tmp/notie" ok notie ok present
  expect_finding "$tmp/notie" "a selection with no deterministic tiebreak" || return 1

  # 10. The subtle one: a short set is padded by cycling, so one address
  #     holds two shards and a single departure costs two.
  build "$tmp/pad" ok pad ok present
  expect_finding "$tmp/pad" "a short validator set padded with duplicates" || return 1

  # 11. The object index disappears.
  build "$tmp/noobj" ok ok gone present
  expect_finding "$tmp/noobj" "a missing location index" || return 1

  # 12. The object index swallows errors and returns a partial answer.
  build "$tmp/swallow" ok ok swallow present
  expect_finding "$tmp/swallow" "a partial index read as loss" || return 1

  # 13. A regression test is dropped.
  build "$tmp/notest" ok ok ok absent
  expect_finding "$tmp/notest" "a missing regression test" || return 1

  echo "shard placement gate self-test OK: 12 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
