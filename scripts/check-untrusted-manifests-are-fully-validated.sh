#!/usr/bin/env bash
# ============================================================================
# check-untrusted-manifests-are-fully-validated.sh
#
# Every path that takes a manifest from a caller must apply the same check.
#
# Why this gate exists.
#
# Two entry points accept a `ContentManifest` an untrusted caller built.
# `RegisterStorageManifest` called `validate_untrusted`. `open_deal` called
# `verify_id` and stopped there, and `open_deal` is the path that also takes
# the payer's money and seeds the registry through first-writer-wins.
#
# The two checks are not interchangeable. `verify_id` proves the id was
# derived from the fields present. It does not prove the fields agree with
# one another, and `manifest_id` covers `k` and `n`, so an author who wants a
# false claim computes the id over the claim it wants:
#
#     three data shards, no parity, declared (k = 1, n = 3)
#
# hashes perfectly consistently and reports a loss tolerance of two. The
# object survives no failures at all. A repair trigger reads the declared
# tolerance and concludes nothing needs doing, which is the one moment the
# number matters.
#
# `validate_untrusted` is what catches it: it requires the data-shard count to
# equal `k` and the parity count to equal `n - k`, so a claim the shard list
# cannot deliver is refused. Both checks existed. Only one of the two doors
# used the stronger one.
#
# What the gate checks.
#
#   1. `validate_untrusted` still exists and still ties `k` and `n` to the
#      shards actually present. A version that dropped those comparisons would
#      pass every name-based check while proving nothing.
#   2. Every entry point that accepts a caller-supplied manifest calls it.
#      `open_deal` and the `RegisterStorageManifest` handler are named
#      explicitly, because those are the two doors and a third would be added
#      next to one of them.
#
#      `ChainCommand::RegisterStorageManifest {` appears twice: once where the
#      client-side method sends the command, and once in the match arm that
#      handles it. Only the second validates anything, and taking the first
#      match reported a door that was in fact guarded. The handler is the arm
#      followed by `=>`, so that is what this looks for.
#   3. No such path settles for `verify_id` alone.
#   4. The named regressions exist and are real `#[test]` functions.
#
# Usage:
#   bash scripts/check-untrusted-manifests-are-fully-validated.sh
#   bash scripts/check-untrusted-manifests-are-fully-validated.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
manifest = os.path.join(root, "src", "storage", "manifest.rs")
deal = os.path.join(root, "src", "domain", "storage_deal.rs")
actor = os.path.join(root, "src", "chain", "chain_actor.rs")

for path in (manifest, deal, actor):
    if not os.path.isfile(path):
        print(f"FAIL: expected source file missing: {path}", file=sys.stderr)
        sys.exit(2)


def strip_comments(src):
    return re.sub(r"//[^\n]*", "", src)


def body_of(src, header):
    """Text of the function whose signature matches `header`, brace-matched."""
    m = re.search(header, src)
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


manifest_code = strip_comments(open(manifest, encoding="utf-8").read())
deal_src = open(deal, encoding="utf-8").read()
deal_code = strip_comments(deal_src)
actor_code = strip_comments(open(actor, encoding="utf-8").read())

problems = []
checked = 0

# 1. The strong check must still be strong. A `validate_untrusted` that no
#    longer compares the declared scheme against the shards would satisfy
#    every call-site check below and prove nothing.
checked += 1
vu = body_of(manifest_code, r"pub fn validate_untrusted\s*\(")
if vu is None:
    problems.append(
        "`ContentManifest::validate_untrusted` is gone. It is the only check "
        "that ties the declared erasure scheme to the shards present."
    )
else:
    checked += 1
    if not re.search(r"erasure\.k|\.k\b", vu) or "ShardKind::Data" not in vu:
        problems.append(
            "`validate_untrusted` no longer compares `k` against the data "
            "shards present. Without that comparison a manifest can declare a "
            "loss tolerance its shard list cannot deliver, and the id will "
            "still verify because `manifest_id` covers `k` and `n`."
        )
    if not re.search(r"erasure\.n|\bn\b", vu) or "shard_count" not in vu:
        problems.append(
            "`validate_untrusted` no longer ties `n` to `shard_count`."
        )

# 2/3. Both doors must use it, and neither may settle for the weaker check.
doors = [
    ("open_deal", deal_code, r"pub fn open_deal\s*\("),
    (
        "RegisterStorageManifest handler",
        actor_code,
        # The match arm, not the `send(...)` call that shares the name.
        r"ChainCommand::RegisterStorageManifest\s*\{[^}]*\}\s*=>",
    ),
]
for name, src, header in doors:
    checked += 1
    if name.startswith("Register"):
        m = re.search(header, src)
        region = src[m.start() : m.start() + 2000] if m else None
    else:
        region = body_of(src, header)
    if region is None:
        problems.append(
            f"cannot find `{name}` to check what it validates. If it was "
            "renamed, update this gate in the same commit so the door stays "
            "watched."
        )
        continue
    if "validate_untrusted" not in region:
        weak = "verify_id" in region
        detail = (
            " It calls `verify_id`, which only proves the id was derived from "
            "the fields present, not that they agree with each other."
            if weak
            else ""
        )
        problems.append(
            f"`{name}` accepts a caller-supplied manifest without calling "
            f"`validate_untrusted`.{detail}"
        )

# 4. The regressions must exist as real tests.
checked += 1
for test in (
    "a_deal_open_refuses_a_manifest_claiming_parity_it_does_not_have",
    "a_deal_open_still_accepts_a_coherent_manifest",
):
    if not re.search(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + test + r"\s*\(", deal_src):
        problems.append(f"required regression test `{test}` is missing or is not a `#[test]`.")

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"untrusted manifest gate OK: {checked} checks, both doors apply the same "
    "validation"
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

  # Fixtures are written by python: the test bodies contain `#[test]`, and
  # bash treats `[` as a glob inside `${var//pattern/...}`, so a substitution
  # would silently do nothing and leave the canary asserting against an
  # unmodified tree.
  build() {
    python3 - "$1" "$2" "$3" "$4" <<'PYB'
import os
import sys

root, vu_mode, deal_mode, tests_mode = sys.argv[1:5]
for sub in ("src/storage", "src/domain", "src/chain"):
    os.makedirs(os.path.join(root, sub), exist_ok=True)

strong = """    pub fn validate_untrusted(&self) -> Result<(), String> {
        if self.erasure.n != self.shard_count { return Err("n".into()); }
        let data = self.shards.iter().filter(|s| s.kind == ShardKind::Data).count() as u32;
        if data != self.erasure.k { return Err("k".into()); }
        self.verify_id()
    }
"""
weak = """    pub fn validate_untrusted(&self) -> Result<(), String> {
        self.verify_id()
    }
"""
manifest = strong if vu_mode == "strong" else (weak if vu_mode == "weak" else "")
open(os.path.join(root, "src/storage/manifest.rs"), "w").write(manifest)

checked_call = "manifest.validate_untrusted()?;"
weak_call = "manifest.verify_id()?;"
call = checked_call if deal_mode == "strong" else weak_call
tests = ""
if tests_mode == "present":
    for name in (
        "a_deal_open_refuses_a_manifest_claiming_parity_it_does_not_have",
        "a_deal_open_still_accepts_a_coherent_manifest",
    ):
        tests += "#[test]\nfn %s() {}\n" % name
open(os.path.join(root, "src/domain/storage_deal.rs"), "w").write(
    "    pub fn open_deal(&mut self) -> Result<(), String> {\n        %s\n        Ok(())\n    }\n%s" % (call, tests)
)
# The real file names this command twice: once where the client method
# sends it, once in the arm that handles it. Only the arm validates, so a
# gate that takes the first match reports a guarded door as unguarded.
open(os.path.join(root, "src/chain/chain_actor.rs"), "w").write(
    "pub async fn register_storage_manifest(&self) {\n"
    "    self.tx.send(ChainCommand::RegisterStorageManifest {\n"
    "        manifest,\n        response: tx,\n    }).await;\n}\n"
    "ChainCommand::RegisterStorageManifest { manifest, response } => {\n"
    "    if let Err(e) = manifest.validate_untrusted() { return; }\n}\n"
)
PYB
  }

  # 1. Both doors strong: the corrected shape must pass.
  build "$tmp/good" strong strong present
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    return 1
  fi

  # 2. The original bug: the deal door settles for `verify_id`.
  build "$tmp/weakdoor" strong weak present
  expect_finding "$tmp/weakdoor" "a deal-open that only calls verify_id" || return 1

  # 3. The check itself is hollowed out while both call sites still call it.
  #    Name-based checking alone would call this fixed.
  build "$tmp/hollow" weak strong present
  expect_finding "$tmp/hollow" "a validate_untrusted that checks no scheme" || return 1

  # 4. The check disappears entirely.
  build "$tmp/gone" gone strong present
  expect_finding "$tmp/gone" "a missing validate_untrusted" || return 1

  # 5. A regression test is dropped.
  build "$tmp/notest" strong strong absent
  expect_finding "$tmp/notest" "a missing regression test" || return 1

  # 6. The guarded handler must still pass when the same command name also
  #    appears at the `send` site. Every fixture above already carries both
  #    spellings, so a gate matching the first occurrence fails canary 1;
  #    this asserts the distinction directly, on a tree where the handler is
  #    guarded and the sender, correctly, validates nothing.
  build "$tmp/twin" strong strong present
  if ! ( scan "$tmp/twin" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the `send` site was mistaken for the handler, so a" >&2
    echo "guarded door was reported as unguarded." >&2
    return 1
  fi

  echo "untrusted manifest gate self-test OK: 6 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
