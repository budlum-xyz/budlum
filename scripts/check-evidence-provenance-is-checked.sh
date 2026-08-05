#!/usr/bin/env bash
# ============================================================================
# check-evidence-provenance-is-checked.sh
#
# A slashing report may only move stake once the consensus layer has verified
# it.
#
# Why this gate exists.
#
# `SlashingReport` carries a `provenance` field with two values.
# `ConsensusVerified` means the local consensus engine checked the signatures
# or the quorum. `Unverified` means the report arrived from outside, through
# the permissionless `slash-evidence-submit` endpoint, and nobody has checked
# anything yet.
#
# `is_actionable` refuses the second. Its own doc says that refusal is "what
# keeps the permissionless slash-evidence-submit endpoint safe without a
# whitelist", and the field exists for no other reason.
#
# The risk is direct: an externally submitted report passes structural
# validation. Every field is present, the addresses are non-zero, the block
# hashes differ. A path that validates shape and then slashes would cut a
# validator's stake on a claim nobody verified, and anyone can submit one.
#
# What this gate checks:
#
#   1. `is_actionable` still refuses `Unverified`. A version that returned
#      `Ok` for both provenances would satisfy every call-site check below
#      and protect nothing.
#   2. `slash_from_report`, the entry point that takes a typed report, calls
#      it. That is the path evidence flows through.
#   3. The two callers of the bare `slash` are the ones that may use it. Both
#      sit behind consensus: the account-state mirror of a slash consensus
#      already decided, and the executor's Lubot equivocation path where the
#      same block carries the proof. A third caller appearing means someone
#      routed evidence around the provenance check, and the gate names the
#      file so the review is about that specific line.
#
# What this gate does not check: whether `ConsensusVerified` was set
# honestly. That is the producing engine's job, and a report that lies about
# its own provenance is a bug in the engine that set it, not in this check.
#
# Usage:
#   bash scripts/check-evidence-provenance-is-checked.sh
#   bash scripts/check-evidence-provenance-is-checked.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
evidence = os.path.join(root, "src", "registry", "evidence.rs")
registry = os.path.join(root, "src", "registry", "permissionless.rs")

for path in (evidence, registry):
    if not os.path.isfile(path):
        print(f"FAIL: expected source file missing: {path}", file=sys.stderr)
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


ev_code = strip_comments(open(evidence, encoding="utf-8").read())
reg_raw = open(registry, encoding="utf-8").read()
reg_code = strip_comments(reg_raw)
reg_prod = reg_code.split("#[cfg(test)]")[0]

problems = []
checked = 0

# 1. The check itself must still refuse unverified reports.
checked += 1
actionable = body_of(ev_code, r"pub fn is_actionable\s*\(")
if actionable is None:
    problems.append(
        "`SlashingReport::is_actionable` is gone. It is the only thing "
        "standing between an externally submitted claim and a validator's "
        "stake."
    )
else:
    checked += 1
    if "Unverified" not in actionable:
        problems.append(
            "`is_actionable` no longer mentions `Unverified`, so it does not "
            "distinguish a consensus-verified report from one anybody can "
            "submit. The provenance field then decides nothing."
        )
    checked += 1
    if "Err(" not in actionable:
        problems.append(
            "`is_actionable` never returns an error. A check that accepts "
            "every report satisfies every call-site test and protects "
            "nothing."
        )
    checked += 1
    if "validate_shape" not in actionable:
        problems.append(
            "`is_actionable` no longer runs the structural check, so a "
            "malformed report that happens to be consensus-verified would "
            "pass."
        )

# 2. The typed entry point must call it.
checked += 1
from_report = body_of(reg_prod, r"pub fn slash_from_report\s*\(")
if from_report is None:
    problems.append(
        "`slash_from_report` is gone. Evidence then has no entry point that "
        "reads its provenance."
    )
else:
    checked += 1
    if "is_actionable" not in from_report:
        problems.append(
            "`slash_from_report` does not call `is_actionable`. It takes a "
            "report, so it can see the provenance field, and skipping the "
            "check is exactly the hole the field exists to close."
        )

# 3. The bare `slash` may only be reached from paths that already sit behind
#    consensus. A new caller is not automatically wrong, but it is always
#    worth a look, so the gate names it.
checked += 1
allowed = {
    "src/core/account.rs",
    "src/execution/executor.rs",
    "src/registry/permissionless.rs",
}
unexpected = []
for dirpath, _dirs, files in os.walk(os.path.join(root, "src")):
    for name in files:
        if not name.endswith(".rs"):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        # `/tests/` covers the test tree; `_tests.rs` covers test modules
        # that live next to the code they exercise, which this repo does for
        # registry scenarios.
        if rel in allowed or "/tests/" in rel or rel.endswith("_tests.rs"):
            continue
        text = strip_comments(open(path, encoding="utf-8").read())
        prod = text.split("#[cfg(test)]")[0]
        if re.search(r"\.slash(_role_only)?\s*\(", prod):
            unexpected.append(rel)
if unexpected:
    problems.append(
        "a new caller reaches the bare `slash` without going through "
        f"`slash_from_report`: {', '.join(sorted(unexpected))}. The bare form "
        "takes a condition and trusts it, which is right only where consensus "
        "already decided. If this path carries a `SlashingReport`, it should "
        "use `slash_from_report` so the provenance is read."
    )

# 4. The regressions must exist as real tests somewhere in the tree.
checked += 1
found_unverified_test = False
for dirpath, _dirs, files in os.walk(os.path.join(root, "src")):
    for name in files:
        if name.endswith(".rs"):
            text = open(os.path.join(dirpath, name), encoding="utf-8").read()
            if "ProofProvenance::Unverified" in text and "#[test]" in text:
                found_unverified_test = True
if not found_unverified_test:
    problems.append(
        "no test constructs a report with `ProofProvenance::Unverified`. The "
        "refusal is then asserted by nothing."
    )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"evidence provenance gate OK: {checked} checks, unverified reports "
    "cannot move stake"
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

  # Fixtures are written by python: bodies contain `#[test]`, and bash treats
  # `[` as a glob inside `${var//pattern/...}`, so a substitution would
  # silently do nothing and leave the canary asserting against an unmodified
  # tree.
  build() {
    python3 - "$@" <<'PYB'
import os
import sys

root, check_mode, call_mode, caller_mode, test_mode = sys.argv[1:6]
for sub in ("src/registry", "src/core", "src/execution", "src/rpc"):
    os.makedirs(os.path.join(root, sub), exist_ok=True)

if check_mode == "gone":
    actionable = ""
elif check_mode == "always_ok":
    actionable = """    pub fn is_actionable(&self) -> Result<(), EvidenceError> {
        self.validate_shape()?;
        Ok(())
    }
"""
elif check_mode == "no_shape":
    actionable = """    pub fn is_actionable(&self) -> Result<(), EvidenceError> {
        match self.provenance {
            ProofProvenance::ConsensusVerified => Ok(()),
            ProofProvenance::Unverified => Err(EvidenceError::Unverified),
        }
    }
"""
else:
    actionable = """    pub fn is_actionable(&self) -> Result<(), EvidenceError> {
        self.validate_shape()?;
        match self.provenance {
            ProofProvenance::ConsensusVerified => Ok(()),
            ProofProvenance::Unverified => Err(EvidenceError::Unverified),
        }
    }
"""

tests = ""
if test_mode == "present":
    tests = """
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unverified_is_refused() {
        let r = report_with(ProofProvenance::Unverified);
        assert!(r.is_actionable().is_err());
    }
}
"""
open(os.path.join(root, "src/registry/evidence.rs"), "w").write(
    "impl SlashingReport {\n" + actionable + "}\n" + tests
)

if call_mode == "gone":
    from_report = ""
elif call_mode == "skips":
    from_report = """    pub fn slash_from_report(&mut self, report: &SlashingReport) -> Result<Option<SlashOutcome>, EvidenceError> {
        let condition = report.condition();
        let ratio = self.params.slash_ratio(condition);
        self.slash(report.offender, report.role, condition, ratio).ok();
        Ok(None)
    }
"""
else:
    from_report = """    pub fn slash_from_report(&mut self, report: &SlashingReport) -> Result<Option<SlashOutcome>, EvidenceError> {
        report.is_actionable()?;
        let condition = report.condition();
        let ratio = self.params.slash_ratio(condition);
        self.slash(report.offender, report.role, condition, ratio).ok();
        Ok(None)
    }
"""
open(os.path.join(root, "src/registry/permissionless.rs"), "w").write(
    "impl PermissionlessRegistry {\n"
    + from_report
    + "    pub fn slash(&mut self, a: Address, r: RoleId, c: SlashingCondition, s: u64) -> Result<SlashOutcome, RegistryError> { todo!() }\n"
    + "}\n"
)

# The two allowed callers always exist.
open(os.path.join(root, "src/core/account.rs"), "w").write(
    "fn mirror(&mut self) { let _ = self.registry.slash(a, r, c, s); }\n"
)
open(os.path.join(root, "src/execution/executor.rs"), "w").write(
    "fn lubot(&mut self) { let _ = self.registry.slash_role_only(a, r, c, s); }\n"
)

# A third caller appears when the fixture asks for one.
if caller_mode == "extra":
    open(os.path.join(root, "src/rpc/server.rs"), "w").write(
        "async fn submit(&self) { let _ = self.registry.slash(a, r, c, s); }\n"
    )
else:
    open(os.path.join(root, "src/rpc/server.rs"), "w").write(
        "async fn submit(&self) { let _ = self.registry.slash_from_report(&report); }\n"
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

  # 2. The check disappears.
  build "$tmp/nocheck" gone ok ok present
  expect_finding "$tmp/nocheck" "a missing is_actionable" || return 1

  # 3. The subtle one: `is_actionable` still exists, still runs the structural
  #    check, and accepts every provenance. Every call site still calls it.
  build "$tmp/alwaysok" always_ok ok ok present
  expect_finding "$tmp/alwaysok" "a check that accepts unverified reports" || return 1

  # 4. Provenance is read, structure is not.
  build "$tmp/noshape" no_shape ok ok present
  expect_finding "$tmp/noshape" "a check that skips structural validation" || return 1

  # 5. The typed entry point disappears.
  build "$tmp/nofrom" ok gone ok present
  expect_finding "$tmp/nofrom" "a missing slash_from_report" || return 1

  # 6. The typed entry point stops calling the check.
  build "$tmp/skips" ok skips ok present
  expect_finding "$tmp/skips" "an entry point that skips the provenance check" || return 1

  # 7. A third caller routes around the typed path.
  build "$tmp/extra" ok ok extra present
  expect_finding "$tmp/extra" "a new caller reaching the bare slash" || return 1

  # 8. Nothing asserts the refusal.
  build "$tmp/notest" ok ok ok absent
  expect_finding "$tmp/notest" "a missing regression test" || return 1

  echo "evidence provenance gate self-test OK: 7 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
