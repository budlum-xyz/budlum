#!/usr/bin/env bash
# ============================================================================
# check-refusals-do-not-mutate-first.sh
#
# A function that can still refuse must not have taken anything out yet.
#
# Why this gate exists.
#
# `AiRegistry::settle_agent_payment_immediate` removed the payment from the
# live map and then decided whether to accept it:
#
#   let payment = self.agent_payments.remove(payment_id).ok_or(..)?;
#   if payment.is_escrowed() {
#       self.agent_payments.insert(payment.payment_id, payment);  // put back
#       return Err(..);
#   }
#   if self.settled_agent_payments.contains_key(payment_id) {
#       return Err(..);                                           // and not here
#   }
#
# One refusal path restored the entry and the other did not. A second settle
# therefore reported failure *and* consumed the live payment on its way out,
# leaving nothing for release or reclaim to find while the caller had been
# told the call failed.
#
# It was reachable from production: `executor.rs` credits the recipient and
# then calls this, and `apply_block_checked` propagates the error with `?`
# without rolling anything back, so a torn write stays torn.
#
# The shape is easy to write and hard to see. `remove(..)?` reads like a
# lookup, because most of the time the happy path is the only one anybody
# pictures. The fix is ordering, not bookkeeping: decide every refusal while
# the value is still in place, and only then take it out.
#
# What the gate checks.
#
# In production code, a function returning `Result` that calls `.remove(` on
# a `self.` collection and *afterwards* reaches a `return Err(` must either
# restore what it removed on that path (an `.insert(` between the two), or
# carry `PARTIAL: allowed - <reason>` in the function's doc comment.
#
# Known limits, stated so a pass is not read for more than it carries.
# This measures textual order inside one function body. It cannot see a
# refusal that lives in a helper the function calls, and it does not model
# control flow, so an `insert` on an unrelated branch counts as a restore.
# It catches the shape that bit us, which is a `remove` at the top and a
# `return Err` below it with nothing putting the value back.
#
# Usage:
#   bash scripts/check-refusals-do-not-mutate-first.sh              # gate
#   bash scripts/check-refusals-do-not-mutate-first.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
SCAN_ROOTS = ("src", "budzero", "wallet-core")
MARKER = re.compile(r"PARTIAL:\s*allowed\b(.*)")


def balanced(src, open_at):
    depth, j = 0, open_at
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at:j + 1]
        j += 1
    return src[open_at:]


def strip_test_mods(src):
    out, i = [], 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{", src[i:])
        if not m:
            out.append(src[i:])
            return "".join(out)
        start, brace = i + m.start(), i + m.end() - 1
        out.append(src[i:start])
        depth, j = 0, brace
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        i = j + 1


def is_test_path(path):
    return (
        f"{os.sep}tests{os.sep}" in path
        or path.endswith("_tests.rs")
        or path.endswith(f"{os.sep}tests.rs")
    )


def doc_above(src, at):
    """The doc comment block immediately preceding `at`."""
    lines = src[:at].splitlines()
    doc = []
    for line in reversed(lines[:-1] if lines else []):
        t = line.strip()
        if t.startswith("///") or t.startswith("//"):
            doc.append(t)
            continue
        if t.startswith("#[") or not t:
            continue
        break
    return "\n".join(reversed(doc))


files = []
for scan_root in SCAN_ROOTS:
    base = os.path.join(root, scan_root)
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "node_modules")]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if name.endswith(".rs") and not is_test_path(path):
                files.append(path)

if not files:
    print(f"FAIL: no production .rs files found under {root}", file=sys.stderr)
    sys.exit(2)

problems = []
checked_fns = 0

FN = re.compile(r"\bfn\s+(\w+)\s*\([^)]*\)\s*->\s*Result<")

for path in files:
    try:
        src = strip_test_mods(open(path, encoding="utf-8", errors="ignore").read())
    except OSError as exc:
        print(f"FAIL: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)

    for m in FN.finditer(src):
        brace = src.find("{", m.end())
        if brace < 0:
            continue
        body = balanced(src, brace)
        lines = body.splitlines()

        # `self.foo.remove(..)` is often written across three lines by
        # rustfmt:
        #
        #     let payment = self
        #         .agent_payments
        #         .remove(payment_id)
        #
        # A single-line regex demanding `self.<field>.remove(` matches none of
        # them, and a name-based gate that matches nothing reports nothing: the
        # first version of this gate passed the very function it was written
        # for. Join each line with the two above it before testing, so a
        # wrapped receiver reads the same as an inline one.
        def receiver_is_self(idx):
            window = " ".join(
                lines[k].strip() for k in range(max(0, idx - 2), idx + 1)
            )
            return re.search(r"self\s*\.\s*\w+\s*\.\s*remove\(", window) is not None

        removes = [
            i for i, l in enumerate(lines)
            if not l.strip().startswith("//")
            and ".remove(" in l
            and receiver_is_self(i)
        ]
        if not removes:
            continue
        checked_fns += 1

        first_remove = removes[0]
        later_err = [
            i for i, l in enumerate(lines)
            if i > first_remove
            and not l.strip().startswith("//")
            and re.search(r"return\s+Err\(", l)
        ]
        if not later_err:
            continue

        # A refusal counts as guarded only when something puts the value back
        # between the remove and that refusal. Checking against the LAST
        # refusal was the mistake the original bug would have walked through:
        # `settle_agent_payment_immediate` restored on its first refusal and
        # not on its second, and an any() over the whole span read the first
        # insert as covering both. Each refusal is asked separately, and the
        # first unguarded one is the finding.
        def guarded(err_line):
            return any(
                re.search(r"\.insert\(", lines[i])
                for i in range(first_remove + 1, err_line)
                if not lines[i].strip().startswith("//")
            )

        unguarded = [i for i in later_err if not guarded(i)]
        restored = not unguarded
        declared = MARKER.search(doc_above(src, m.start()))

        if restored and not declared:
            continue
        if declared and not later_err:
            continue
        if not restored and not declared:
            rel = os.path.relpath(path, root)
            line_no = src[:brace].count("\n") + 1 + first_remove + 1
            problems.append(
                f"{rel}:{line_no}: `{m.group(1)}` removes from a `self.` collection and "
                "can still `return Err` afterwards, with nothing putting the value "
                "back. The caller is told the call failed while the entry is gone, "
                "and nothing rolls it back. Decide every refusal before the remove, "
                "restore it on the failing path, or write `PARTIAL: allowed - "
                "<reason>` in the function's doc."
            )

if not checked_fns:
    print(
        "FAIL: gate found no Result-returning fn that removes from a collection - "
        "wrong root, or the pattern changed shape.",
        file=sys.stderr,
    )
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"partial-write gate OK: {checked_fns} Result-returning fns remove from a "
    "collection, each deciding its refusals first, restoring on failure, or "
    "declaring why a partial write is allowed"
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
      echo "Exit 2 means the gate measured nothing; that is not a pass." >&2
      return 1
    fi
  }

  expect_pass() {
    local dir="$1" what="$2"
    if ! ( scan "$dir" ) >/dev/null 2>&1; then
      echo "GATE IS WRONG: $what was rejected!" >&2
      return 1
    fi
  }

  expect_broken() {
    local dir="$1" what="$2" rc=0
    ( scan "$dir" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
      echo "GATE MISREPORTS: $what exited $rc, expected 2 (measured nothing)." >&2
      return 1
    fi
  }

  mk() {
    local dir="$1" body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/src"
    printf '%s\n' "$body" >"$dir/src/lib.rs"
  }

  # 1. The bug this gate exists for, in the shape it had.
  mk "$tmp/torn" 'impl Registry {
    pub fn settle(&mut self, id: &u64) -> Result<(), String> {
        let payment = self.payments.remove(id).ok_or("missing")?;
        if self.settled.contains_key(id) {
            return Err(String::from("already settled"));
        }
        self.settled.insert(*id, payment);
        Ok(())
    }
}'
  expect_finding "$tmp/torn" "a remove followed by an unrestored refusal" || return 1

  # 2. The fix: every refusal decided before the remove.
  mk "$tmp/ordered" 'impl Registry {
    pub fn settle(&mut self, id: &u64) -> Result<(), String> {
        let payment = self.payments.get(id).ok_or("missing")?;
        if self.settled.contains_key(id) {
            return Err(String::from("already settled"));
        }
        let payment = self.payments.remove(id).ok_or("missing")?;
        self.settled.insert(*id, payment);
        Ok(())
    }
}'
  expect_pass "$tmp/ordered" "a fn that decides refusals before removing" || return 1

  # 3. Restoring on the failing path is also correct.
  mk "$tmp/restored" 'impl Registry {
    pub fn settle(&mut self, id: &u64) -> Result<(), String> {
        let payment = self.payments.remove(id).ok_or("missing")?;
        if payment.escrowed {
            self.payments.insert(*id, payment);
            return Err(String::from("escrowed"));
        }
        Ok(())
    }
}'
  expect_pass "$tmp/restored" "a fn that puts the value back before failing" || return 1

  # 4. Declared exception with a reason.
  mk "$tmp/declared" 'impl Registry {
    /// PARTIAL: allowed - the removal is the point; the error only reports
    /// how much was consumed.
    pub fn drain(&mut self, id: &u64) -> Result<(), String> {
        let payment = self.payments.remove(id).ok_or("missing")?;
        if payment.escrowed {
            return Err(String::from("partially drained"));
        }
        Ok(())
    }
}'
  expect_pass "$tmp/declared" "a declared partial write with a reason" || return 1

  # 5. A remove with no refusal after it is not this bug and must not be
  #    flagged, or the gate cries wolf on every ordinary consumer.
  mk "$tmp/clean" 'impl Registry {
    pub fn settle(&mut self, id: &u64) -> Result<(), String> {
        if self.settled.contains_key(id) {
            return Err(String::from("already settled"));
        }
        let payment = self.payments.remove(id).ok_or("missing")?;
        self.settled.insert(*id, payment);
        Ok(())
    }
}'
  expect_pass "$tmp/clean" "a remove with every refusal above it" || return 1

  # 6. A commented-out refusal is not a refusal.
  mk "$tmp/commented" 'impl Registry {
    pub fn settle(&mut self, id: &u64) -> Result<(), String> {
        let payment = self.payments.remove(id).ok_or("missing")?;
        // return Err(String::from("this line is a comment"));
        self.settled.insert(*id, payment);
        Ok(())
    }
}'
  expect_pass "$tmp/commented" "a commented-out refusal after a remove" || return 1

  # 7. Nothing to measure must be exit 2, never a pass.
  mk "$tmp/none" 'impl Registry {
    pub fn get(&self, id: &u64) -> Option<u64> {
        self.payments.get(id).copied()
    }
}'
  expect_broken "$tmp/none" "a tree with no Result fn that removes" || return 1

  echo "partial-write gate self-test OK: an unrestored refusal after a remove \
is rejected and a tree with nothing to measure reports so; ordering the \
refusals first, restoring before failing, a declared exception, a remove with \
no refusal after it, and a commented-out refusal all pass."
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  "")
    scan "$ROOT"
    ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
