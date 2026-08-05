#!/usr/bin/env bash
# ============================================================================
# check-lock-failures-do-not-open-a-bound.sh
#
# A lock that fails must not answer "yes" to a question that admits a peer.
#
# Why this gate exists.
#
# `node.rs` recovers from a poisoned `PeerManager` mutex in 76 places, through
# a helper written for exactly that purpose:
#
#     fn peer_manager_lock(&self) -> MutexGuard<'_, PeerManager> {
#         self.peer_manager.lock().unwrap_or_else(|poisoned| {
#             tracing::error!("PeerManager lock was poisoned ...");
#             poisoned.into_inner()
#         })
#     }
#
# Four sites did not use it. They read
#
#     self.peer_manager.lock().map(|pm| pm.can_admit_subnet(subnet))
#         .unwrap_or(true)
#
# and `true` is the permissive answer. A `Mutex` poisons the moment any thread
# panics while holding it, and this tree already assumes that happens: the
# helper exists because fourteen sites used to `process::exit(1)` on it, and
# `poisoned_lock_locks.rs` pins that they no longer do.
#
# So after one panic anywhere near the peer table, `can_admit_subnet` stops
# rejecting and the /24 eclipse bound is off. One operator can then fill the
# peer table from a single subnet and surround the node. The two bookkeeping
# sites had the mirror problem: connect and disconnect both reported success
# unconditionally, so `peer_count` drifted in both directions.
#
# The shape is worth naming because it reads as defensive. `unwrap_or` looks
# like a safe default, and for a display value it is. For a bound that decides
# whether to admit a peer, the safe default is the restrictive one, and the
# genuinely safe answer is not to have a default at all: recover the guard and
# keep enforcing.
#
# What the gate checks.
#
# In production code, a lock result that feeds an admission decision must not
# be defaulted open. Concretely: a line containing `unwrap_or(true)` or
# `unwrap_or_else(|_| true)` within three lines of a `.lock()` is a finding,
# unless the enclosing function carries `FAILOPEN: allowed - <reason>`.
#
# Known limits, stated so a pass is not read for more than it carries.
# It measures the `lock() ... unwrap_or(true)` shape textually. A default-open
# reached through a named helper, or written as `if let Ok(..) {} else { true }`,
# is not caught. It closes the shape that was actually here, and the
# `poisoned_lock_locks.rs` tests carry the rest.
#
# Usage:
#   bash scripts/check-lock-failures-do-not-open-a-bound.sh              # gate
#   bash scripts/check-lock-failures-do-not-open-a-bound.sh --self-test  # canary
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
MARKER = re.compile(r"FAILOPEN:\s*allowed\b(.*)")


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

OPEN = re.compile(r"unwrap_or\(\s*true\s*\)|unwrap_or_else\(\s*\|_\|\s*true\s*\)")

problems = []
checked_locks = 0

for path in files:
    try:
        src = strip_test_mods(open(path, encoding="utf-8", errors="ignore").read())
    except OSError as exc:
        print(f"FAIL: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)

    if ".lock()" not in src:
        continue
    lines = src.splitlines()

    # A function carrying the marker is exempt for its whole body. Cheap
    # approximation: collect the line ranges of marked functions.
    exempt_from = []
    for i, line in enumerate(lines):
        if MARKER.search(line):
            exempt_from.append(i)

    for i, line in enumerate(lines):
        t = line.lstrip()
        if t.startswith("//"):
            continue
        if ".lock()" not in line:
            continue
        checked_locks += 1
        # The default may sit a few lines below, after `.map(..)`.
        window = lines[i:min(i + 6, len(lines))]
        for offset, w in enumerate(window):
            if w.lstrip().startswith("//"):
                continue
            if not OPEN.search(w):
                continue
            # Marker anywhere in the 30 lines above counts as the enclosing
            # function declaring itself.
            declared = any(i - 30 <= e <= i for e in exempt_from)
            if declared:
                break
            rel = os.path.relpath(path, root)
            problems.append(
                f"{rel}:{i + offset + 1}: a `.lock()` failure defaults to `true`. "
                "`true` is the permissive answer, so the bound this feeds stops "
                "rejecting the moment the mutex is poisoned, which is exactly "
                "when something has already gone wrong. Recover the guard "
                "instead (see `peer_manager_lock`), or write "
                "`FAILOPEN: allowed - <reason>` on the function."
            )
            break

if not checked_locks:
    print(
        "FAIL: gate found no `.lock()` call to measure - wrong root, or the "
        "locking pattern changed shape.",
        file=sys.stderr,
    )
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"lock-failure gate OK: {checked_locks} `.lock()` sites, none of them "
    "defaulting a bound open on failure"
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
      echo "GATE MISREPORTS: $what exited $rc, expected 2." >&2
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
  mk "$tmp/open" 'impl Node {
    fn admit(&self, subnet: Option<[u8; 3]>) -> bool {
        self.peer_manager
            .lock()
            .map(|pm| pm.can_admit_subnet(subnet))
            .unwrap_or(true)
    }
}'
  expect_finding "$tmp/open" "a lock failure defaulting a bound open" || return 1

  # 2. The fix: recover the guard and keep enforcing.
  mk "$tmp/recovered" 'impl Node {
    fn admit(&self, subnet: Option<[u8; 3]>) -> bool {
        self.peer_manager_lock().can_admit_subnet(subnet)
    }
    fn peer_manager_lock(&self) -> MutexGuard<'"'"'_, PeerManager> {
        self.peer_manager.lock().unwrap_or_else(|p| p.into_inner())
    }
}'
  expect_pass "$tmp/recovered" "a recovered guard" || return 1

  # 3. Failing closed is also correct.
  mk "$tmp/closed" 'impl Node {
    fn admit(&self, subnet: Option<[u8; 3]>) -> bool {
        self.peer_manager
            .lock()
            .map(|pm| pm.can_admit_subnet(subnet))
            .unwrap_or(false)
    }
}'
  expect_pass "$tmp/closed" "a lock failure that denies" || return 1

  # 4. Declared exception with a reason.
  mk "$tmp/declared" 'impl Node {
    /// FAILOPEN: allowed - this is a display counter, not an admission
    /// decision; showing a stale number beats blocking the UI.
    fn is_visible(&self) -> bool {
        self.peer_manager.lock().map(|pm| pm.visible()).unwrap_or(true)
    }
}'
  expect_pass "$tmp/declared" "a declared fail-open with a reason" || return 1

  # 5. `unwrap_or(true)` far from any lock is not this bug.
  mk "$tmp/unrelated" 'impl Node {
    fn flag(&self, cfg: &Config) -> bool {
        cfg.mobile_mode.map(|m| m).unwrap_or(true)
    }
    fn admit(&self) -> bool {
        self.peer_manager.lock().map(|pm| pm.ok()).unwrap_or(false)
    }
}'
  expect_pass "$tmp/unrelated" "an unwrap_or(true) with no lock nearby" || return 1

  # 6. A commented-out default is not a default.
  mk "$tmp/commented" 'impl Node {
    fn admit(&self) -> bool {
        // .unwrap_or(true) was the bug; it is gone
        self.peer_manager.lock().map(|pm| pm.ok()).unwrap_or(false)
    }
}'
  expect_pass "$tmp/commented" "a commented-out fail-open" || return 1

  # 7. Nothing to measure is exit 2, never a pass.
  mk "$tmp/nolocks" 'impl Node {
    fn total(&self) -> u64 {
        self.count
    }
}'
  expect_broken "$tmp/nolocks" "a tree with no lock at all" || return 1

  echo "lock-failure gate self-test OK: a bound defaulted open is rejected and \
a tree with no lock reports nothing measured; a recovered guard, a fail-closed \
default, a declared exception, an unrelated unwrap_or(true) and a commented-out \
one all pass."
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
