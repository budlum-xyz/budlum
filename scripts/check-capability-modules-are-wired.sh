#!/usr/bin/env bash
# ============================================================================
# check-capability-modules-are-wired.sh
#
# A module that exports a capability nobody calls must say so in its own docs.
#
# Why this gate exists.
#
# `src/storage/mobile_self.rs` defines `MobileSelfProfile`,
# `ReplicaRecommendation` and `MobileSelfContentPolicy`. Its module doc states
# the rule the design depends on: a phone may self-host B.U.D. data, but must
# never be treated as always-online storage, and critical content has to carry
# a paid replica. `recommendation_for_content` and `validate_against_profile`
# implement exactly that rule, and both are tested.
#
# Neither is called from anywhere in the production tree. `storage/mod.rs`
# re-exports the types with `pub use`, which is not a call. So the rule exists,
# passes its tests, and never runs. Nothing in the tree refuses to put critical
# content on an opportunistic phone, because the code that would refuse is
# never reached.
#
# This is a different failure from an orphan file, which
# check-no-orphan-source-files.sh already catches. An orphan is not compiled at
# all. These modules *are* compiled, *are* linted, *are* covered, and show a
# healthy green test run, which is precisely why they read as finished work. A
# reader counting capabilities finds `MobileSelfContentPolicy` and concludes
# the policy is enforced. Test coverage is the strongest possible evidence for
# that wrong conclusion: the tests pass because the function is correct, not
# because anything invokes it.
#
# Six other modules measured the same way, among them
# `src/storage/erasure.rs`, whose own module doc explains that a manifest
# declaring `(k=4, n=6)` was "a promise the code could not keep" until parity
# could actually be computed. The coder was written. It is not called either,
# so the promise is still open, one layer further in.
#
# What the gate checks.
#
# For every production module exporting at least MIN_PUB_FNS public functions:
# if no other production file calls any of them, the module must declare it in
# its own module documentation:
#
#     //! WIRING: unwired - <reason>
#
# The marker sits next to the code rather than in a central allowlist on
# purpose. A central list is edited by whoever is adding an entry, and grows
# quietly. A marker in the module doc is read by the next person who opens the
# file, which is the person who can act on it.
#
# The gate also refuses the reverse. If a module carries the marker and the
# tree does call it, the marker is stale and the doc now understates what the
# module does. Wiring a module and deleting its marker belong in one commit.
#
# The gate does not require modules to be wired. Shipping a capability
# unfinished is a schedule decision. Presenting an unfinished one as finished
# is not.
#
# Ambiguous names prove nothing. `calculate_leaf` is defined on more than ten
# different types in this tree. A bare `x.calculate_leaf()` somewhere therefore
# does not tell us whose method ran, and counting it as a call marked
# `mobile_self.rs` wired when nothing reaches it. Any name defined by more than
# one production module is discarded as evidence.
#
# A module whose *entire* surface is ambiguous names is skipped rather than
# reported. There is no evidence either way about it, and a gate that reports
# absence of evidence as evidence of absence teaches people to add markers to
# silence it. `src/core/address.rs` is the example: `zero`, `as_bytes` and
# `to_hex` are spelled the same on several types, and it is called from
# hundreds of places. Skipping costs some coverage and keeps every failure the
# gate does print true.
#
# A name preceded by `::` belongs to whatever is on the left of it, not to this
# module. `developer_os.rs` has an `SdkFeature::MobileSelfProfile` enum variant
# that merely happens to be spelled like `storage::mobile_self`'s struct, and
# counting it marked the module wired while nothing reached it. Evidence
# therefore never matches a name that follows a path separator, unless the
# segment before it is this module's own name.
#
# Types count as much as functions. `poa.rs` exports `PoAEngine`, whose methods
# are reached through `dyn ConsensusEngine`, so no call names them; `main.rs`
# nonetheless constructs it by type. `proof_verifier.rs` is reached through its
# constants. Measuring only function names accused both. A module is therefore
# also wired when another production file names one of the types, constants or
# statics it declares, which is the shape a `dyn` dispatch or a constant lookup
# actually leaves behind at the call site.
#
# Known limits, stated so nobody reads more into a pass than it carries.
# Reachability is measured by name. A module reached only through a value
# passed as a bare function pointer, with no type or constant of its own
# named anywhere, is not seen; such a module needs its marker removed by hand
# and the reason recorded. `new`, `default`, `fmt`, `from`,
# `into` and `validate` are excluded from the export count because they are
# implemented nearly everywhere and would swamp the signal.
#
# Usage:
#   bash scripts/check-capability-modules-are-wired.sh              # gate
#   bash scripts/check-capability-modules-are-wired.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]

# Roots that hold shipped library code. Benches, fuzz targets, kani harnesses
# and examples are drivers: they call into the tree and are not called by it,
# so measuring them for inbound calls would flag every one of them.
SCAN_ROOTS = ("src", "budzero", "wallet-core")

# Below this a module is a small helper, not a capability surface, and the
# name-based measurement is too noisy to act on.
MIN_PUB_FNS = 3

# Implemented almost everywhere; counting them would drown the signal.
UBIQUITOUS = {"new", "default", "fmt", "from", "into", "validate"}

MARKER = re.compile(r"^\s*//!\s*WIRING:\s*unwired\b(.*)$", re.MULTILINE)


def strip_test_mods(src):
    """Remove `#[cfg(test)] mod ... { ... }` blocks, brace-matched.

    Cutting at the first `#[cfg(test)]` instead would silently drop the
    production half of every file that keeps a test module in the middle,
    and those files would then look far deader than they are.
    """
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


USE_LINE = re.compile(r"^\s*(?:pub\s+)?use\s[^;]*;", re.MULTILINE | re.DOTALL)

ENUM_BODY = re.compile(
    r"\benum\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]*>\s*)?\{", re.MULTILINE
)


def strip_use_statements(src):
    """Drop `use` and `pub use` items.

    A re-export names every symbol it forwards, so counting those names as
    calls makes `pub use capability::{alpha, beta}` look exactly like code
    that invokes them. That is the confusion this whole gate exists to
    remove, so the evidence pool must not contain it. Imports are dropped for
    the same reason: naming a type in a `use` is not using it.
    """
    return USE_LINE.sub("", src)


def strip_enum_bodies(src):
    """Remove the inside of `enum ... { ... }` declarations.

    A variant list is a set of declarations, not uses. `SdkFeature` declaring
    a `MobileSelfProfile` variant matched the struct of that name in
    `storage/mobile_self.rs` and marked it wired, when in truth the two share
    nothing but spelling.
    """
    out, i = [], 0
    while True:
        m = ENUM_BODY.search(src, i)
        if not m:
            out.append(src[i:])
            return "".join(out)
        out.append(src[i:m.end() - 1])
        depth, j = 0, m.end() - 1
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        i = j


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
        dirnames[:] = [
            d for d in dirnames if d not in (".git", "target", "node_modules")
        ]
        for name in filenames:
            if name.endswith(".rs"):
                files.append(os.path.join(dirpath, name))

if not files:
    print(f"FAIL: no .rs files found under {root}", file=sys.stderr)
    sys.exit(2)

bodies = {}
for path in files:
    try:
        bodies[path] = strip_test_mods(
            open(path, encoding="utf-8", errors="ignore").read()
        )
    except OSError as exc:
        print(f"FAIL: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)

production = [p for p in files if not is_test_path(p)]

# What counts as evidence of a call: the file with its imports and re-exports
# removed.
evidence = {
    p: strip_enum_bodies(strip_use_statements(b)) for p, b in bodies.items()
}

# A name defined by more than one production module cannot identify a callee.
# Count definitions per name across the tree, once.
definers = {}
for path in production:
    for m in re.finditer(r"\bpub (?:async )?fn ([a-z_][a-z0-9_]*)", bodies[path]):
        definers.setdefault(m.group(1), set()).add(path)
    for m in re.finditer(
        r"\bpub (?:struct|enum|trait|const|static|type)\s+([A-Za-z_][A-Za-z0-9_]*)",
        bodies[path],
    ):
        definers.setdefault(m.group(1), set()).add(path)
ambiguous = {name for name, owners in definers.items() if len(owners) > 1}

problems = []
checked = 0
skipped = 0

for path in production:
    body = bodies[path]
    exported = {
        m.group(1)
        for m in re.finditer(r"\bpub (?:async )?fn ([a-z_][a-z0-9_]*)", body)
    } - UBIQUITOUS
    if len(exported) < MIN_PUB_FNS:
        continue

    # Types, constants and statics this module declares. A `dyn` dispatch names
    # none of the methods it calls, but the concrete type has to be named
    # somewhere for the value to exist at all.
    exported |= {
        m.group(1)
        for m in re.finditer(
            r"\bpub (?:struct|enum|trait|const|static|type)\s+([A-Za-z_][A-Za-z0-9_]*)",
            body,
        )
    }

    # Only names unique to this module can serve as evidence of a call. With
    # none, this module cannot be measured either way, so say nothing about it.
    identifying = exported - ambiguous
    if not identifying:
        skipped += 1
        continue

    checked += 1

    mod_name = os.path.splitext(os.path.basename(path))[0]

    callers = set()
    for other in production:
        if other == path:
            continue
        other_body = evidence[other]
        for fn in identifying:
            if fn in callers:
                continue
            # `(?<!:)` after the boundary rejects `Other::Name`: that names a
            # member of `Other`, not this module. `mod_name::Name` is kept,
            # since that is this module being addressed directly.
            pattern = (
                r"(?:(?<![a-zA-Z0-9_:])|(?<=\b"
                + re.escape(mod_name)
                + r"::))"
                + re.escape(fn)
                + r"(?![a-zA-Z0-9_])"
            )
            if re.search(pattern, other_body):
                callers.add(fn)
        if callers:
            break

    wired = bool(callers)
    declared = MARKER.search(body)
    rel = os.path.relpath(path, root)

    if not wired and not declared:
        problems.append(
            f"{rel} exports {len(exported)} public functions, and no other "
            f"production file calls any of the {len(identifying)} that are "
            "named uniquely enough to trace, but the module doc does not say "
            "so. A `pub use` re-export is not a call. Add "
            "`//! WIRING: unwired - <reason>` to the module doc, or wire it."
        )
    elif wired and declared:
        reason = declared.group(1).strip(" -\t")
        problems.append(
            f"{rel} is marked `WIRING: unwired` ({reason or 'no reason given'}) "
            "and the tree does call it. The marker is stale and now understates "
            "the module. Remove it in the commit that wired the module."
        )

if not checked:
    print(
        f"FAIL: gate checked no module (MIN_PUB_FNS={MIN_PUB_FNS} too high?)",
        file=sys.stderr,
    )
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"capability wiring gate OK: {checked} capability modules measured, "
    f"each either called or declaring that it is not "
    f"({skipped} skipped as untraceable by name)"
)
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # A canary that only asks "did it fail?" cannot tell a real finding (exit 1)
  # from the gate failing to measure anything at all (exit 2). The second is a
  # broken gate, and treating it as a pass is how a gate goes hollow.
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

  mk() {
    local dir="$1" lib_body="$2" caller_body="$3"
    rm -rf "$dir"
    mkdir -p "$dir/src"
    printf '%s\n' "$lib_body" >"$dir/src/capability.rs"
    printf '%s\n' "$caller_body" >"$dir/src/lib.rs"
  }

  local CAPABILITY='pub fn alpha() -> u8 { 1 }
pub fn beta() -> u8 { 2 }
pub fn gamma() -> u8 { 3 }'

  local MARKED='//! WIRING: unwired - kept until the caller lands.
pub fn alpha() -> u8 { 1 }
pub fn beta() -> u8 { 2 }
pub fn gamma() -> u8 { 3 }'

  local CALLS='pub mod capability;
pub fn drive() -> u8 { capability::alpha() }'

  local REEXPORT_ONLY='pub mod capability;
pub use capability::{alpha, beta, gamma};'

  # 1. Wired and unmarked: the ordinary healthy shape, must pass.
  mk "$tmp/wired" "$CAPABILITY" "$CALLS"
  if ! ( scan "$tmp/wired" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a module that is genuinely called was rejected!" >&2
    return 1
  fi

  # 2. Unwired and marked: honest, must pass.
  mk "$tmp/honest" "$MARKED" "$REEXPORT_ONLY"
  if ! ( scan "$tmp/honest" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: an unwired module that declares itself was rejected!" >&2
    return 1
  fi

  # 3. Unwired and silent: the bug this gate exists for. A `pub use` must not
  #    be mistaken for a call.
  mk "$tmp/silent" "$CAPABILITY" "$REEXPORT_ONLY"
  expect_finding "$tmp/silent" "a silently unwired capability module" || return 1

  # 4. Wired and still marked: a stale marker understating the module.
  mk "$tmp/stale" "$MARKED" "$CALLS"
  expect_finding "$tmp/stale" "a stale unwired marker on a wired module" || return 1

  # 5. A test-only caller must not count as wiring, which is the exact shape
  #    that made mobile_self.rs look finished.
  rm -rf "$tmp/testonly"
  mkdir -p "$tmp/testonly/src/tests"
  printf '%s\n' "$CAPABILITY" >"$tmp/testonly/src/capability.rs"
  printf '%s\n' "$REEXPORT_ONLY" >"$tmp/testonly/src/lib.rs"
  printf '%s\n' 'fn t() -> u8 { crate::capability::alpha() }' \
    >"$tmp/testonly/src/tests/drive.rs"
  expect_finding "$tmp/testonly" "a test-only caller counted as wiring" || return 1

  # 6. An inline #[cfg(test)] module must not count either.
  mk "$tmp/inline" "$CAPABILITY" "$REEXPORT_ONLY"
  cat >>"$tmp/inline/src/lib.rs" <<'RS'
#[cfg(test)]
mod tests {
    #[test]
    fn drives() {
        assert_eq!(crate::capability::alpha(), 1);
    }
}
RS
  expect_finding "$tmp/inline" "an inline test module counted as wiring" || return 1

  # 7. A name defined by two modules must not let a call to one of them count
  #    as wiring for the other. This is the shape that hid mobile_self.rs: its
  #    `calculate_leaf` shares a name with ten other types, and someone else's
  #    call to theirs made it look reached.
  rm -rf "$tmp/ambiguous"
  mkdir -p "$tmp/ambiguous/src"
  printf '%s\n' 'pub fn shared_name() -> u8 { 1 }
pub fn other_shared() -> u8 { 2 }
pub fn only_here_alpha() -> u8 { 3 }' >"$tmp/ambiguous/src/capability.rs"
  printf '%s\n' 'pub fn shared_name() -> u8 { 9 }
pub fn other_shared() -> u8 { 8 }
pub fn only_here_beta() -> u8 { 7 }' >"$tmp/ambiguous/src/twin.rs"
  printf '%s\n' 'pub mod capability;
pub mod twin;
pub fn drive() -> u8 { twin::shared_name() + twin::only_here_beta() }' \
    >"$tmp/ambiguous/src/lib.rs"
  expect_finding "$tmp/ambiguous" \
    "a call to a same-named function in a different module counted as wiring" \
    || return 1

  # 8. A module with no traceable name at all must be skipped, not accused.
  #    Reporting it would be reporting absence of evidence as evidence, and
  #    the only way to silence it would be a marker that says nothing true.
  #    Every other module in this fixture is called, so the single skipped one
  #    is the only thing the gate could possibly complain about.
  rm -rf "$tmp/untraceable"
  mkdir -p "$tmp/untraceable/src"
  printf '%s\n' 'pub fn shared_name() -> u8 { 1 }
pub fn other_shared() -> u8 { 2 }
pub fn third_shared() -> u8 { 3 }' >"$tmp/untraceable/src/capability.rs"
  printf '%s\n' 'pub fn shared_name() -> u8 { 9 }
pub fn other_shared() -> u8 { 8 }
pub fn third_shared() -> u8 { 7 }' >"$tmp/untraceable/src/twin.rs"
  # A measurable, properly wired module so the run is not empty. Without it
  # `checked` is zero, the gate exits 2, and this canary would be asserting
  # that the gate refused to measure rather than that it skipped politely.
  printf '%s\n' 'pub fn traceable_one() -> u8 { 1 }
pub fn traceable_two() -> u8 { 2 }
pub fn traceable_three() -> u8 { 3 }' >"$tmp/untraceable/src/measurable.rs"
  printf '%s\n' 'pub mod capability;
pub mod twin;
pub mod measurable;
pub fn drive() -> u8 { twin::shared_name() + measurable::traceable_one() }' \
    >"$tmp/untraceable/src/lib.rs"
  if ! ( scan "$tmp/untraceable" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a module with no uniquely-named export was accused" >&2
    echo "instead of skipped, so the only way to quiet it is a false marker." >&2
    return 1
  fi

  # 9. An enum variant spelled like this module's type belongs to the enum,
  #    not to the module. `SdkFeature::MobileSelfProfile` in developer_os.rs is
  #    exactly this, and counting it marked storage/mobile_self.rs wired while
  #    nothing reached it.
  rm -rf "$tmp/variant"
  mkdir -p "$tmp/variant/src"
  printf '%s\n' 'pub struct MobileSelfProfile { pub v: u8 }
pub fn alpha_only_here() -> u8 { 1 }
pub fn beta_only_here() -> u8 { 2 }
pub fn gamma_only_here() -> u8 { 3 }' >"$tmp/variant/src/capability.rs"
  printf '%s\n' 'pub fn traceable_one() -> u8 { 1 }
pub fn traceable_two() -> u8 { 2 }
pub fn traceable_three() -> u8 { 3 }' >"$tmp/variant/src/measurable.rs"
  printf '%s\n' 'pub mod capability;
pub mod measurable;
pub enum SdkFeature { MobileSelfProfile, Other }
pub fn drive() -> u8 {
    let f = SdkFeature::MobileSelfProfile;
    match f { SdkFeature::MobileSelfProfile => measurable::traceable_one(), _ => 0 }
}' >"$tmp/variant/src/lib.rs"
  expect_finding "$tmp/variant" \
    "an enum variant sharing a name with the module type counted as wiring" \
    || return 1

  echo "capability wiring gate self-test OK: 9 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
