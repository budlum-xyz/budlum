#!/usr/bin/env bash
# ============================================================================
# check-fuzz-targets-are-wired.sh
#
# A fuzz target only fuzzes if three files agree about it:
#
#   fuzz/fuzz_targets/<name>.rs   the harness
#   fuzz/Cargo.toml               a [[bin]] entry, or cargo-fuzz cannot build it
#   a workflow                    a run line, or nothing ever executes it
#
# Any one of the three missing gives a target that looks present and does
# nothing. That is the same shape as the gate scripts that sat in `scripts/`
# with no workflow invoking them: counted, never run.
#
# This gate exists because `budl_compile` and `budl_compile_then_run` were
# added in a tree where nothing checked the wiring. It is worth having on its
# own terms too: the target list in `ci.yml` is a hand written bash array and
# the one in `fuzz-nightly.yml` is a hand written matrix, so three lists drift
# by default.
#
# Deliberately NOT checked: that every target runs in the quick set. Splitting
# fast and slow work is a real decision (`budl_compile` parses and returns,
# `budl_compile_then_run` executes bytecode to the gas limit), so a target may
# legitimately live only in the nightly matrix. What the gate requires is that
# it runs *somewhere*.
#
# Usage:
#   bash scripts/check-fuzz-targets-are-wired.sh              # gate
#   bash scripts/check-fuzz-targets-are-wired.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os
import re
import sys

root = sys.argv[1]
targets_dir = os.path.join(root, "fuzz", "fuzz_targets")
manifest = os.path.join(root, "fuzz", "Cargo.toml")
workflows = os.path.join(root, ".github", "workflows")

if not os.path.isdir(targets_dir):
    print(f"FAIL: no fuzz target directory at {targets_dir}", file=sys.stderr)
    sys.exit(2)
if not os.path.isfile(manifest):
    print(f"FAIL: no manifest at {manifest}", file=sys.stderr)
    sys.exit(2)

harnesses = sorted(
    f[:-3] for f in os.listdir(targets_dir) if f.endswith(".rs")
)
if not harnesses:
    print("FAIL: no .rs harnesses found; the gate would be vacuous", file=sys.stderr)
    sys.exit(2)

manifest_text = open(manifest, encoding="utf-8").read()
declared = set(re.findall(r'^\s*name\s*=\s*"([^"]+)"', manifest_text, re.M))
paths = set(
    os.path.basename(p)[:-3]
    for p in re.findall(r'^\s*path\s*=\s*"fuzz_targets/([^"]+)"', manifest_text, re.M)
)

workflow_text = ""
if os.path.isdir(workflows):
    for f in sorted(os.listdir(workflows)):
        if f.endswith((".yml", ".yaml")):
            workflow_text += open(os.path.join(workflows, f), encoding="utf-8").read()
if not workflow_text:
    print(f"FAIL: no workflow files under {workflows}; gate would be vacuous",
          file=sys.stderr)
    sys.exit(2)

problems = []
for name in harnesses:
    if name not in declared or name not in paths:
        problems.append(
            f"  {name}: harness exists but fuzz/Cargo.toml has no matching "
            f"[[bin]] (name and path). cargo-fuzz cannot build it."
        )
        continue
    # A mention anywhere in the workflows counts: the quick set is a bash
    # array, the nightly set is a matrix, and both are plain text.
    if not re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", workflow_text):
        problems.append(
            f"  {name}: built but never run. No workflow mentions it, so it "
            f"fuzzes nothing on any schedule."
        )

# The reverse direction: a [[bin]] pointing at a file that is not there fails
# the build, but a stale entry that names a deleted harness is worth catching
# here with a readable message.
for name in sorted(paths - set(harnesses)):
    problems.append(f"  {name}: fuzz/Cargo.toml declares it, no such harness file.")

if problems:
    print(f"FAIL: {len(problems)} fuzz target(s) are not fully wired:", file=sys.stderr)
    for p in problems:
        print(p, file=sys.stderr)
    sys.exit(1)

print(f"Fuzz wiring OK: {len(harnesses)} harness(es), each with a [[bin]] entry "
      f"and at least one workflow that runs it.")
PY
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  build() {
    local d="$1"
    mkdir -p "$d/fuzz/fuzz_targets" "$d/.github/workflows"
    printf '#![no_main]\n' > "$d/fuzz/fuzz_targets/alpha.rs"
    printf '#![no_main]\n' > "$d/fuzz/fuzz_targets/beta.rs"
    cat > "$d/fuzz/Cargo.toml" <<'TOML'
[package]
name = "x-fuzz"

[[bin]]
name = "alpha"
path = "fuzz_targets/alpha.rs"

[[bin]]
name = "beta"
path = "fuzz_targets/beta.rs"
TOML
    cat > "$d/.github/workflows/fuzz.yml" <<'YML'
jobs:
  q:
    steps:
      - run: cargo fuzz run alpha
      - run: cargo fuzz run beta
YML
  }

  build "$tmp/clean"
  out="$(scan "$tmp/clean" 2>&1)" || fail "canary: a fully wired tree was rejected: $out"
  case "$out" in
    *"Fuzz wiring OK"*) ;;
    *) fail "canary: clean tree passed with an unexpected message: $out" ;;
  esac

  # 1. A harness with no [[bin]] entry cannot be built by cargo-fuzz.
  rm -rf "$tmp/nobin"; build "$tmp/nobin"
  printf '#![no_main]\n' > "$tmp/nobin/fuzz/fuzz_targets/orphan.rs"
  if scan "$tmp/nobin" >/dev/null 2>&1; then
    fail "canary: a harness with no [[bin]] entry was accepted"
  fi

  # 2. A target that builds but no workflow runs. This is the failure the
  #    gate is really for: it looks present in every listing.
  rm -rf "$tmp/norun"; build "$tmp/norun"
  printf '#![no_main]\n' > "$tmp/norun/fuzz/fuzz_targets/gamma.rs"
  cat >> "$tmp/norun/fuzz/Cargo.toml" <<'TOML'

[[bin]]
name = "gamma"
path = "fuzz_targets/gamma.rs"
TOML
  if scan "$tmp/norun" >/dev/null 2>&1; then
    fail "canary: a target that no workflow runs was accepted"
  fi

  # 3. A [[bin]] naming a harness that does not exist.
  rm -rf "$tmp/stale"; build "$tmp/stale"
  cat >> "$tmp/stale/fuzz/Cargo.toml" <<'TOML'

[[bin]]
name = "deleted"
path = "fuzz_targets/deleted.rs"
TOML
  if scan "$tmp/stale" >/dev/null 2>&1; then
    fail "canary: a [[bin]] pointing at a missing harness was accepted"
  fi

  # 4. A substring must not count as a match. `alpha` appearing inside
  #    `alpha_extended` would otherwise let a real target hide behind a
  #    similarly named one.
  rm -rf "$tmp/substr"; build "$tmp/substr"
  printf '#![no_main]\n' > "$tmp/substr/fuzz/fuzz_targets/alpha_extended.rs"
  cat >> "$tmp/substr/fuzz/Cargo.toml" <<'TOML'

[[bin]]
name = "alpha_extended"
path = "fuzz_targets/alpha_extended.rs"
TOML
  if scan "$tmp/substr" >/dev/null 2>&1; then
    fail "canary: 'alpha_extended' was matched by the workflow line for 'alpha'"
  fi

  # 5. Vacuity floors.
  mkdir -p "$tmp/empty/fuzz/fuzz_targets" "$tmp/empty/.github/workflows"
  printf '[package]\nname = "x"\n' > "$tmp/empty/fuzz/Cargo.toml"
  if scan "$tmp/empty" >/dev/null 2>&1; then
    fail "canary: a tree with no harnesses passed"
  fi

  rm -rf "$tmp/nowf"; build "$tmp/nowf"; rm -rf "$tmp/nowf/.github/workflows"
  if scan "$tmp/nowf" >/dev/null 2>&1; then
    fail "canary: a tree with no workflows passed"
  fi

  echo "Self-test OK: unbuilt harness, unrun target, stale [[bin]], substring match, and two empty trees all rejected; a wired tree passes."
  exit 0
fi

scan "$ROOT"
