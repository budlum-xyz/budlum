#!/usr/bin/env bash
# ============================================================================
# check-no-unicode-dashes.sh: no typographic dash may enter the tree.
#
# Why this exists as a gate rather than a review habit:
#
# A previous pass removed 1299 em dashes by hand and reported the tree clean.
# It was not. Nineteen survived, and three of them sat in the `name:` field of
# workflow jobs that branch protection lists as required checks:
#
#     Semver Check (Madde 5 <em dash> public API breakage gate)
#     Udeps <em dash> kullanilmayan bagimlilik kapisi
#     Geiger <em dash> unsafe gorunurluk (first-party 0 kanit katmani)
#
# Renaming a required check silently unlists it: the job still runs, still
# passes, and stops counting toward the merge requirement. So a cosmetic
# character in a job name is a branch-protection hazard, and the only way to
# retire it safely is to rename the job and update protection in the same
# change. A hand count cannot be trusted with that; a gate can.
#
# Characters rejected, with the ASCII replacement each one should have taken:
#
#     U+2010 hyphen              -> -
#     U+2011 non-breaking hyphen -> -
#     U+2012 figure dash         -> -
#     U+2013 en dash             -> - in ranges, "to" in prose
#     U+2014 em dash             -> , or : depending on the clause
#     U+2015 horizontal bar      -> ,
#     U+2212 minus sign          -> -
#     U+00AD soft hyphen         -> deleted (invisible, breaks grep)
#
# Usage:
#   bash scripts/check-no-unicode-dashes.sh              # gate
#   bash scripts/check-no-unicode-dashes.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Binary and generated files carry no prose, and Cargo.lock is machine written.
scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os
import sys

root = sys.argv[1]

DASHES = {
    "\u2010": "U+2010 hyphen",
    "\u2011": "U+2011 non-breaking hyphen",
    "\u2012": "U+2012 figure dash",
    "\u2013": "U+2013 en dash",
    "\u2014": "U+2014 em dash",
    "\u2015": "U+2015 horizontal bar",
    "\u2212": "U+2212 minus sign",
    "\u00ad": "U+00AD soft hyphen",
}

SKIP_DIRS = {".git", "target", "node_modules", ".cargo"}
SKIP_FILES = {"Cargo.lock", "flake.lock", "imports.lock", "LICENSE.md"}

hits = []
scanned = 0
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for name in sorted(filenames):
        if name in SKIP_FILES:
            continue
        path = os.path.join(dirpath, name)
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        for lineno, line in enumerate(text.split("\n"), 1):
            for ch, label in DASHES.items():
                if ch in line:
                    rel = os.path.relpath(path, root)
                    hits.append(f"  {rel}:{lineno}: {label}\n      {line.strip()[:100]}")

# A scan that walked nothing would pass silently, which is the failure mode
# this project treats as a defect in the gate rather than a clean result.
if scanned < 50:
    print(f"FAIL: only {scanned} text files scanned under {root}; the gate would be vacuous",
          file=sys.stderr)
    sys.exit(2)

if hits:
    print(f"FAIL: {len(hits)} typographic dash(es) in the tree:", file=sys.stderr)
    for h in hits[:40]:
        print(h, file=sys.stderr)
    if len(hits) > 40:
        print(f"  ... and {len(hits) - 40} more", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Replace with ASCII: a comma or colon in prose, a plain hyphen in ranges.", file=sys.stderr)
    print("  If the hit is a workflow `name:` that branch protection requires,", file=sys.stderr)
    print("  update the protection contexts in the same change or the check stops counting.",
          file=sys.stderr)
    sys.exit(1)

print(f"No typographic dashes: {scanned} text files scanned.")
PY
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # The canary needs enough files to clear the vacuity floor, so the fixture
  # is built to look like a small tree rather than a single file.
  mkdir -p "$tmp/clean/src"
  for i in $(seq 1 60); do
    printf 'fn f%s() { let a = 1 - 1; }\n' "$i" > "$tmp/clean/src/f$i.rs"
  done
  printf '# Title\n\nPlain ASCII prose, nothing typographic here.\n' > "$tmp/clean/README.md"

  out="$(scan "$tmp/clean" 2>&1)" || fail "canary: a clean tree was rejected: $out"
  case "$out" in
    *"No typographic dashes"*) ;;
    *) fail "canary: clean tree passed without the expected message: $out" ;;
  esac

  # Each character has to be caught on its own; catching only the em dash is
  # how the previous pass missed the en dashes and the minus signs. The
  # fixtures are written by python because `printf` in this shell does not
  # expand \u escapes and would otherwise write the literal text "\u2010",
  # producing a canary that passes for the wrong reason.
  for cp in 2010 2011 2012 2013 2014 2015 2212 00ad; do
    rm -rf "$tmp/dirty"
    cp -r "$tmp/clean" "$tmp/dirty"
    python3 -c "
import sys
open(sys.argv[1], 'w', encoding='utf-8').write(
    '# A heading ' + chr(int(sys.argv[2], 16)) + ' with a typographic dash\n')
" "$tmp/dirty/DIRTY.md" "$cp"
    # The fixture must really contain the character, or the canary is testing
    # nothing at all.
    python3 -c "
import sys
t = open(sys.argv[1], encoding='utf-8').read()
sys.exit(0 if chr(int(sys.argv[2], 16)) in t else 1)
" "$tmp/dirty/DIRTY.md" "$cp" \
      || fail "canary: fixture for U+$cp does not contain the character"
    if scan "$tmp/dirty" >/dev/null 2>&1; then
      fail "canary: U+$cp was not detected; the gate is blind to it"
    fi
  done

  # A job name is the case that motivated the gate, so it is exercised by name.
  rm -rf "$tmp/wf"
  cp -r "$tmp/clean" "$tmp/wf"
  mkdir -p "$tmp/wf/.github/workflows"
  python3 -c "
import sys
open(sys.argv[1], 'w', encoding='utf-8').write(
    'jobs:\n  x:\n    name: Semver Check (Madde 5 ' + chr(0x2014)
    + ' public API breakage gate)\n')
" "$tmp/wf/.github/workflows/semver.yml"
  if scan "$tmp/wf" >/dev/null 2>&1; then
    fail "canary: an em dash inside a workflow job name was not detected"
  fi

  # And the vacuity floor itself has to fire, or an empty checkout would pass.
  mkdir -p "$tmp/empty"
  printf 'nothing\n' > "$tmp/empty/only.txt"
  if scan "$tmp/empty" >/dev/null 2>&1; then
    fail "canary: a near-empty tree passed; the vacuity floor is not working"
  fi

  echo "Self-test OK: clean tree passes, 8 dash characters detected, workflow name detected, vacuity floor fires."
  exit 0
fi

scan "$ROOT"
