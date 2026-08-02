#!/usr/bin/env bash
# ============================================================================
# check-security-parameters-are-derived.sh
#
# The security parameters absorbed into the transcript must be read out of the
# FRI configuration, not written down a second time.
#
# Why this gate exists.
#
# The Fiat-Shamir transcript carries the degrees, the commitments and the
# public values. It did not carry the FRI parameters, and those are what decide
# what a proof is worth: `num_queries` and `log_blowup` set the soundness
# error, the proof-of-work bits set the grinding cost. Measured on the current
# configuration, `log_blowup = 3`, `num_queries = 100` and 16 grinding bits are
# roughly 316 bits of security. `num_queries = 1`, `log_blowup = 1` and no
# grinding is one bit, and produces a proof of exactly the same shape.
#
# Least Authority's audit of Plonky3 found this class directly: a challenger
# that absorbed neither the FRI config nor the polynomial degree let a prover
# tamper with unabsorbed data. Our degrees were already absorbed. The FRI
# parameters were not.
#
# `fiat_shamir_binding.rs` now requires both sides to absorb
# `security_parameters` before the first challenge. That test proves the
# absorption happens. It cannot prove the absorbed values are the real ones: a
# `security_parameters()` returning a hard-coded array, or a `build_config`
# writing the numbers out by hand next to the `FriParameters` literal, would
# satisfy it and bind nothing. Two sources of truth for one set of numbers is
# how they drift.
#
# What the gate checks.
#
# 1. The trait declares `security_parameters`, and both prover and verifier
#    absorb it before their first `sample_algebra_element`.
# 2. `build_config` builds the absorbed vector out of the `fri_params` binding
#    it hands to the PCS. Every entry must be a field read from that binding;
#    a bare integer literal in that vector is the drift this gate is named for.
# 3. Every field of the `FriParameters` literal that carries a number is
#    represented. A parameter that governs the proof but is left out of the
#    vector is unabsorbed, which is the original bug in miniature.
#
# Usage:
#   bash scripts/check-security-parameters-are-derived.sh              # gate
#   bash scripts/check-security-parameters-are-derived.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  local root="$1"
  python3 - "$root" <<'PY'
import os
import re
import sys

root = sys.argv[1]
cfg = os.path.join(root, "budzero", "bud-proof", "src", "bud_stark", "config.rs")
prover = os.path.join(root, "budzero", "bud-proof", "src", "bud_stark", "prover.rs")
verifier = os.path.join(root, "budzero", "bud-proof", "src", "bud_stark", "verifier.rs")
build = os.path.join(root, "budzero", "bud-proof", "src", "plonky3_prover.rs")

for path, what in ((cfg, "config"), (prover, "prover"), (verifier, "verifier"), (build, "build_config")):
    if not os.path.isfile(path):
        print(f"FAIL: no {what} at {path}", file=sys.stderr)
        sys.exit(2)

cfg_src = open(cfg, encoding="utf-8").read()
prover_src = open(prover, encoding="utf-8").read()
verifier_src = open(verifier, encoding="utf-8").read()
build_src = open(build, encoding="utf-8").read()

def strip_comments(s):
    return re.sub(r"//[^\n]*", "", s)

problems = []
checked = 0

# 1. The trait must declare it, and both sides must absorb it before the
#    first challenge.
checked += 1
if not re.search(r"fn\s+security_parameters\s*\(&self\)", cfg_src):
    problems.append(
        "config.rs does not declare `security_parameters`, so the FRI "
        "parameters are outside the Fiat-Shamir transcript. num_queries and "
        "log_blowup set the soundness error and the proof-of-work bits set the "
        "grinding cost; a proof produced under weaker parameters has the same "
        "shape as one produced under the real ones."
    )

for src, name in ((prover_src, "prover"), (verifier_src, "verifier")):
    code = strip_comments(src)
    lines = code.split("\n")
    checked += 1
    stops = [i for i, l in enumerate(lines) if "sample_algebra_element()" in l]
    if not stops:
        problems.append(f"{name}.rs samples no challenge; this gate cannot place the absorption.")
        continue
    stop = stops[0]
    before = "\n".join(lines[:stop])
    if "security_parameters()" not in before:
        problems.append(
            f"{name}.rs does not absorb `security_parameters()` before its first "
            f"challenge. A parameter set the prover controls and the transcript "
            f"does not cover can be chosen after the challenge is drawn."
        )

# 2. The absorbed vector must be derived from the FriParameters binding.
m = re.search(
    r"let\s+fri_params\s*=\s*p3_fri::FriParameters\s*\{(.*?)\};", build_src, re.DOTALL
)
checked += 1
if not m:
    problems.append(
        "plonky3_prover.rs does not build a `fri_params` binding this gate can "
        "read. Either the configuration moved, in which case update the gate in "
        "the same commit, or there is no single place the FRI parameters are "
        "stated."
    )
else:
    fri_body = strip_comments(m.group(1))
    # Numeric fields of the literal, excluding the mmcs handle.
    fri_fields = set()
    for fm in re.finditer(r"(\w+)\s*:\s*([0-9]+)\s*,", fri_body):
        fri_fields.add(fm.group(1))

    sm = re.search(r"let\s+security\s*=\s*vec!\[(.*?)\];", build_src, re.DOTALL)
    if not sm:
        problems.append(
            "plonky3_prover.rs builds no `security` vector, so nothing states "
            "which parameters reach the transcript. Derive one from the "
            "`fri_params` binding."
        )
    else:
        sec_body = strip_comments(sm.group(1))

        # Every entry must read from fri_params, never be a literal.
        entries = [e.strip() for e in sec_body.split(",") if e.strip()]
        for e in entries:
            if re.fullmatch(r"[0-9]+\s*(as\s+u64)?", e):
                problems.append(
                    f"the absorbed security vector contains the literal `{e}` "
                    f"instead of reading the field from `fri_params`. A "
                    f"hand-written copy is a second source of truth and can "
                    f"drift from the parameters that actually govern the proof."
                )
            elif "fri_params." not in e:
                problems.append(
                    f"the absorbed security vector entry `{e}` does not read "
                    f"from `fri_params`, so this gate cannot tell that it "
                    f"describes the configuration in use."
                )

        # Every numeric FRI field must appear.
        for field in sorted(fri_fields):
            if f"fri_params.{field}" not in sec_body:
                problems.append(
                    f"`{field}` is set on the FRI parameters but is not absorbed "
                    f"into the transcript. A parameter that governs the proof "
                    f"and sits outside the transcript is the exact shape of the "
                    f"bug this binding was added for."
                )
        checked += len(fri_fields)

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"security parameters OK: {checked} checks, every FRI field is derived and absorbed")
PY
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mk() {
    local dir="$1" cfg="$2" pv="$3" build="$4"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-proof/src/bud_stark"
    printf '%s\n' "$cfg" >"$dir/budzero/bud-proof/src/bud_stark/config.rs"
    printf '%s\n' "$pv" >"$dir/budzero/bud-proof/src/bud_stark/prover.rs"
    printf '%s\n' "$pv" >"$dir/budzero/bud-proof/src/bud_stark/verifier.rs"
    printf '%s\n' "$build" >"$dir/budzero/bud-proof/src/plonky3_prover.rs"
  }

  GOOD_CFG='    fn security_parameters(&self) -> Vec<Val<Self>>;'
  GOOD_PV='    challenger.observe_slice(&config.security_parameters());
    let rand_1: SC::Challenge = challenger.sample_algebra_element();'
  GOOD_BUILD='    let fri_params = p3_fri::FriParameters {
        log_blowup: 3,
        num_queries: 100,
        commit_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let security = vec![
        fri_params.log_blowup as u64,
        fri_params.num_queries as u64,
        fri_params.commit_proof_of_work_bits as u64,
    ];'

  # 1. The corrected shape must pass.
  mk "$tmp/good" "$GOOD_CFG" "$GOOD_PV" "$GOOD_BUILD"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    ( scan "$tmp/good" ) || true
    exit 1
  fi

  # 2. The original bug: nobody absorbs the parameters.
  mk "$tmp/noabsorb" "$GOOD_CFG" '    let rand_1: SC::Challenge = challenger.sample_algebra_element();' "$GOOD_BUILD"
  if ( scan "$tmp/noabsorb" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a transcript that never absorbs the parameters was accepted!" >&2
    exit 1
  fi

  # 3. Absorbed after the first challenge is the same bug with extra steps.
  mk "$tmp/late" "$GOOD_CFG" '    let rand_1: SC::Challenge = challenger.sample_algebra_element();
    challenger.observe_slice(&config.security_parameters());' "$GOOD_BUILD"
  if ( scan "$tmp/late" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: parameters absorbed after the challenge were accepted!" >&2
    exit 1
  fi

  # 4. Hand-written literals instead of reading the binding. This is the drift
  #    the gate is named for: it absorbs numbers, just not necessarily the
  #    ones in force.
  mk "$tmp/literal" "$GOOD_CFG" "$GOOD_PV" '    let fri_params = p3_fri::FriParameters {
        log_blowup: 3,
        num_queries: 100,
        commit_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let security = vec![3, 100, 16];'
  if ( scan "$tmp/literal" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: hand-written literals were accepted as the absorbed parameters!" >&2
    exit 1
  fi

  # 5. A FRI field that governs the proof but is left out of the vector.
  mk "$tmp/missing" "$GOOD_CFG" "$GOOD_PV" '    let fri_params = p3_fri::FriParameters {
        log_blowup: 3,
        num_queries: 100,
        commit_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let security = vec![
        fri_params.log_blowup as u64,
        fri_params.num_queries as u64,
    ];'
  if ( scan "$tmp/missing" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a FRI parameter left out of the transcript was accepted!" >&2
    exit 1
  fi

  # 6. The trait declaration removed: the binding is gone entirely.
  mk "$tmp/notrait" '    fn is_zk(&self) -> bool;' "$GOOD_PV" "$GOOD_BUILD"
  if ( scan "$tmp/notrait" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a config with no security_parameters declaration was accepted!" >&2
    exit 1
  fi

  # 7. Only one side absorbing. Prover and verifier must agree or the honest
  #    prover is the one that fails.
  rm -rf "$tmp/oneside"
  mkdir -p "$tmp/oneside/budzero/bud-proof/src/bud_stark"
  printf '%s\n' "$GOOD_CFG" >"$tmp/oneside/budzero/bud-proof/src/bud_stark/config.rs"
  printf '%s\n' "$GOOD_PV" >"$tmp/oneside/budzero/bud-proof/src/bud_stark/prover.rs"
  printf '%s\n' '    let rand_1: SC::Challenge = challenger.sample_algebra_element();' \
    >"$tmp/oneside/budzero/bud-proof/src/bud_stark/verifier.rs"
  printf '%s\n' "$GOOD_BUILD" >"$tmp/oneside/budzero/bud-proof/src/plonky3_prover.rs"
  if ( scan "$tmp/oneside" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: only the prover absorbing was accepted!" >&2
    exit 1
  fi

  # 8. A missing tree must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no sources was accepted!" >&2
    exit 1
  fi

  echo "security parameter gate self-test OK: no absorption, late absorption, hand-written literals, a missing FRI field, a removed trait method, one-sided absorption and a missing tree are all rejected; the derived tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
