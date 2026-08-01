#!/usr/bin/env bash
# ============================================================================
# check-containment-defaults.sh - a gate that is off by default must stay off
# by default, and the path that reaches it must actually consult it.
#
# From the containment-first directive: the protection is not that a
# vulnerability is hidden, it is that it cannot be triggered. Three mechanisms
# carry that here - a feature closed until a threshold is proven, a default
# that refuses on uncertainty, and structural isolation. All three fail the
# same way: the flag stays in the source, reads correctly in review, and the
# code path that matters never looks at it.
#
# That is not hypothetical. Both halves happened at once:
#
#   * bud-vm's `decode_instruction` hard-coded `MainnetActivation::full()`,
#     which set every staged-rollout flag true and left
#     `MainnetActivation::default()` unreachable from the only caller that
#     consults it. `verify_merkle_enabled: false` and
#     `verify_inference_enabled: false` became dead code.
#
#   * `ContractCall` runs bytecode straight out of `tx.data` through
#     `ZkVmExecutor::execute_bytecode`, which passed `mainnet = false` and so
#     skipped `decode_for_mainnet` entirely. The gate would not have applied to
#     the one input an attacker chooses even if it had been correct.
#
# And the test meant to catch it asserted `is_err() || gas_used > 0`, which is
# true of every possible outcome.
#
# This gate reads the source and checks the three things that were wrong:
#
#   1. The staged-rollout defaults are still closed.
#   2. The VM decodes against `default()`, not `full()`.
#   3. The contract-execution entry point requests gated decoding.
#
# It cannot prove a gate is *correct* - only that it is still wired the way it
# was argued. That is the property that decayed.
#
# Usage:
#   bash scripts/check-containment-defaults.sh              # gate
#   bash scripts/check-containment-defaults.sh --self-test  # canary
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Strip line comments so prose about a default cannot satisfy a check about it.
# The finding this gate exists for came with a long comment explaining the
# right thing while the code did the opposite.
code_of() {
  sed 's,//.*,,' "$1"
}

gate() {
  local root="$1"
  local isa="$root/budzero/bud-isa/src/lib.rs"
  local vm="$root/budzero/bud-vm/src/lib.rs"
  local exec_rs="$root/src/execution/zkvm.rs"

  for f in "$isa" "$vm" "$exec_rs"; do
    [ -f "$f" ] || fail "expected source file missing: $f"
  done

  local isa_code vm_code exec_code
  isa_code="$(code_of "$isa")"
  vm_code="$(code_of "$vm")"
  exec_code="$(code_of "$exec_rs")"

  # 1. The defaults are closed.
  #
  # Matched inside the Default impl only: `full()` sets the same field names to
  # true a few lines below, and a whole-file grep would find whichever came
  # first.
  local default_block
  default_block="$(printf '%s\n' "$isa_code" | sed -n '/impl Default for MainnetActivation/,/^}/p')"
  [ -n "$default_block" ] || fail "MainnetActivation no longer has a Default impl - the staged-rollout defaults are the containment boundary"

  local flag
  for flag in verify_merkle_enabled verify_inference_enabled; do
    printf '%s\n' "$default_block" | grep -qE "$flag: *false" \
      || fail "MainnetActivation::default() no longer closes $flag.
  VerifyMerkle is gated because its path verification is unfinished;
  VerifyInference because there is no verification circuit behind it and it
  returns a hard-coded zero. Opening either is a consensus-visible decision
  that belongs in the commit that makes it, with the verification to match."
  done

  # 2. The VM consults the defaults.
  printf '%s\n' "$vm_code" | grep -q "MainnetActivation::default()" \
    || fail "bud-vm no longer decodes against MainnetActivation::default().
  Whatever it uses instead is what the gate actually is."
  if printf '%s\n' "$vm_code" | grep -q "MainnetActivation::full()"; then
    fail "bud-vm decodes against MainnetActivation::full(), which sets every
  staged-rollout flag true and makes default() dead code. This is the exact
  state the gate was in when VerifyMerkle and VerifyInference were both open
  on mainnet."
  fi

  # 3. Contract execution asks for the gated decoder.
  #
  # `execute_bytecode` is what the executor calls for ContractCall, with
  # bytecode taken from tx.data.
  local entry
  entry="$(printf '%s\n' "$exec_code" | sed -n '/pub fn execute_bytecode(/,/^    }/p')"
  [ -n "$entry" ] || fail "ZkVmExecutor::execute_bytecode was renamed or removed; re-derive which entry point ContractCall uses"
  printf '%s\n' "$entry" | grep -qE "execute_bytecode_inner\([^)]*true" \
    || fail "ZkVmExecutor::execute_bytecode no longer requests gated decoding.
  ContractCall passes user-supplied tx.data straight into it. With the
  ungated path, decode_for_mainnet is never called and the staged-rollout
  flags apply to nothing."

  echo "Containment defaults OK: staged-rollout flags closed, VM decodes against default(), contract execution is gated."
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  build() {
    local dir="$1" default_merkle="$2" vm_activation="$3" exec_gated="$4"
    rm -rf "$dir"
    mkdir -p "$dir/budzero/bud-isa/src" "$dir/budzero/bud-vm/src" "$dir/src/execution"
    cat > "$dir/budzero/bud-isa/src/lib.rs" <<EOF
impl Default for MainnetActivation {
    fn default() -> Self {
        Self {
            verify_merkle_enabled: $default_merkle,
            verify_inference_enabled: false,
        }
    }
}
impl MainnetActivation {
    pub fn full() -> Self {
        Self { verify_merkle_enabled: true, verify_inference_enabled: true }
    }
}
EOF
    cat > "$dir/budzero/bud-vm/src/lib.rs" <<EOF
fn decode_instruction(raw: u64, mainnet_mode: bool) -> Result<Instruction, String> {
    if mainnet_mode {
        let activation = bud_isa::MainnetActivation::$vm_activation;
        Instruction::decode_for_mainnet(raw, activation)
    } else {
        Instruction::decode(raw)
    }
}
EOF
    cat > "$dir/src/execution/zkvm.rs" <<EOF
impl ZkVmExecutor {
    pub fn execute_bytecode(bytecode: &[u8], gas_limit: u64) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_inner(bytecode, gas_limit, $exec_gated)
    }
}
EOF
  }

  # 1. The state that shipped: VM on full activation.
  build "$tmp/full" "false" "full()" "true"
  if ( gate "$tmp/full" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a VM decoding against MainnetActivation::full() was accepted!" >&2
    exit 1
  fi

  # 2. A default flipped open.
  build "$tmp/open" "true" "default()" "true"
  if ( gate "$tmp/open" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: verify_merkle_enabled: true in the defaults was accepted!" >&2
    exit 1
  fi

  # 3. The contract entry point back on ungated decoding.
  build "$tmp/ungated" "false" "default()" "false"
  if ( gate "$tmp/ungated" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an ungated execute_bytecode was accepted!" >&2
    exit 1
  fi

  # 4. A comment describing the right thing must not satisfy the check. This is
  #    how the finding hid: the code above decode_instruction explained the
  #    correct behaviour at length while the line below did the opposite.
  build "$tmp/prose" "false" "full()" "true"
  sed -i '1i // We decode against MainnetActivation::default() for staged rollout.' \
    "$tmp/prose/budzero/bud-vm/src/lib.rs"
  if ( gate "$tmp/prose" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a comment mentioning default() satisfied the check!" >&2
    exit 1
  fi

  # 5. A missing file must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( gate "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no sources was accepted!" >&2
    exit 1
  fi

  # 6. The correct configuration must pass.
  build "$tmp/good" "false" "default()" "true"
  if ! ( gate "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a correctly gated tree was rejected!" >&2
    ( gate "$tmp/good" ) >&2 || true
    exit 1
  fi

  echo "containment defaults self-test OK: full activation, an opened default, an ungated entry point, a comment standing in for code and a missing tree are all rejected; the correct wiring passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

gate "${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
