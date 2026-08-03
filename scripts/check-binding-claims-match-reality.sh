#!/usr/bin/env bash
# ============================================================================
# check-binding-claims-match-reality.sh
#
# A capability flag must not claim a binding the tree does not contain.
#
# Why this gate exists.
#
# `WalletBindingCapabilities` reported `uniffi_mobile: true` and
# `wasm_browser: true`. Measured against the tree, neither was wired:
#
#   * `uniffi_bindings` held one function, `binding_capabilities()`, which
#     returned that same struct. `wasm_bindings` was identical. Both modules
#     described themselves and exported nothing else.
#   * No `.udl` file existed anywhere, and UniFFI cannot generate Kotlin or
#     Swift without an interface definition or a proc-macro export.
#   * `#[wasm_bindgen]` appeared on nothing, so no symbol reached a browser.
#
# The constant was already named `WALLET_BINDING_STUB_VERSION`, so the shape
# was known to whoever wrote it. What made it worth a gate is that the struct
# is a capability descriptor: something reads it to decide what it can call.
# A flag that is `true` regardless of whether the work is done cannot be told
# apart from a flag that means the work is done, and the funding document
# describes mobile and browser wallets as deliverables, so the reader most
# likely to check is the one least able to verify it by hand.
#
# What the gate checks.
#
# `bindings_are_wired` is only allowed to be `true` when the tree contains
# evidence of a real binding surface:
#
#   * a `.udl` file, or a `uniffi::export` / `uniffi::setup_scaffolding`
#     invocation, for the mobile side, and
#   * at least one `#[wasm_bindgen]` attribute for the browser side.
#
# It also refuses the reverse: if that evidence exists and the flag is still
# `false`, the descriptor is lying in the other direction and a caller is
# being told it cannot do something it can.
#
# The gate deliberately does not require the bindings to exist. Shipping
# without them is a schedule decision. Claiming them is not.
#
# Usage:
#   bash scripts/check-binding-claims-match-reality.sh              # gate
#   bash scripts/check-binding-claims-match-reality.sh --self-test  # canary
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
wallet = os.path.join(root, "wallet-core", "src", "lib.rs")

if not os.path.isfile(wallet):
    print(f"FAIL: no wallet core at {wallet}", file=sys.stderr)
    sys.exit(2)

src = open(wallet, encoding="utf-8").read()
code = re.sub(r"//[^\n]*", "", src)

problems = []
checked = 0

# The descriptor has to still exist and still carry the field the gate is
# about. A rename that drops it silently would otherwise pass.
checked += 1
if "WalletBindingCapabilities" not in src:
    problems.append(
        "wallet-core no longer defines `WalletBindingCapabilities`. If the "
        "descriptor was removed the entry here should go with it, in the same "
        "commit, with the reason."
    )
elif "bindings_are_wired" not in src:
    problems.append(
        "`WalletBindingCapabilities` has no `bindings_are_wired` field, so "
        "this gate cannot tell what the descriptor is claiming. The field was "
        "added because the previous flags, `uniffi_mobile` and `wasm_browser`, "
        "were hard-coded true with nothing behind them."
    )
else:

    # What the descriptor claims.
    m = re.search(r"bindings_are_wired\s*:\s*(true|false)", code)
    if not m:
        problems.append(
            "`bindings_are_wired` is never given a literal value this gate can "
            "read. If it became a computed expression, update the gate in the "
            "same commit so the claim stays checkable."
        )
    else:
        claims_wired = m.group(1) == "true"
        checked += 1

        # What the tree actually contains. Walk it once rather than trusting
        # any single file.
        udl_files = []
        wasm_exports = []
        uniffi_macros = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d not in (".git", "target", "node_modules")
            ]
            for name in filenames:
                path = os.path.join(dirpath, name)
                if name.endswith(".udl"):
                    udl_files.append(path)
                    continue
                if not name.endswith(".rs"):
                    continue
                try:
                    body = open(path, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                body = re.sub(r"//[^\n]*", "", body)
                if re.search(r"#\[\s*wasm_bindgen", body):
                    wasm_exports.append(path)
                if re.search(r"uniffi::(export|setup_scaffolding)", body):
                    uniffi_macros.append(path)

        has_mobile = bool(udl_files or uniffi_macros)
        has_browser = bool(wasm_exports)
        really_wired = has_mobile and has_browser
        checked += 2

        if claims_wired and not really_wired:
            missing = []
            if not has_mobile:
                missing.append(
                    "no `.udl` file and no `uniffi::export` or "
                    "`uniffi::setup_scaffolding`, so nothing reaches Kotlin or Swift"
                )
            if not has_browser:
                missing.append(
                    "no `#[wasm_bindgen]` attribute anywhere, so no symbol "
                    "reaches a browser"
                )
            problems.append(
                "`bindings_are_wired` is true and the tree does not support it: "
                + "; ".join(missing)
                + ". This is a capability descriptor, so a caller reads it to "
                "decide what it can invoke."
            )

        if really_wired and not claims_wired:
            problems.append(
                "the tree has a real binding surface but `bindings_are_wired` "
                "is still false, so callers are told they cannot use something "
                "they can. Update the descriptor together with the binding."
            )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)

print(f"binding claim gate OK: {checked} checks, the descriptor matches the tree")
PY
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  mk() {
    local dir="$1" wallet_body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/wallet-core/src"
    printf '%s\n' "$wallet_body" >"$dir/wallet-core/src/lib.rs"
  }

  HONEST='pub struct WalletBindingCapabilities {
    pub uniffi_feature_compiles: bool,
    pub wasm_feature_compiles: bool,
    pub bindings_are_wired: bool,
}
impl WalletBindingCapabilities {
    pub fn current() -> Self {
        Self {
            uniffi_feature_compiles: true,
            wasm_feature_compiles: true,
            bindings_are_wired: false,
        }
    }
}'

  # 1. The honest shape must pass: no bindings, and the flag says so.
  mk "$tmp/honest" "$HONEST"
  if ! ( scan "$tmp/honest" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: an honest descriptor with no bindings was rejected!" >&2
    ( scan "$tmp/honest" ) || true
    exit 1
  fi

  # 2. The original bug: claiming a wiring the tree does not have.
  mk "$tmp/overclaim" 'pub struct WalletBindingCapabilities {
    pub bindings_are_wired: bool,
}
impl WalletBindingCapabilities {
    pub fn current() -> Self {
        Self { bindings_are_wired: true }
    }
}'
  if ( scan "$tmp/overclaim" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a claimed binding with nothing behind it was accepted!" >&2
    exit 1
  fi

  # 3. Half a binding is not a binding: mobile present, browser absent.
  rm -rf "$tmp/halfmobile"; mkdir -p "$tmp/halfmobile/wallet-core/src"
  printf '%s\n' 'pub struct WalletBindingCapabilities { pub bindings_are_wired: bool }
impl WalletBindingCapabilities {
    pub fn current() -> Self { Self { bindings_are_wired: true } }
}' >"$tmp/halfmobile/wallet-core/src/lib.rs"
  printf '%s\n' 'namespace wallet {};' >"$tmp/halfmobile/wallet-core/src/wallet.udl"
  if ( scan "$tmp/halfmobile" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a mobile-only binding claiming both was accepted!" >&2
    exit 1
  fi

  # 4. Both present and claimed: the state this gate is meant to allow, so it
  #    must not block the work landing.
  rm -rf "$tmp/wired"; mkdir -p "$tmp/wired/wallet-core/src"
  printf '%s\n' 'pub struct WalletBindingCapabilities { pub bindings_are_wired: bool }
impl WalletBindingCapabilities {
    pub fn current() -> Self { Self { bindings_are_wired: true } }
}
#[wasm_bindgen]
pub fn wallet_address() -> String { String::new() }' >"$tmp/wired/wallet-core/src/lib.rs"
  printf '%s\n' 'namespace wallet {};' >"$tmp/wired/wallet-core/src/wallet.udl"
  if ! ( scan "$tmp/wired" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: a genuinely wired tree was rejected!" >&2
    ( scan "$tmp/wired" ) || true
    exit 1
  fi

  # 5. The reverse lie: bindings exist, the descriptor still says no.
  rm -rf "$tmp/underclaim"; mkdir -p "$tmp/underclaim/wallet-core/src"
  printf '%s\n' 'pub struct WalletBindingCapabilities { pub bindings_are_wired: bool }
impl WalletBindingCapabilities {
    pub fn current() -> Self { Self { bindings_are_wired: false } }
}
#[wasm_bindgen]
pub fn wallet_address() -> String { String::new() }' >"$tmp/underclaim/wallet-core/src/lib.rs"
  printf '%s\n' 'namespace wallet {};' >"$tmp/underclaim/wallet-core/src/wallet.udl"
  if ( scan "$tmp/underclaim" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a descriptor denying bindings that exist was accepted!" >&2
    exit 1
  fi

  # 6. A commented-out export is not an export.
  rm -rf "$tmp/comment"; mkdir -p "$tmp/comment/wallet-core/src"
  printf '%s\n' 'pub struct WalletBindingCapabilities { pub bindings_are_wired: bool }
impl WalletBindingCapabilities {
    pub fn current() -> Self { Self { bindings_are_wired: true } }
}
// #[wasm_bindgen]
pub fn wallet_address() -> String { String::new() }' >"$tmp/comment/wallet-core/src/lib.rs"
  printf '%s\n' 'namespace wallet {};' >"$tmp/comment/wallet-core/src/wallet.udl"
  if ( scan "$tmp/comment" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a commented-out wasm export was counted!" >&2
    exit 1
  fi

  # 7. Dropping the field must fail rather than pass for having nothing to
  #    check, which is how the original state would come back.
  mk "$tmp/nofield" 'pub struct WalletBindingCapabilities {
    pub uniffi_mobile: bool,
}
impl WalletBindingCapabilities {
    pub fn current() -> Self { Self { uniffi_mobile: true } }
}'
  if ( scan "$tmp/nofield" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a descriptor without the checked field was accepted!" >&2
    exit 1
  fi

  # 8. A missing tree must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no wallet core was accepted!" >&2
    exit 1
  fi

  echo "binding claim gate self-test OK: an overclaim, a half binding, a reverse denial, a commented-out export, a dropped field and a missing tree are all rejected; an honest descriptor and a genuinely wired one both pass."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT"
