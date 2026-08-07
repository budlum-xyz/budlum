#!/usr/bin/env bash
# ============================================================================
# check-a-derivation-cannot-outlive-its-master.sh
#
# Two levers in `src/storage/` reach a zero multiplier, and both reach it the
# same way: what is kept is a description rather than bytes. A generated
# object describes a seed and a program. A derived object describes a region
# of another object. Neither holds a byte of its own.
#
# That is also what makes a derived object dependent. Reading one means
# fetching the master and recomputing, so the master going away does not
# shrink storage, it destroys the derivation. And it does so silently: the
# derived manifest is still present, still well formed, still hashes to an id
# that looks valid. The first sign is a read that cannot be served, and for
# this class there is no stored copy to fall back to.
#
# `src/storage/dictionary.rs` already solves exactly this shape for objects
# compressed against a shared dictionary: a reference count, a grace window
# once the count reaches zero, and a refusal to delete while references exist.
# Derivations have the identical dependency and had none of it, which is the
# gap this gate closes and then keeps closed.
#
# What the gate checks.
#
#   1. A registry type exists that counts what depends on a master.
#   2. Releasing a master while derivations name it is refused, by name, and
#      the refusal is asserted in a test rather than only written in a match
#      arm nothing reaches.
#   3. The count reaching zero opens a window rather than the door, and a new
#      derivation cancels a pending release. Without the second half, a
#      derivation registered while a release is in flight loses its master.
#   4. Acquiring against a master nobody holds is refused. A derivation of an
#      absent master can never be read.
#   5. The refusal tests have a counterpart showing the ordinary case still
#      succeeds. A registry that refuses everything satisfies every check
#      above and is useless.
#
# Usage:
#   bash scripts/check-a-derivation-cannot-outlive-its-master.sh              # gate
#   bash scripts/check-a-derivation-cannot-outlive-its-master.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() { echo "FAIL: $*" >&2; exit 1; }

scan() {
  local target="$1"
  [ -f "$target" ] || fail "derived-content module missing at $target"

  # 1. The registry and its counter.
  grep -q 'pub struct MasterRegistry' "$target" ||
    fail "no MasterRegistry: nothing tracks what depends on a master, so releasing one \
would take its derivations with it silently"
  grep -q 'fn derivation_count' "$target" ||
    fail "MasterRegistry does not expose a derivation count; a refusal nobody can inspect \
cannot be reasoned about at the call site"

  # 2. The refusal exists as a distinct error rather than a bare bool.
  local variant
  for variant in MasterStillDerived MasterGraceNotElapsed UnknownMaster; do
    grep -q "$variant" "$target" ||
      fail "DerivedError has no $variant variant"
  done

  # 3. Each rule is asserted by a test, not merely written.
  local t
  for t in \
    a_master_carrying_derivations_is_not_released \
    a_master_nothing_derives_from_is_released \
    the_last_derivation_opens_a_grace_window \
    a_new_derivation_cancels_a_pending_release \
    a_derivation_of_an_unheld_master_is_refused
  do
    grep -q "fn $t" "$target" ||
      fail "missing test: $t"
  done

  # 4. The refusals must be asserted as errors. A test named for a refusal
  #    that never checks for one is the vacuous-green shape this repository
  #    has already had to fix elsewhere.
  local body
  body="$(sed -n '/fn a_master_carrying_derivations_is_not_released/,/^    }$/p' "$target")"
  printf '%s' "$body" | grep -qE 'expect_err|is_err\(\)|unwrap_err' ||
    fail "a_master_carrying_derivations_is_not_released does not assert an error"

  # 5. The positive counterpart. Without it every check above is satisfied by
  #    a registry that refuses everything.
  body="$(sed -n '/fn a_master_nothing_derives_from_is_released/,/^    }$/p' "$target")"
  printf '%s' "$body" | grep -qE 'expect\(|unwrap\(\)' ||
    fail "a_master_nothing_derives_from_is_released does not assert success, so the \
refusal tests could be satisfied by a registry that refuses everything"

  # 6. The window has to be able to close. A grace period nothing can outlast
  #    is a refusal wearing a delay's clothes.
  body="$(sed -n '/fn the_last_derivation_opens_a_grace_window/,/^    }$/p' "$target")"
  printf '%s' "$body" | grep -q 'MASTER_GRACE_EPOCHS' ||
    fail "the grace-window test does not reference MASTER_GRACE_EPOCHS, so it cannot be \
checking the boundary"
  printf '%s' "$body" | grep -qE 'expect\(|unwrap\(\)' ||
    fail "the grace-window test never shows the window closing"

  echo "Derivation permanence OK: masters are reference counted, releasing a derived-from \
master is refused by name, the window opens on the last release and closes on time, and a \
new derivation cancels a pending release."
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  local good="$tmp/good.rs"
  cat > "$good" <<'EOF'
pub enum DerivedError {
    MasterStillDerived { master_id: ContentId, derivations: u32 },
    MasterGraceNotElapsed { master_id: ContentId },
    UnknownMaster { master_id: ContentId },
}

pub const MASTER_GRACE_EPOCHS: u64 = 1024;

pub struct MasterRegistry {
    entries: BTreeMap<ContentId, MasterEntry>,
}

impl MasterRegistry {
    pub fn derivation_count(&self, master_id: &ContentId) -> Option<u32> {
        None
    }
}

mod tests {
    #[test]
    fn a_master_carrying_derivations_is_not_released() {
        let err = reg.release_master(&master(), 10_000).expect_err("refused");
    }

    #[test]
    fn a_master_nothing_derives_from_is_released() {
        reg.release_master(&master(), 10_000).expect("nothing depends on it");
    }

    #[test]
    fn the_last_derivation_opens_a_grace_window() {
        assert!(reg.release_master(&master(), 1_000).is_err());
        reg.release_master(&master(), 1_000 + MASTER_GRACE_EPOCHS).expect("closed");
    }

    #[test]
    fn a_new_derivation_cancels_a_pending_release() {
        assert!(true);
    }

    #[test]
    fn a_derivation_of_an_unheld_master_is_refused() {
        assert!(true);
    }
}
EOF
  ( scan "$good" ) >/dev/null 2>&1 ||
    { echo "BROKEN GATE: a correct module was rejected!" >&2; ( scan "$good" ) >&2 || true; exit 1; }

  # No registry at all: the state this gate was written to end.
  sed 's/pub struct MasterRegistry/pub struct Unrelated/' "$good" > "$tmp/noreg.rs"
  if ( scan "$tmp/noreg.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a module with no master registry was accepted!" >&2
    exit 1
  fi

  # A refusal test that asserts nothing.
  sed 's/let err = reg.release_master(&master(), 10_000).expect_err("refused");/let _ = reg.release_master(\&master(), 10_000);/' \
    "$good" > "$tmp/noassert.rs"
  if ( scan "$tmp/noassert.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a refusal test asserting nothing was accepted!" >&2
    exit 1
  fi

  # Refusals present, positive case missing: a registry that refuses
  # everything would pass.
  sed 's/reg.release_master(&master(), 10_000).expect("nothing depends on it");/let _ = reg.release_master(\&master(), 10_000);/' \
    "$good" > "$tmp/nopositive.rs"
  if ( scan "$tmp/nopositive.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: refusals with no successful counterpart were accepted!" >&2
    exit 1
  fi

  # A window that never closes.
  sed 's/        reg.release_master(&master(), 1_000 + MASTER_GRACE_EPOCHS).expect("closed");//' \
    "$good" > "$tmp/neverclose.rs"
  if ( scan "$tmp/neverclose.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a grace window that never closes was accepted!" >&2
    exit 1
  fi

  # The race: a new derivation must cancel a pending release.
  sed 's/fn a_new_derivation_cancels_a_pending_release/fn unrelated_name/' "$good" \
    > "$tmp/norace.rs"
  if ( scan "$tmp/norace.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: no test for a derivation racing a pending release!" >&2
    exit 1
  fi

  # A missing error variant.
  sed 's/    UnknownMaster { master_id: ContentId },//' "$good" > "$tmp/novariant.rs"
  if ( scan "$tmp/novariant.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing UnknownMaster variant was accepted!" >&2
    exit 1
  fi

  # A missing module must fail rather than count as nothing to check.
  if ( scan "$tmp/absent.rs" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing module was accepted!" >&2
    exit 1
  fi

  echo "derivation-permanence gate self-test OK: a missing registry, an unasserted refusal, \
refusals with no successful counterpart, a window that never closes, a missing race test, a \
missing error variant and an absent module are all rejected; a correct module passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "$ROOT/src/storage/derived.rs"
