#!/usr/bin/env bash
# Keeps src/crypto/domain_tags.rs honest.
#
# The inventory is a hand-checkable list of every cryptographic domain-separation
# Tag in the workspace. A list like that is only worth having if it cannot drift,
# So this compares it against the tags actually present in the source tree and
# Fails on any difference in either direction:
#
#   - a tag used in code but missing from the inventory means a new separation
#     Domain slipped in without review;
#   - a tag listed but no longer used means the inventory is stale and a future
#     Reviewer would be checking a surface that does not exist.
#
# Run with --self-test to prove the comparison can fail (see the canary below).
set -euo pipefail

ROOT="${BUDLUM_ROOT:-.}"
INVENTORY="src/crypto/domain_tags.rs"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Tags written as string literals anywhere in the Rust sources, minus the
# Inventory itself (which is where the expected answer lives).
tags_in_sources() {
  local root="$1"
  grep -rhoE '"BDLM_[A-Z0-9_]+"' \
    --include='*.rs' \
    "$root/src" "$root/budzero" "$root/wallet-core" 2>/dev/null \
    | tr -d '"' \
    | sort -u
}

# Tags listed in the inventory constant.
tags_in_inventory() {
  local root="$1"
  grep -oE '"BDLM_[A-Z0-9_]+"' "$root/$INVENTORY" \
    | tr -d '"' \
    | sort -u
}

check_tree() {
  local root="$1"

  [[ -f "$root/$INVENTORY" ]] || fail "missing inventory: $INVENTORY"

  local listed used
  listed="$(mktemp)"
  used="$(mktemp)"

  tags_in_inventory "$root" > "$listed"

  # The inventory file is a .rs file under src/ too, so its own literals are
  # Excluded from the "used in code" side of the comparison.
  grep -rhoE '"BDLM_[A-Z0-9_]+"' \
    --include='*.rs' \
    --exclude="$(basename "$INVENTORY")" \
    "$root/src" "$root/budzero" "$root/wallet-core" 2>/dev/null \
    | tr -d '"' | sort -u > "$used"

  local missing extra
  missing="$(comm -23 "$used" "$listed" || true)"
  extra="$(comm -13 "$used" "$listed" || true)"
  local count
  count="$(wc -l < "$listed" | tr -d ' ')"
  rm -f "$listed" "$used"

  if [[ -n "$missing" ]]; then
    echo "Domain tags used in code but absent from $INVENTORY:" >&2
    echo "$missing" | sed 's/^/  + /' >&2
    fail "inventory is incomplete"
  fi

  if [[ -n "$extra" ]]; then
    echo "Domain tags listed in $INVENTORY but unused in code:" >&2
    echo "$extra" | sed 's/^/  - /' >&2
    fail "inventory is stale"
  fi

  echo "Domain tag inventory OK ($count tags)"
}

# Canary: build a tree where a tag is used but unlisted, and require the check
# To reject it. Without this the gate could pass by never comparing anything.
self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT
  mkdir -p "$tmp/src/crypto" "$tmp/budzero" "$tmp/wallet-core"

  cat > "$tmp/src/crypto/domain_tags.rs" <<'DOC'
pub const DOMAIN_TAGS: &[&str] = &["BDLM_LISTED_V1"];
DOC
  cat > "$tmp/src/used.rs" <<'DOC'
const A: &str = "BDLM_LISTED_V1";
DOC

  ( check_tree "$tmp" ) >/dev/null || fail "self-test: matching tree should pass"

  cat > "$tmp/src/sneaky.rs" <<'DOC'
const B: &str = "BDLM_UNLISTED_V1";
DOC
  if ( check_tree "$tmp" ) >/dev/null 2>&1; then
    fail "self-test: unlisted tag was not caught"
  fi

  rm "$tmp/src/sneaky.rs"
  cat > "$tmp/src/crypto/domain_tags.rs" <<'DOC'
pub const DOMAIN_TAGS: &[&str] = &["BDLM_LISTED_V1", "BDLM_GONE_V1"];
DOC
  if ( check_tree "$tmp" ) >/dev/null 2>&1; then
    fail "self-test: stale tag was not caught"
  fi

  echo "Domain tag gate self-test OK"
}

case "${1:-}" in
  --self-test) self_test ;;
  "") check_tree "$ROOT" ;;
  *) check_tree "$1" ;;
esac
