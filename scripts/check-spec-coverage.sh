#!/usr/bin/env bash
set -euo pipefail

ROOT="${BUDLUM_SPEC_ROOT:-.}"

required_specs=(
  "docs/GENESIS_REWARD_POOL_SPEC.md|docs/spec-review/GENESIS_REWARD_POOL_SPEC_REVIEW.md|GENESIS_REWARD_POOL_SPEC"
  "docs/BUD_STORAGE_TECHNICAL_SPEC.md|docs/spec-review/BUD_STORAGE_TECHNICAL_SPEC_REVIEW.md|BUD_STORAGE_TECHNICAL_SPEC"
  "docs/DOMAIN_FORK_CHOICE_SPEC.md|docs/spec-review/DOMAIN_FORK_CHOICE_SPEC_REVIEW.md|DOMAIN_FORK_CHOICE_SPEC"
  "docs/EIP1559_FEE_MARKET_SPEC.md|docs/spec-review/EIP1559_FEE_MARKET_SPEC_REVIEW.md|EIP1559_FEE_MARKET_SPEC"
)

required_review_lines=(
  "**Status:** Approved"
  "- [x] Interface frozen marker present"
  "- [x] ADR link present"
  "- [x] Scope and non-goals documented"
  "- [x] Security/threat interaction documented"
  "- [x] State/root/supply interaction documented where relevant"
  "- [x] Test or CI gate defined"
  "- [x] Implementation phase and owner path identified"
)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

check_one() {
  local spec="$1"
  local review="$2"
  local label="$3"
  local spec_path="$ROOT/$spec"
  local review_path="$ROOT/$review"

  [[ -f "$spec_path" ]] || fail "$label spec missing: $spec"
  [[ -f "$review_path" ]] || fail "$label review missing: $review"

  grep -Eq "INTERFACE_FROZEN[:*[:space:]]+true" "$spec_path" \
    || fail "$label missing INTERFACE_FROZEN: true marker"
  grep -Fq "SPEC_REVIEW:" "$spec_path" \
    || fail "$label missing SPEC_REVIEW link"
  if ! grep -Fq "$review" "$spec_path" && ! grep -Fq "$(basename "$review")" "$spec_path"; then
    fail "$label SPEC_REVIEW does not point to $review"
  fi
  grep -Eq "ADR.*ADR-[0-9]{3}|ADR-[0-9]{3}" "$spec_path" \
    || fail "$label missing ADR reference"
  grep -Eq "Interface Freeze|interface-frozen|interface frozen" "$spec_path" \
    || fail "$label missing interface freeze section"
  grep -Eq "CI Kapısı|CI gate|spec-coverage|check-spec-coverage" "$spec_path" \
    || fail "$label missing CI/spec gate section"

  for line in "${required_review_lines[@]}"; do
    grep -Fq -- "$line" "$review_path" \
      || fail "$label review missing checklist line: $line"
  done

  grep -Fq "$spec" "$review_path" \
    || fail "$label review does not mention spec path"
}

run_check() {
  [[ -d "$ROOT/docs/spec-review" ]] || fail "docs/spec-review directory missing"
  [[ -f "$ROOT/docs/spec-review/README.md" ]] || fail "docs/spec-review/README.md missing"

  local item spec review label
  for item in "${required_specs[@]}"; do
    IFS='|' read -r spec review label <<<"$item"
    check_one "$spec" "$review" "$label"
  done

  echo "Spec coverage gate OK: ${#required_specs[@]} Phase 11.6 specs are interface-frozen and reviewed."
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT

  mkdir -p "$tmp/good/docs/spec-review" "$tmp/bad/docs/spec-review"
  cp "$ROOT/docs/spec-review/README.md" "$tmp/good/docs/spec-review/README.md" 2>/dev/null || echo "# review" > "$tmp/good/docs/spec-review/README.md"
  cp "$tmp/good/docs/spec-review/README.md" "$tmp/bad/docs/spec-review/README.md"

  local item spec review label
  for item in "${required_specs[@]}"; do
    IFS='|' read -r spec review label <<<"$item"
    mkdir -p "$(dirname "$tmp/good/$spec")" "$(dirname "$tmp/good/$review")" \
             "$(dirname "$tmp/bad/$spec")" "$(dirname "$tmp/bad/$review")"
    cat > "$tmp/good/$spec" <<EOF_SPEC
# $label
**ADR:** ADR-999
**SPEC_REVIEW:** [$review]($review)
**INTERFACE_FROZEN:** true
## Interface Freeze
## CI Kapısı
EOF_SPEC
    cat > "$tmp/good/$review" <<EOF_REVIEW
# Review $label
**Spec:** \`$spec\`
**Status:** Approved
- [x] Interface frozen marker present
- [x] ADR link present
- [x] Scope and non-goals documented
- [x] Security/threat interaction documented
- [x] State/root/supply interaction documented where relevant
- [x] Test or CI gate defined
- [x] Implementation phase and owner path identified
EOF_REVIEW
    cp "$tmp/good/$spec" "$tmp/bad/$spec"
    cp "$tmp/good/$review" "$tmp/bad/$review"
  done

  BUDLUM_SPEC_ROOT="$tmp/good" bash "$0" >/dev/null
  perl -0pi -e 's/INTERFACE_FROZEN:\*\* true/INTERFACE_FROZEN:** false/' "$tmp/bad/docs/GENESIS_REWARD_POOL_SPEC.md"
  if BUDLUM_SPEC_ROOT="$tmp/bad" bash "$0" >/dev/null 2>&1; then
    fail "self-test expected bad fixture to fail"
  fi
  echo "Spec coverage self-test OK"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  run_check
fi
