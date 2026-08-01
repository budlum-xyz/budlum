#!/usr/bin/env bash
# ============================================================================
# check-gates-are-wired.sh, every gate script must actually run somewhere.
#
# A script in `scripts/` that no workflow invokes proves nothing about any
# commit, but it still shows up when someone counts the gates. Four of them
# had accumulated that way (`check-bloat.sh`, `check-kani.sh`,
# `check-machete.sh`, `check-taplo.sh`, all added in one commit), and three
# duplicated work that `extra-tooling.yml` was already doing properly with
# pinned tool versions and real canaries.
#
# This gate closes the door behind them: a new `scripts/check-*.sh` has to be
# referenced by a workflow, or CI fails and says so by name.
#
# Run with --self-test to prove the check can fail.
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-.}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Scripts that are deliberately not invoked by a workflow.
#
# Empty on purpose. An entry here is a standing claim that a gate is worth
# keeping without running, which is a hard claim to make honestly, if it is
# worth keeping, wire it up. Anything added here needs the reason in the same
# commit.
ALLOWED_UNWIRED=()

is_allowed() {
  local name="$1"
  local allowed
  for allowed in ${ALLOWED_UNWIRED[@]+"${ALLOWED_UNWIRED[@]}"}; do
    [ "$name" = "$allowed" ] && return 0
  done
  return 1
}

# A script counts as wired if any workflow file mentions its basename.
# Deliberately a plain substring match: the point is to catch scripts nothing
# references at all, not to parse shell invocations out of YAML.
check_wired() {
  local root="$1"
  local workflows="$root/.github/workflows"
  [ -d "$workflows" ] || fail "no workflow directory at $workflows"

  local found_any=0
  local unwired=()
  local script name

  for script in "$root"/scripts/check-*.sh; do
    [ -e "$script" ] || continue
    found_any=1
    name="$(basename "$script")"
    is_allowed "$name" && continue
    if ! grep -rqF "$name" "$workflows" 2>/dev/null; then
      unwired+=("$name")
    fi
  done

  # Guard against the gate silently passing on an empty or misnamed tree.
  [ "$found_any" -eq 1 ] || fail "no scripts/check-*.sh found under $root - wrong root?"

  if [ "${#unwired[@]}" -gt 0 ]; then
    echo "FAIL: these gate scripts are never invoked by any workflow:" >&2
    printf '  - %s\n' "${unwired[@]}" >&2
    echo "Wire them into .github/workflows/, or delete them. A gate that does not run is not a gate." >&2
    exit 1
  fi

  local total
  total="$(find "$root/scripts" -maxdepth 1 -name 'check-*.sh' | wc -l | tr -d ' ')"
  echo "Gate wiring OK: all $total scripts/check-*.sh are referenced by a workflow."
}

self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap 'rm -rf "${SELF_TEST_TMP:-}"' EXIT
  local tmp="$SELF_TEST_TMP"

  mkdir -p "$tmp/scripts" "$tmp/.github/workflows"
  printf '#!/usr/bin/env bash\ntrue\n' > "$tmp/scripts/check-wired-example.sh"
  cat > "$tmp/.github/workflows/ci.yml" <<'YML'
jobs:
  example:
    steps:
      - run: bash ./scripts/check-wired-example.sh
YML

  # A tree where the only gate is wired must pass, otherwise the negative
  # case below would prove nothing.
  if ! (check_wired "$tmp" >/dev/null 2>&1); then
    echo "FAIL: self-test could not make a correctly wired tree pass" >&2
    exit 1
  fi

  # Add a gate nothing references; the check must notice.
  printf '#!/usr/bin/env bash\ntrue\n' > "$tmp/scripts/check-orphan-example.sh"
  if (check_wired "$tmp" >/dev/null 2>&1); then
    echo "FAIL: gate accepted a tree containing an unwired script (vacuous gate)" >&2
    exit 1
  fi

  echo "Gate wiring self-test OK"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

check_wired "${1:-$ROOT}"
