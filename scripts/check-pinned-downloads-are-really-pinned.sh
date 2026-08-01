#!/usr/bin/env bash
# ============================================================================
# check-pinned-downloads-are-really-pinned.sh, a checksum fetched from the
# server it verifies is not a pin.
#
# The coverage job installed two tools. One was pinned:
#
#   curl -sSfL -o /tmp/clcov.tar.gz https://.../cargo-llvm-cov-....tar.gz
#   echo "9a75fe29...  /tmp/clcov.tar.gz" | sha256sum -c -
#
# The other only looked pinned:
#
#   curl -sSfLO https://.../cargo-nextest-0.9.140-...tar.gz
#   curl -sSfLO https://.../cargo-nextest-0.9.140-...sha256
#   sha256sum -c cargo-nextest-0.9.140-...sha256
#
# Both files come from the same release. Anyone who can replace the tarball can
# replace the `.sha256` next to it, so the check verifies the artefact against
# a hash the artefact's own host supplied, it proves the download was not
# corrupted in transit and nothing else. The step was named
# "(sha256 pinli)" and had been for as long as it existed.
#
# The distinction matters most in exactly the situation a pin is for: a
# compromised or hijacked release. A transit-integrity check passes happily
# through that; a checked-in hash does not.
#
# This gate requires that every checksum a workflow verifies against is written
# in the repository, and fails when one is downloaded instead.
#
# Usage:
#   bash scripts/check-pinned-downloads-are-really-pinned.sh              # gate
#   bash scripts/check-pinned-downloads-are-really-pinned.sh --self-test  # canary
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# A workflow fetches a checksum file if it curls a URL ending in a checksum
# extension. Those are the ones that cannot serve as a pin.
scan() {
  local root="$1"
  local workflows="$root/.github/workflows"
  [ -d "$workflows" ] || fail "no workflow directory at $workflows"

  local found_any=0 offenders=() f line n
  for f in "$workflows"/*.yml "$workflows"/*.yaml; do
    [ -e "$f" ] || continue
    found_any=1
    n=0
    while IFS= read -r line; do
      n=$((n + 1))
      # Only curl/wget lines matter; a bare mention in a comment does not.
      case "$line" in
        *curl*|*wget*) ;;
        *) continue ;;
      esac
      # A remote checksum file being fetched.
      if printf '%s' "$line" | grep -qE 'https?://[^[:space:]]+\.(sha256|sha512|sha1|md5|checksum|checksums)([[:space:]]|$|\\)'; then
        offenders+=("$(basename "$f"):$n")
      fi
    done < "$f"
  done

  [ "$found_any" -eq 1 ] || fail "no workflow files found under $workflows - wrong root?"

  if [ "${#offenders[@]}" -gt 0 ]; then
    echo "FAIL: these workflow lines download a checksum from the same host as the artefact:" >&2
    printf '  - %s\n' "${offenders[@]}" >&2
    cat >&2 <<'EOT'
A hash served next to the file it describes verifies transit, not provenance:
whoever can replace one can replace the other. Write the expected hash into the
workflow instead, the way the cargo-llvm-cov step does:

    curl -sSfL -o /tmp/tool.tar.gz https://.../tool.tar.gz
    echo "<hash>  /tmp/tool.tar.gz" | sha256sum -c -

Obtain the hash by downloading the artefact once and hashing it yourself, and
record when it was taken.
EOT
    exit 1
  fi

  # Guard against passing on a tree where no workflow verifies anything at all.
  local verifies
  verifies="$(grep -rlE 'sha256sum -c|shasum -a 256 -c' "$workflows" 2>/dev/null | wc -l | tr -d ' ')"
  [ "$verifies" -gt 0 ] || fail "no workflow verifies any checksum - the gate would be vacuous"

  echo "Download pinning OK: every verified checksum is written in the repository ($verifies workflow file(s) verify hashes; none fetch one)."
  return 0
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  mk() {
    local dir="$1"; shift
    rm -rf "$dir"; mkdir -p "$dir/.github/workflows"
    printf '%s\n' "$@" > "$dir/.github/workflows/ci.yml"
  }

  # 1. The real case: the checksum is downloaded from the artefact's own
  #    release. This is what shipped, and it must fail.
  mk "$tmp/fetched" \
    '        run: |' \
    '          curl -sSfLO https://github.com/x/y/releases/download/v1/tool.tar.gz' \
    '          curl -sSfLO https://github.com/x/y/releases/download/v1/tool.sha256' \
    '          sha256sum -c tool.sha256'
  if ( scan "$tmp/fetched" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a checksum downloaded from the artefact's own host was accepted!" >&2
    exit 1
  fi

  # 2. Same shape with wget and .sha512 must also fail.
  mk "$tmp/wget" \
    '        run: |' \
    '          wget https://example.com/tool.tar.gz' \
    '          wget https://example.com/tool.sha512' \
    '          sha256sum -c tool.sha512'
  if ( scan "$tmp/wget" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a wget-fetched .sha512 was accepted!" >&2
    exit 1
  fi

  # 3. A tree where nothing verifies anything must fail rather than pass by
  #    having no offenders.
  mk "$tmp/noverify" \
    '        run: |' \
    '          curl -sSfL -o /tmp/tool.tar.gz https://example.com/tool.tar.gz' \
    '          tar -xzf /tmp/tool.tar.gz'
  if ( scan "$tmp/noverify" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree that verifies no checksum at all was accepted!" >&2
    exit 1
  fi

  # 4. A missing workflow directory must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty"
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no workflows was accepted!" >&2
    exit 1
  fi

  # 5. The correct shape must pass, or the gate rejects every pull request.
  mk "$tmp/good" \
    '        run: |' \
    '          curl -sSfL -o /tmp/tool.tar.gz https://example.com/tool.tar.gz' \
    '          echo "abc123  /tmp/tool.tar.gz" | sha256sum -c -'
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a checked-in hash was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    exit 1
  fi

  # 6. A URL merely mentioned in a comment is not a download.
  mk "$tmp/comment" \
    '        # see https://example.com/tool.sha256 for upstream hashes' \
    '        run: |' \
    '          curl -sSfL -o /tmp/tool.tar.gz https://example.com/tool.tar.gz' \
    '          echo "abc123  /tmp/tool.tar.gz" | sha256sum -c -'
  if ! ( scan "$tmp/comment" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a checksum URL inside a comment was treated as a download!" >&2
    exit 1
  fi

  echo "pinned-download gate self-test OK: fetched checksums (curl and wget), a tree that verifies nothing and a missing workflow directory are all rejected; a checked-in hash passes and a commented URL is ignored."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
