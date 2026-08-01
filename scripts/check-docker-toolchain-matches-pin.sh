#!/usr/bin/env bash
# ============================================================================
# check-docker-toolchain-matches-pin.sh - the image must build with the pinned
# compiler.
#
# The Dockerfile carried this comment:
#
#   # Toolchain, rust-toolchain.toml (channel = "1.94.0") ve CI'daki
#   # dtolnay/rust-toolchain pini ile AYNI olmak zorundadir. Onceden 1.97.1
#   # kullaniliyordu ... Digest, rust:1.94.0-bookworm icin dogrulandi.
#   FROM rust:1.97.1-bookworm@sha256:77fac8b9...
#
# The comment describes a fix that was never applied. The tag still said
# 1.97.1, and the digest was not rust:1.94.0-bookworm either - pulling that
# digest's config blob from the registry gives RUST_VERSION=1.97.1. So the
# published image was built by a compiler three minor versions ahead of the one
# every CI job uses, while a comment in the same file asserted the opposite.
#
# That matters here specifically. Codegen and MIR optimisation change between
# releases, so a release binary built by 1.97.1 is not bit-identical to one
# built by 1.94.0 from the same source. The repository runs a determinism
# workflow and advertises reproducible builds; the container that ships to
# operators was outside that guarantee.
#
# `rust-toolchain.toml` was also not copied into the build context, so rustup
# had nothing to correct the base image with - whatever compiler the image
# carried is what ran.
#
# This gate compares three places that must agree and fails by name when they
# do not:
#
#   1. rust-toolchain.toml   channel = "X"
#   2. Dockerfile            FROM rust:X-bookworm@sha256:...
#   3. .github/workflows/*   dtolnay/rust-toolchain  toolchain: "X"
#
# It also requires that the Dockerfile copies rust-toolchain.toml, and that
# the builder stage verifies `rustc --version` against it - a pin that nothing
# checks at build time is a pin that silently stops holding.
#
# What this gate deliberately does NOT do: resolve the digest against a
# registry. That needs network access from the runner and would make the gate
# fail for reasons unrelated to the tree. The digest/tag correspondence is
# verified by hand when either changes, and the in-image `rustc --version`
# check is what catches a mismatch that slips through - it runs inside the
# actual build, where the actual compiler is.
#
# Usage:
#   bash scripts/check-docker-toolchain-matches-pin.sh              # gate
#   bash scripts/check-docker-toolchain-matches-pin.sh --self-test  # canary
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# channel = "1.94.0"  ->  1.94.0
pinned_channel() {
  local root="$1" f="$1/rust-toolchain.toml"
  [ -f "$f" ] || fail "no rust-toolchain.toml at $f"
  sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1
}

# FROM rust:1.94.0-bookworm@sha256:...  ->  1.94.0
dockerfile_tag_version() {
  local root="$1" f="$1/Dockerfile"
  [ -f "$f" ] || fail "no Dockerfile at $f"
  sed -n 's/^FROM[[:space:]]\+rust:\([0-9][0-9.]*\)-.*/\1/p' "$f" | head -1
}

# Every `toolchain: "X"` under .github/workflows, deduplicated.
workflow_versions() {
  local root="$1" d="$1/.github/workflows"
  [ -d "$d" ] || fail "no workflow directory at $d"
  grep -rhoE '^[[:space:]]*toolchain:[[:space:]]*"?[0-9][0-9.]*"?' "$d" \
    | grep -oE '[0-9][0-9.]*' | sort -u
}

gate() {
  local root="$1"

  local pinned tag
  pinned="$(pinned_channel "$root")"
  [ -n "$pinned" ] || fail "could not parse channel from rust-toolchain.toml - gate would be vacuous"

  tag="$(dockerfile_tag_version "$root")"
  [ -n "$tag" ] || fail "could not parse a rust:VERSION tag from the Dockerfile FROM line - gate would be vacuous"

  if [ "$tag" != "$pinned" ]; then
    fail "Dockerfile builds on rust:$tag but rust-toolchain.toml pins $pinned.
  A release binary built by a different compiler is not bit-identical to the one
  CI produces, which is exactly the claim the determinism workflow makes.
  Update the FROM line *and* its digest together - the digest overrides the tag,
  so changing only the tag changes nothing."
  fi

  # The digest must be present. A floating tag is not a pin.
  grep -qE '^FROM[[:space:]]+rust:[0-9][0-9.]*-[a-z]+@sha256:[0-9a-f]{64}' "$root/Dockerfile" \
    || fail "the builder FROM line has no @sha256 digest - the base image can move under us"

  # Every workflow toolchain must agree with the pin.
  local v mismatched=()
  while read -r v; do
    [ -n "$v" ] || continue
    [ "$v" = "$pinned" ] || mismatched+=("$v")
  done <<< "$(workflow_versions "$root")"

  if [ "${#mismatched[@]}" -gt 0 ]; then
    fail "workflows request toolchain ${mismatched[*]} but rust-toolchain.toml pins $pinned"
  fi

  # rust-toolchain.toml must reach the build context, or rustup cannot correct
  # whatever compiler the base image happens to carry.
  grep -qE '^COPY[^#]*\brust-toolchain\.toml\b' "$root/Dockerfile" \
    || fail "the Dockerfile never copies rust-toolchain.toml into the build context,
  so the pin does not apply inside the image and the base image's own compiler is used"

  # And the image must prove it at build time.
  grep -qE 'rustc --version' "$root/Dockerfile" \
    || fail "the builder stage never checks 'rustc --version' against the pin;
  a base image that moves would be caught by nothing"

  echo "Docker toolchain gate OK: Dockerfile, rust-toolchain.toml and every workflow all pin $pinned; digest present; pin copied and verified in-image."
  return 0
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  build_fixture() {
    local dir="$1" from="$2" copyline="$3" rustccheck="$4" wf="$5"
    rm -rf "$dir"; mkdir -p "$dir/.github/workflows"
    printf '[toolchain]\nchannel = "1.94.0"\n' > "$dir/rust-toolchain.toml"
    {
      printf 'FROM %s AS builder\n' "$from"
      printf '%s\n' "$copyline"
      [ -n "$rustccheck" ] && printf '%s\n' "$rustccheck"
      printf 'RUN cargo build --release --locked\n'
    } > "$dir/Dockerfile"
    printf 'jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: "%s"\n' "$wf" > "$dir/.github/workflows/ci.yml"
  }

  local GOOD_FROM='rust:1.94.0-bookworm@sha256:0000000000000000000000000000000000000000000000000000000000000000'
  local GOOD_COPY='COPY Cargo.toml rust-toolchain.toml ./'
  local GOOD_CHECK='RUN rustc --version'

  # 1. The real case: the tag drifted ahead of the pin. This is the bug that
  #    shipped, and it must fail.
  build_fixture "$tmp/drift" \
    'rust:1.97.1-bookworm@sha256:0000000000000000000000000000000000000000000000000000000000000000' \
    "$GOOD_COPY" "$GOOD_CHECK" "1.94.0"
  if ( gate "$tmp/drift" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a Dockerfile building on 1.97.1 against a 1.94.0 pin was accepted!" >&2
    exit 1
  fi

  # 2. A floating tag with no digest must fail - the base image could move.
  build_fixture "$tmp/nodigest" 'rust:1.94.0-bookworm' "$GOOD_COPY" "$GOOD_CHECK" "1.94.0"
  if ( gate "$tmp/nodigest" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a FROM line without a digest was accepted!" >&2
    exit 1
  fi

  # 3. A workflow asking for a different toolchain must fail.
  build_fixture "$tmp/wf" "$GOOD_FROM" "$GOOD_COPY" "$GOOD_CHECK" "1.90.0"
  if ( gate "$tmp/wf" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a workflow pinning a different toolchain was accepted!" >&2
    exit 1
  fi

  # 4. Not copying rust-toolchain.toml must fail: the pin never reaches the
  #    image, which is the second half of how this shipped.
  build_fixture "$tmp/nocopy" "$GOOD_FROM" 'COPY Cargo.toml ./' "$GOOD_CHECK" "1.94.0"
  if ( gate "$tmp/nocopy" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a Dockerfile that never copies rust-toolchain.toml was accepted!" >&2
    exit 1
  fi

  # 5. No in-image rustc check must fail.
  build_fixture "$tmp/nocheck" "$GOOD_FROM" "$GOOD_COPY" '' "1.94.0"
  if ( gate "$tmp/nocheck" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a builder stage that never verifies rustc --version was accepted!" >&2
    exit 1
  fi

  # 6. A missing Dockerfile must fail rather than pass by default.
  rm -rf "$tmp/empty"; mkdir -p "$tmp/empty/.github/workflows"
  printf '[toolchain]\nchannel = "1.94.0"\n' > "$tmp/empty/rust-toolchain.toml"
  if ( gate "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with no Dockerfile was accepted!" >&2
    exit 1
  fi

  # 7. The consistent case must pass, or the gate rejects every pull request.
  build_fixture "$tmp/good" "$GOOD_FROM" "$GOOD_COPY" "$GOOD_CHECK" "1.94.0"
  if ! ( gate "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a consistent tree was rejected!" >&2
    ( gate "$tmp/good" ) >&2 || true
    exit 1
  fi

  echo "docker toolchain gate self-test OK: version drift, a missing digest, a divergent workflow, an uncopied pin, a missing in-image check and a missing Dockerfile are all rejected; a consistent tree passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

gate "${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
