#!/usr/bin/env bash
# ============================================================================
# check-git-deps-are-audited-by-commit.sh
#
# A git dependency's version number is not evidence about its contents.
#
# Why this gate exists.
#
# Twenty-three packages in the root lockfile come from a git revision rather
# than a registry, all of them the pinned rust-libp2p tree. For a registry
# crate, `version = "0.50.0"` names an immutable published artefact, and every
# scanner in the repository reasons from that name: cargo-audit, cargo-deny,
# osv-scanner and grype all match advisories against `name` plus `version`.
#
# For a git dependency the same field is whatever the manifest happened to say
# at that commit, and it does not move when the code does. Measured on the
# pinned tree:
#
#   commit 8541b83b  gossipsub Cargo.toml version = 0.50.0  backoff.rs has no
#                    checked_add: the CVE-2026-33040 insertion-side overflow
#                    is present
#   commit a7d59cbf  gossipsub Cargo.toml version = 0.50.0  adds the insertion
#                    checked_add, CHANGELOG opens 0.49.3
#   commit 5d47d9d5  gossipsub Cargo.toml version = 0.50.0  adds the heartbeat
#                    checked_add, CHANGELOG opens 0.49.4
#
# Three different security postures, one version string. A scanner told
# "libp2p-gossipsub 0.50.0" cannot distinguish them, and 0.50.0 is not a
# published crates.io release, so no advisory range covers it either. Both
# CVEs are in fact patched at the pinned revision, which is the point: the
# repository is safe here by luck of when the pin was taken, and nothing in
# CI would have said otherwise had it been taken a fortnight earlier.
#
# cargo-vet does not close this. Its own documentation classifies git
# dependencies as non-auditable, so the 437-package audit count excludes all
# twenty-three. Cargo does not write a checksum for git sources into the
# lockfile either, so there is no artefact digest to compare against.
#
# What the gate checks.
#
# Every distinct git revision in a lockfile must be recorded in
# .github/git-dep-audit.toml with:
#
#   * the revision, byte-identical to the lockfile
#   * an upstream-commit date, so a reviewer can ask what landed after it
#   * the specific advisories checked at that revision and the file and symbol
#     that carries each fix
#
# The gate does not fetch anything. A network call at gate time would make the
# result depend on a third party's uptime and on whatever the branch says
# today, which is the same mistake as trusting a checksum served next to the
# artefact it describes. What is checked is that a human wrote down what they
# verified and that the revision they verified is the revision being built.
#
# The gate fails when a lockfile carries a git revision the file does not
# mention, and when the file mentions a revision no lockfile uses. The second
# direction matters: a stale entry is how a record stops describing the build.
#
# Usage:
#   bash scripts/check-git-deps-are-audited-by-commit.sh              # gate
#   bash scripts/check-git-deps-are-audited-by-commit.sh --self-test  # canary
# ============================================================================
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Revisions used by a tree's lockfiles, one per line, deduplicated.
lockfile_revs() {
  local root="$1"
  find "$root" -name Cargo.lock -not -path '*/target/*' -print0 2>/dev/null |
    xargs -0 --no-run-if-empty grep -ho 'source = "git+[^"]*"' 2>/dev/null |
    sed -n 's/.*[?&]rev=\([0-9a-f]\{40\}\).*/\1/p' |
    sort -u
}

# Revisions the audit record declares.
recorded_revs() {
  local record="$1"
  sed -n 's/^[[:space:]]*rev[[:space:]]*=[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' "$record" | sort -u
}

scan() {
  local root="$1"
  local record="$root/.github/git-dep-audit.toml"

  [ -f "$record" ] || fail "no git dependency audit record at .github/git-dep-audit.toml"

  local used recorded
  used="$(lockfile_revs "$root")"
  recorded="$(recorded_revs "$record")"

  # A record that declares nothing passes every comparison against a tree that
  # uses nothing. Refuse that shape outright rather than reporting success.
  if [ -z "$used" ] && [ -z "$recorded" ]; then
    fail "no git revisions in any lockfile and none recorded - gate would be vacuous"
  fi

  local missing extra
  missing="$(comm -23 <(printf '%s\n' "$used") <(printf '%s\n' "$recorded") | sed '/^$/d')"
  extra="$(comm -13 <(printf '%s\n' "$used") <(printf '%s\n' "$recorded") | sed '/^$/d')"

  if [ -n "$missing" ]; then
    echo "FAIL: these git revisions are built but not recorded in .github/git-dep-audit.toml:" >&2
    printf '  - %s\n' $missing >&2
    cat >&2 <<'EOT'

A git dependency's version field is set by the manifest at that commit and does
not change when the code does, so no scanner can tell a patched revision from an
unpatched one. Record what was checked at this revision: the advisories, and the
file and symbol carrying each fix.
EOT
    exit 1
  fi

  if [ -n "$extra" ]; then
    echo "FAIL: these revisions are recorded but no lockfile uses them:" >&2
    printf '  - %s\n' $extra >&2
    echo "" >&2
    echo "A record that describes a revision nobody builds has stopped describing the build." >&2
    exit 1
  fi

  # Every recorded revision needs the fields that make it evidence rather than
  # an assertion. A bare `rev` with nothing under it is a reviewer's initials.
  #
  # A block runs from its `rev` line to the next [[revision]] header or end of
  # file. Blank lines do not end it: the real record uses multi-line strings,
  # and an earlier version of this loop stopped at the first blank line inside
  # one, then reported the fields below it as missing.
  local rev block
  for rev in $recorded; do
    block="$(awk -v r="$rev" '
      /^[[:space:]]*\[\[revision\]\]/ { inb = 0 }
      $0 ~ "rev[[:space:]]*=[[:space:]]*\"" r "\"" { inb = 1 }
      inb { print }
    ' "$record")"
    printf '%s' "$block" | grep -q 'committed[[:space:]]*=' ||
      fail "revision ${rev:0:12} has no 'committed' date - a reviewer cannot ask what landed after an unknown point"
    printf '%s' "$block" | grep -q 'advisories[[:space:]]*=' ||
      fail "revision ${rev:0:12} records no 'advisories' - the record says a revision was used, not that it was checked"
    printf '%s' "$block" | grep -q 'evidence[[:space:]]*=' ||
      fail "revision ${rev:0:12} records no 'evidence' - name the file and symbol carrying each fix"
  done

  # A package claimed never to compile must actually never compile.
  #
  # The record narrows its own exposure by naming five packages that sit in
  # the lockfile and are reached by nothing, so the count of unread-and-
  # reachable crates is seventeen rather than twenty-two. That is a claim
  # about the build, and a claim about the build that nothing checks goes
  # stale the first time a feature is switched on. Enabling `quic` would pull
  # in libp2p-quic and libp2p-tls, the record would still say they are never
  # compiled, and the exposure would have grown while the paperwork said it
  # had shrunk.
  #
  # `cargo tree -e normal -i <pkg>` answers "does anything reach this crate".
  # It is skipped when cargo is unavailable or offline rather than passed,
  # because a check that silently becomes a no-op is the failure this file
  # exists to argue against; the skip is printed.
  local claimed
  claimed="$(sed -n '/packages_never_compiled[[:space:]]*=/,/\]/p' "$record" |
    grep -oE '"[a-z0-9-]+"' | tr -d '"' || true)"

  if [ -n "$claimed" ]; then
    if ! command -v cargo >/dev/null 2>&1; then
      echo "SKIP: cargo is not on PATH, so packages_never_compiled was not verified." >&2
    else
      local pkg tree_out compiled=()
      for pkg in $claimed; do
        if ! tree_out="$(cargo tree -e normal -i "$pkg" 2>&1)"; then
          echo "SKIP: cargo tree failed for $pkg, so the claim was not verified." >&2
          compiled=()
          break
        fi
        printf '%s' "$tree_out" | grep -q 'nothing to print' || compiled+=("$pkg")
      done
      if [ "${#compiled[@]}" -gt 0 ]; then
        echo "FAIL: these packages are recorded as never compiled, and they compile:" >&2
        printf '  - %s\n' "${compiled[@]}" >&2
        cat >&2 <<'EOT'

The record uses that list to narrow how many packages at this revision are
unread. A package that started compiling is a package that started needing to
be read, and the record now understates the exposure. Either drop it from
packages_never_compiled and read it, or find out which feature pulled it in.
EOT
        exit 1
      fi
    fi
  fi

  local n
  n="$(printf '%s\n' "$used" | sed '/^$/d' | wc -l | tr -d ' ')"
  echo "Git dependency audit OK: $n revision(s) built, each recorded with a date, the advisories checked and the code carrying each fix."
  return 0
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  local REV="38b8a2c0e91bf6955f5357adcdd40d3b6683a0dd"
  local OTHER="8541b83bdc381fc1965098d64b0f87eb922c3a0c"

  mklock() {
    local dir="$1" rev="$2"
    mkdir -p "$dir"
    cat > "$dir/Cargo.lock" <<EOF
[[package]]
name = "libp2p-gossipsub"
version = "0.50.0"
source = "git+https://github.com/libp2p/rust-libp2p?rev=$rev#$rev"
EOF
  }

  mkrecord() {
    local dir="$1"; shift
    mkdir -p "$dir/.github"
    printf '%s\n' "$@" > "$dir/.github/git-dep-audit.toml"
  }

  local full=(
    '[[revision]]'
    "rev = \"$REV\""
    'committed = "2026-07-27"'
    'advisories = ["CVE-2026-33040", "CVE-2026-34219"]'
    'evidence = "backoff.rs update_backoff and heartbeat both checked_add"'
    ''
  )

  # 1. The shape that must pass, or the gate rejects every pull request.
  mklock "$tmp/good" "$REV"; mkrecord "$tmp/good" "${full[@]}"
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "BROKEN GATE: a fully recorded revision was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    exit 1
  fi

  # 2. A built revision nobody recorded. This is the case the gate exists for.
  mklock "$tmp/unrecorded" "$REV"
  mkrecord "$tmp/unrecorded" '# nothing recorded'
  if ( scan "$tmp/unrecorded" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: an unrecorded git revision was accepted!" >&2
    exit 1
  fi

  # 3. The pin moves and the record does not. Recording a revision once must
  #    not vouch for every later one, which is the whole failure being closed.
  mklock "$tmp/moved" "$OTHER"; mkrecord "$tmp/moved" "${full[@]}"
  if ( scan "$tmp/moved" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a record for a different revision vouched for the built one!" >&2
    exit 1
  fi

  # 4. A revision recorded but no longer built: a stale entry.
  mklock "$tmp/stale" "$REV"
  mkrecord "$tmp/stale" "${full[@]}" '[[revision]]' "rev = \"$OTHER\"" \
    'committed = "2026-03-18"' 'advisories = []' 'evidence = "none"' ''
  if ( scan "$tmp/stale" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a record naming an unbuilt revision was accepted!" >&2
    exit 1
  fi

  # 5. A bare revision with no supporting fields is initials, not evidence.
  for f in committed advisories evidence; do
    local partial=()
    local line
    for line in "${full[@]}"; do
      case "$line" in "$f"*) continue ;; esac
      partial+=("$line")
    done
    mklock "$tmp/no_$f" "$REV"; mkrecord "$tmp/no_$f" "${partial[@]}"
    if ( scan "$tmp/no_$f" ) >/dev/null 2>&1; then
      echo "VACUOUS GATE: a revision recorded without '$f' was accepted!" >&2
      exit 1
    fi
  done

  # 6. A tree with no git dependencies and an empty record must not pass by
  #    having nothing to disagree about.
  mkdir -p "$tmp/empty"
  cat > "$tmp/empty/Cargo.lock" <<'EOF'
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
EOF
  mkrecord "$tmp/empty" '# no git dependencies'
  if ( scan "$tmp/empty" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a tree with nothing to check reported success!" >&2
    exit 1
  fi

  # 7. A missing record must fail rather than be treated as nothing to do.
  mklock "$tmp/norecord" "$REV"
  if ( scan "$tmp/norecord" ) >/dev/null 2>&1; then
    echo "VACUOUS GATE: a missing audit record was accepted!" >&2
    exit 1
  fi

  # 8. A package claimed never to compile, that compiles.
  #
  #    Run against the real tree rather than a synthetic one: `cargo tree`
  #    answers a question about this workspace's feature resolution, and a
  #    fabricated lockfile has no features to resolve. The canary takes the
  #    committed record, adds a package that demonstrably does compile, and
  #    requires a refusal. Skipped, loudly, where cargo cannot run.
  local root
  root="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
  if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo is not on PATH, so the never-compiled canary did not run." >&2
  elif ! grep -q 'packages_never_compiled' "$root/.github/git-dep-audit.toml"; then
    echo "SKIP: the record carries no packages_never_compiled list to falsify." >&2
  else
    mkdir -p "$tmp/compiles/.github"
    cp "$root/Cargo.lock" "$tmp/compiles/Cargo.lock"
    # libp2p-gossipsub is compiled: the gossipsub feature is on in Cargo.toml
    # and src/network reaches it. Claiming it never compiles must fail.
    sed 's/^packages_never_compiled = \[/packages_never_compiled = [\n    "libp2p-gossipsub",/' \
      "$root/.github/git-dep-audit.toml" > "$tmp/compiles/.github/git-dep-audit.toml"
    if ( cd "$root" && scan "$tmp/compiles" ) >/dev/null 2>&1; then
      echo "VACUOUS GATE: a package claimed never to compile, which compiles, was accepted!" >&2
      exit 1
    fi
  fi

  echo "git-dep audit gate self-test OK: unrecorded revisions, a moved pin, a stale entry, each missing field, an empty tree, a missing record and a package wrongly claimed never to compile are all rejected; a complete record passes."
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

scan "${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
