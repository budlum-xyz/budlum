#!/usr/bin/env bash
# ============================================================================
# check-paid-content-cannot-be-read-for-free.sh
#
# Pollen sells permission. B.U.D. serves bytes. They were built separately and
# nothing joined them, so the same object could be listed for sale here and
# fetched from storage by anyone who knew its `manifest_id`, with the second
# path asking no questions. Paying was optional in the only sense that counts.
#
# Three properties keep that closed, and each is invisible in review:
#
#   1. the read path consults the binding at all. A refactor that drops the
#      `authorize_content_read` call leaves every test passing, because the
#      tests that would catch it are the ones nobody writes for a check that
#      used to be there;
#   2. protected content can never be declared public. The public class is
#      the deduplicated one, and deduplication keys on content, so a listed
#      asset in it can be confirmed by anyone who guesses the bytes, or have
#      a missing field brute-forced. That is confirmation-of-a-file and
#      learn-the-remaining-information, and paid data is their target;
#   3. the binding is one-way. An unbind would let an owner take payment and
#      then release the bytes into the free path, which is the same as not
#      having sold anything.
#
# Usage:
#   bash scripts/check-paid-content-cannot-be-read-for-free.sh              # gate
#   bash scripts/check-paid-content-cannot-be-read-for-free.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
GATE_SRC="$ROOT/src/pollen/content_gate.rs"
OFFERS_SRC="$ROOT/src/pollen/offers.rs"

fail() { echo "FAIL: $*" >&2; exit 1; }

# 1. The authorisation path refuses when no grant is presented.
#
# Looks for the refusal itself rather than the function name, because a
# function that exists and returns Ok is the failure this is written for.
find_refusal() {
  local file="$1"
  awk '/fn authorize_read/,/^    }/' "$file" | grep -cE 'GrantRequired' || true
}

# 2. The public-class check refuses protected content.
find_public_refusal() {
  local file="$1"
  awk '/fn check_may_be_public/,/^    }/' "$file" \
    | grep -cE 'ProtectedCannotBePublic' || true
}

# 3. No unbind. Any method that removes a binding reopens the hole.
find_unbind() {
  local file="$1"
  sed -e 's://.*::' "$file" \
    | grep -nE 'bindings\.(remove|clear|retain)|fn (unbind|unprotect|release_content)' \
    || true
}

# 4. The registry actually offers the read authorisation, so the storage side
#    has something to call.
find_registry_entrypoint() {
  local file="$1"
  grep -cE 'pub fn authorize_content_read' "$file" || true
}

# 5. The binding is hashed into the registry root. A permission map outside
#    the root is a map two nodes can disagree about while both accepting the
#    same block.
find_in_root() {
  local file="$1"
  awk '/pub fn root\(/,/^    }/' "$file" | grep -cE 'protected_content' || true
}

# 6. Every RPC endpoint that publishes a shard id asks Pollen first.
#
# Shard ids are the handles a reader fetches bytes with, so an endpoint
# printing them for listed content hands out the content to anyone who skips
# the payment path.
#
# Measured per *endpoint*, not per textual occurrence. An `async fn` that
# reaches a shard id, either directly or through a `_to_json` helper, has to
# contain a `pollen_asset_for_content` call. Counting occurrences instead
# would double-count a guarded endpoint that emits twice, and would demand a
# Pollen lookup inside a pure formatter, which cannot see the manifest.
#
# Returns the names of unguarded endpoints, empty when all are guarded.
find_unguarded_endpoints() {
  local file="$1"
  awk '
    /^    async fn / {
      name=$0; sub(/.*async fn /,"",name); sub(/\(.*/,"",name)
      inbody=1; emits=0; guards=0; depth=0
    }
    inbody {
      if ($0 ~ /"shardId":/ || $0 ~ /_to_json\(&/) emits=1
      if ($0 ~ /pollen_asset_for_content/) guards=1
      if ($0 ~ /^    }$/) {
        if (emits && !guards) print name
        inbody=0
      }
    }
  ' "$file"
}

count_pollen_asks() {
  local file="$1"
  grep -cE 'pollen_asset_for_content' "$file" || true
}

# --------------------------------------------------------------- self test
if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  canaries=0

  # Canary 1: an authorise function that always says yes is caught.
  cat > "$tmp/c1.rs" <<'EOF'
    pub fn authorize_read(&self, id: &ContentId, g: Option<AssetId>) -> Result<(), E> {
        Ok(())
    }
EOF
  [ "$(find_refusal "$tmp/c1.rs")" = "0" ] \
    || fail "canary 1: a fail-open authorize_read was not detected"
  canaries=$((canaries + 1))

  # Canary 2: an honest one passes, so the check is not rejecting everything.
  cat > "$tmp/c2.rs" <<'EOF'
    pub fn authorize_read(&self, id: &ContentId, g: Option<AssetId>) -> Result<(), E> {
        let Some(required) = self.asset_for(id) else { return Ok(()); };
        match g {
            None => Err(ContentGateError::GrantRequired { manifest_id: *id, asset_id: required }),
            Some(_) => Ok(()),
        }
    }
EOF
  [ "$(find_refusal "$tmp/c2.rs")" != "0" ] \
    || fail "canary 2: an honest authorize_read must pass"
  canaries=$((canaries + 1))

  # Canary 3: a public check that never refuses is caught. This is the
  # deduplication leak, and it is the quietest of the three.
  cat > "$tmp/c3.rs" <<'EOF'
    pub fn check_may_be_public(&self, id: &ContentId) -> Result<(), E> {
        Ok(())
    }
EOF
  [ "$(find_public_refusal "$tmp/c3.rs")" = "0" ] \
    || fail "canary 3: a check_may_be_public that never refuses was not detected"
  canaries=$((canaries + 1))

  # Canary 4: an unbind method is caught.
  cat > "$tmp/c4.rs" <<'EOF'
    pub fn unbind(&mut self, id: &ContentId) {
        self.bindings.remove(id);
    }
EOF
  [ -n "$(find_unbind "$tmp/c4.rs")" ] \
    || fail "canary 4: an unbind method was not detected"
  canaries=$((canaries + 1))

  # Canary 5: a retain that quietly drops bindings is caught too, because it
  # is the same hole written a way a grep for "remove" would miss.
  cat > "$tmp/c5.rs" <<'EOF'
    pub fn prune(&mut self, keep: usize) {
        self.bindings.retain(|_, _| keep > 0);
    }
EOF
  [ -n "$(find_unbind "$tmp/c5.rs")" ] \
    || fail "canary 5: a retain that drops bindings was not detected"
  canaries=$((canaries + 1))

  # Canary 6: prose about unbinding must NOT be flagged, or the module's own
  # documentation explaining why there is no unbind would fail the gate.
  cat > "$tmp/c6.rs" <<'EOF'
    // There is no unbind: bindings.remove would let an owner take payment
    // and then release the bytes into the free path.
    pub fn asset_for(&self, id: &ContentId) -> Option<AssetId> { self.bindings.get(id).copied() }
EOF
  [ -z "$(find_unbind "$tmp/c6.rs")" ] \
    || fail "canary 6: prose explaining the absence of unbind must not be flagged"
  canaries=$((canaries + 1))

  # Canary 7: a root that omits the binding map is caught.
  cat > "$tmp/c7.rs" <<'EOF'
    pub fn root(&self) -> [u8; 32] {
        hasher.update(b"offers");
        hasher.finalize().into()
    }
EOF
  [ "$(find_in_root "$tmp/c7.rs")" = "0" ] \
    || fail "canary 7: a root omitting protected_content was not detected"
  canaries=$((canaries + 1))

  # Canary 8: a clean file trips nothing, so no check is matching everything.
  cat > "$tmp/c8.rs" <<'EOF'
    fn helper(x: u64) -> u64 { x + 1 }
EOF
  [ -z "$(find_unbind "$tmp/c8.rs")" ] || fail "canary 8: a clean file must not be flagged"
  canaries=$((canaries + 1))

  # Canary 9: an endpoint printing shard ids with no Pollen check is caught.
  cat > "$tmp/c9.rs" <<'EOF'
    async fn leaky(&self, id: String) -> Result<Value, E> {
        Ok(json!({ "shardId": hex::encode(s.shard_id.0) }))
    }
EOF
  [ -n "$(find_unguarded_endpoints "$tmp/c9.rs")" ] \
    || fail "canary 9: an endpoint publishing shard ids with no Pollen check was not detected"
  canaries=$((canaries + 1))

  # Canary 10: one that does ask must pass, so the rule is not banning shard
  # ids outright. Operators need them for content nobody is selling.
  cat > "$tmp/c10.rs" <<'EOF'
    async fn guarded(&self, id: String) -> Result<Value, E> {
        let protecting_asset = self.chain.pollen_asset_for_content(id).await;
        let shards = if protecting_asset.is_some() { vec![] } else {
            vec![json!({ "shardId": hex::encode(s.shard_id.0) })]
        };
        Ok(json!({ "shards": shards }))
    }
EOF
  [ -z "$(find_unguarded_endpoints "$tmp/c10.rs")" ] \
    || fail "canary 10: a guarded endpoint must pass"
  canaries=$((canaries + 1))

  # Canary 11: an endpoint touching no shard id is not asked to guard.
  cat > "$tmp/c11.rs" <<'EOF'
    async fn unrelated(&self) -> Result<Value, E> {
        Ok(json!({ "height": 1 }))
    }
EOF
  [ -z "$(find_unguarded_endpoints "$tmp/c11.rs")" ] \
    || fail "canary 11: an endpoint with no shard id must not be flagged"
  canaries=$((canaries + 1))

  echo "paid content gate self-test OK: $canaries canaries"
  exit 0
fi

# ------------------------------------------------------------------- gate
[ -f "$GATE_SRC" ] || fail "missing $GATE_SRC"
[ -f "$OFFERS_SRC" ] || fail "missing $OFFERS_SRC"

[ "$(find_refusal "$GATE_SRC")" != "0" ] \
  || fail "authorize_read does not refuse a missing grant: paid content is readable for free"

[ "$(find_public_refusal "$GATE_SRC")" != "0" ] \
  || fail "check_may_be_public does not refuse protected content: paid data would be deduplicated"

unbind="$(find_unbind "$GATE_SRC")"
if [ -n "$unbind" ]; then
  echo "$unbind" >&2
  fail "a binding can be removed: an owner could take payment then free the bytes"
fi

[ "$(find_registry_entrypoint "$OFFERS_SRC")" != "0" ] \
  || fail "MarketplaceRegistry exposes no authorize_content_read for the storage layer to call"

[ "$(find_in_root "$OFFERS_SRC")" != "0" ] \
  || fail "protected_content is not hashed into the registry root"

RPC_SRC="$ROOT/src/rpc/server.rs"
if [ -f "$RPC_SRC" ]; then
  unguarded="$(find_unguarded_endpoints "$RPC_SRC")"
  if [ -n "$unguarded" ]; then
    echo "$unguarded" >&2
    fail "RPC endpoint(s) publish shard ids without asking Pollen: the handles for \
fetching paid bytes are served to anyone"
  fi
fi

echo "OK: paid content needs a live grant, stays out of the public class, and is bound permanently"
