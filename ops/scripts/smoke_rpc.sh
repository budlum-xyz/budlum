#!/usr/bin/env bash
#  Smoke: start a short-lived node and probe JSON-RPC chain_id.
# Use the operator listener so smoke is independent from public-RPC auth policy
# And allow-list changes; this job validates node boot, not public exposure.
set -euo pipefail
# The script lives in ops/scripts, so the repository root is two levels up;
# one level is `ops`, where there is no target/ and no Cargo.toml to build.
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

NETWORK="${SMOKE_NETWORK:-devnet}"
# Operator listener port. The public listener is pinned to PUBLIC_PORT below;
# the two must never coincide or the second bind fails with EADDRINUSE and the
# probe loop times out. Guard against a caller passing the public port here.
RPC_PORT="${SMOKE_RPC_PORT:-18546}"
PUBLIC_PORT="${SMOKE_PUBLIC_RPC_PORT:-18545}"
if [[ "$RPC_PORT" == "$PUBLIC_PORT" ]]; then
  echo "[smoke] operator port $RPC_PORT equals public port $PUBLIC_PORT; shifting operator to $((PUBLIC_PORT + 1))" >&2
  RPC_PORT="$((PUBLIC_PORT + 1))"
fi
DB_PATH="${SMOKE_DB_PATH:-$(mktemp -d /tmp/budlum-smoke-db.XXXXXX)}"
BIN="${SMOKE_BIN:-}"
# Fixed paths under /tmp follow whatever symlink another user left there;
# mktemp gives this run a file nobody else could have named in advance.
RPC_RESPONSE="$(mktemp /tmp/budlum-smoke-rpc.XXXXXX.json)"

if [[ -z "$BIN" ]]; then
  if [[ -x "$ROOT/target/debug/budlum-core" ]]; then
    BIN="$ROOT/target/debug/budlum-core"
  elif [[ -x "$ROOT/target/release/budlum-core" ]]; then
    BIN="$ROOT/target/release/budlum-core"
  elif docker image inspect budlum-core:devnet >/dev/null 2>&1; then
    # The docker-smoke workflow builds budlum-core:devnet with compose build
    # (the old smoke-test tag was abandoned over a buildx -f problem).
    echo "[smoke] extracting binary from Docker image..."
    _SMOKE_DOCKER_ID=$(docker create budlum-core:devnet)
    BIN="$(mktemp /tmp/budlum-smoke-bin.XXXXXX)"
    docker cp "$_SMOKE_DOCKER_ID:/usr/local/bin/budlum-core" "$BIN"
    docker rm "$_SMOKE_DOCKER_ID" >/dev/null 2>&1
    chmod +x "$BIN"
  elif command -v cargo >/dev/null 2>&1; then
    echo "[smoke] building budlum-core (debug)..."
    cargo build -q --bin budlum-core
    BIN="$ROOT/target/debug/budlum-core"
  else
    echo "[smoke] ERROR: no budlum-core binary and no cargo" >&2
    exit 1
  fi
fi

rm -rf "$DB_PATH"
mkdir -p "$DB_PATH" "$DB_PATH/secrets"
export RUST_LOG="${RUST_LOG:-warn}"
# This smoke test validates node boot via the loopback operator RPC. Keep the
# Public devnet listener unauthenticated unless a caller deliberately overrides
# It, otherwise the secure-by-default public RPC policy prevents the node from
# Reaching the operator listener at all.
export BUDLUM_RPC_AUTH_REQUIRED="${BUDLUM_RPC_AUTH_REQUIRED:-0}"

ARGS=(
  --network "$NETWORK"
  --port 0
  --rpc-public-listener "127.0.0.1:${PUBLIC_PORT}"
  --rpc-operator-listener "127.0.0.1:${RPC_PORT}"
  --db-path "$DB_PATH/chain"
  --snapshot-dir "$DB_PATH/snapshots"
  --p2p-identity-file "$DB_PATH/secrets/node-id.key"
)

echo "[smoke] starting $BIN ${ARGS[*]}"
"$BIN" "${ARGS[@]}" >"$DB_PATH/node.log" 2>&1 &
PID=$!
cleanup() {
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  rm -f "$RPC_RESPONSE"
}
trap cleanup EXIT

for i in $(seq 1 60); do
  if curl -sf -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"bud_chainId","params":[],"id":1}' \
    "http://127.0.0.1:${RPC_PORT}" >"$RPC_RESPONSE" 2>/dev/null; then
    break
  fi
  sleep 0.5
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "[smoke] node exited early; log:" >&2
    tail -n 80 "$DB_PATH/node.log" >&2 || true
    exit 1
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "[smoke] timeout waiting for RPC" >&2
    tail -n 80 "$DB_PATH/node.log" >&2 || true
    exit 1
  fi
done

echo "[smoke] RPC response: $(cat "$RPC_RESPONSE")"
grep -q '"result"' "$RPC_RESPONSE"
echo "[smoke] OK - bud_chainId responded on ${NETWORK}"
