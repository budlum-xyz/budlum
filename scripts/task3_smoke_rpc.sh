#!/usr/bin/env bash
# Task 3 §3.2 smoke: start a short-lived node and probe JSON-RPC chain_id.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NETWORK="${SMOKE_NETWORK:-devnet}"
RPC_PORT="${SMOKE_RPC_PORT:-18545}"
DB_PATH="${SMOKE_DB_PATH:-/tmp/budlum-task3-smoke-db}"
BIN="${SMOKE_BIN:-}"

if [[ -z "$BIN" ]]; then
  if [[ -x "$ROOT/target/debug/budlum-core" ]]; then
    BIN="$ROOT/target/debug/budlum-core"
  elif [[ -x "$ROOT/target/release/budlum-core" ]]; then
    BIN="$ROOT/target/release/budlum-core"
  elif docker image inspect budlum-core:smoke-test >/dev/null 2>&1; then
    echo "[smoke] extracting binary from Docker image..."
    _SMOKE_DOCKER_ID=$(docker create budlum-core:smoke-test)
    BIN="/tmp/budlum-smoke-bin"
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

ARGS=(
  --network "$NETWORK"
  --port 0
  --rpc-public-listener "127.0.0.1:${RPC_PORT}"
  --db-path "$DB_PATH/chain"
  --snapshot-dir "$DB_PATH/snapshots"
  --p2p-identity-file "$DB_PATH/secrets/node-id.key"
)

echo "[smoke] starting $BIN ${ARGS[*]}"
"$BIN" "${ARGS[@]}" >"$DB_PATH/node.log" 2>&1 &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
trap cleanup EXIT

for i in $(seq 1 60); do
  if curl -sf -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"bud_chainId","params":[],"id":1}' \
    "http://127.0.0.1:${RPC_PORT}" >/tmp/budlum-smoke-rpc.json 2>/dev/null; then
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

echo "[smoke] RPC response: $(cat /tmp/budlum-smoke-rpc.json)"
grep -q '"result"' /tmp/budlum-smoke-rpc.json
echo "[smoke] OK — bud_chainId responded on ${NETWORK}"
