#!/usr/bin/env bash
# Docker smoke test for the node image, in two halves that assert two
# different things:
#
# 1. Mainnet refuses. The image carries no mainnet configuration: no
#    bootnodes, no genesis file, no HSM signer. Started with `--network
#    mainnet` it must exit non-zero with a `CRITICAL SECURITY FAILURE` line
#    and never answer RPC. An earlier version of this script polled that
#    container for 60 seconds, then silently fell back to devnet and printed
#    "Mainnet container is operational" over a devnet chain id.
# 2. Devnet boots. The same image started with `--network devnet` must answer
#    `bud_chainId` with the devnet id and serve a genesis block whose hash is
#    the pinned devnet genesis. Any other chain id or hash fails: a fallback
#    that answers is not a pass, it is a different network.
#
# The genesis pin is the devnet genesis built from `devnet_genesis()`; when
# that genesis changes on purpose, the new hash printed below goes into the
# pin in the same change.

set -euo pipefail

IMAGE_NAME="budlum-mainnet-smoke"
MAINNET_CONTAINER="budlum-smoke-mainnet"
DEVNET_CONTAINER="budlum-smoke-devnet"
RPC_PORT="8545"
DEVNET_CHAIN_ID="0xb0ce"
DEVNET_GENESIS_HASH="0xeb63a496fbb3185c2747af36a63e71d813cd5fae625e8dec19b1b293e1a70a81"

RESPONSE="$(mktemp /tmp/budlum-docker-smoke.XXXXXX.json)"

cleanup() {
    local status=$?
    if [[ "$status" -ne 0 ]]; then
        for c in "$MAINNET_CONTAINER" "$DEVNET_CONTAINER"; do
            if docker inspect "$c" >/dev/null 2>&1; then
                echo "[docker-smoke] --- logs of $c ---" >&2
                docker logs --tail 80 "$c" >&2 || true
            fi
        done
    fi
    echo "[docker-smoke] Cleaning up containers..."
    docker rm -f "$MAINNET_CONTAINER" "$DEVNET_CONTAINER" >/dev/null 2>&1 || true
    rm -f "$RESPONSE"
}
trap cleanup EXIT

rpc() {
    curl -sf -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" \
        "http://127.0.0.1:$RPC_PORT" > "$RESPONSE" 2>/dev/null
}

echo "[docker-smoke] Building Docker image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" -f ops/Dockerfile .

# --- 1. mainnet without a configuration must refuse to start -------------
echo "[docker-smoke] Starting $MAINNET_CONTAINER with --network mainnet (must refuse)"
docker run -d --name "$MAINNET_CONTAINER" "$IMAGE_NAME" --network mainnet --port "$RPC_PORT" >/dev/null
MAINNET_EXIT="$(timeout 60 docker wait "$MAINNET_CONTAINER" || echo running)"
if [[ "$MAINNET_EXIT" == "running" ]]; then
    echo "[docker-smoke] ERROR: the mainnet container is still running after 60s; mainnet must refuse to start without bootnodes, a genesis file and an HSM signer." >&2
    exit 1
fi
if [[ "$MAINNET_EXIT" == "0" ]]; then
    echo "[docker-smoke] ERROR: the mainnet container exited 0; a refusal exits non-zero." >&2
    exit 1
fi
# The log is captured once: a `docker logs | grep -q | head` chain under
# pipefail can die of SIGPIPE when the reader stops early, which would turn a
# correct refusal into a script failure.
MAINNET_LOG="$(docker logs "$MAINNET_CONTAINER" 2>&1 || true)"
REFUSAL="$(grep -m1 "CRITICAL SECURITY FAILURE" <<<"$MAINNET_LOG" || true)"
if [[ -z "$REFUSAL" ]]; then
    echo "[docker-smoke] ERROR: the mainnet container exited $MAINNET_EXIT without a CRITICAL SECURITY FAILURE line." >&2
    exit 1
fi
echo "[docker-smoke] OK: mainnet refused to start without a configuration (exit $MAINNET_EXIT):"
echo "[docker-smoke]   $REFUSAL"

# --- 2. devnet must boot and identify itself ----------------------------
echo "[docker-smoke] Starting $DEVNET_CONTAINER with --network devnet"
docker run -d --name "$DEVNET_CONTAINER" -p "127.0.0.1:$RPC_PORT:$RPC_PORT" \
    -e BUDLUM_RPC_AUTH_REQUIRED=0 \
    -e BUDLUM_RPC_ALLOWED_IPS= \
    "$IMAGE_NAME" --network devnet --port 0 --rpc-public-listener "0.0.0.0:$RPC_PORT" >/dev/null

echo "[docker-smoke] Waiting for devnet RPC (max 60s)..."
for i in $(seq 1 60); do
    if rpc bud_chainId '[]'; then
        break
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$DEVNET_CONTAINER" 2>/dev/null)" != "true" ]]; then
        echo "[docker-smoke] ERROR: the devnet container exited before answering RPC." >&2
        exit 1
    fi
    if [[ "$i" -eq 60 ]]; then
        echo "[docker-smoke] ERROR: timeout waiting for the devnet RPC." >&2
        exit 1
    fi
    sleep 1
done

CHAIN_ID="$(jq -r '.result' "$RESPONSE")"
echo "[docker-smoke] Chain ID: $CHAIN_ID"
if [[ "$CHAIN_ID" != "$DEVNET_CHAIN_ID" ]]; then
    echo "[docker-smoke] ERROR: expected the devnet chain id $DEVNET_CHAIN_ID, got $CHAIN_ID." >&2
    exit 1
fi

if ! rpc bud_getBlockByNumber '[0]'; then
    echo "[docker-smoke] ERROR: bud_getBlockByNumber [0] failed." >&2
    exit 1
fi
GENESIS_HASH="$(jq -r '.result.hash' "$RESPONSE")"
GENESIS_NUMBER="$(jq -r '.result.number' "$RESPONSE")"
echo "[docker-smoke] Genesis block $GENESIS_NUMBER hash: $GENESIS_HASH"
if [[ "$GENESIS_NUMBER" != "0x0" ]]; then
    echo "[docker-smoke] ERROR: block 0 reported number $GENESIS_NUMBER." >&2
    exit 1
fi
if [[ "$GENESIS_HASH" != "$DEVNET_GENESIS_HASH" ]]; then
    echo "[docker-smoke] ERROR: expected the pinned devnet genesis $DEVNET_GENESIS_HASH, got $GENESIS_HASH." >&2
    echo "[docker-smoke]        If devnet_genesis() changed on purpose, update DEVNET_GENESIS_HASH in this script in the same change." >&2
    exit 1
fi

echo "[docker-smoke] SUCCESS: the image refuses an unconfigured mainnet and boots devnet ($DEVNET_CHAIN_ID, genesis $DEVNET_GENESIS_HASH)."
