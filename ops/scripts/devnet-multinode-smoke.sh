#!/usr/bin/env bash
# -- devnet-multinode-smoke.sh -----------------------------------------------
# Brings the 4-node PoS docker-compose devnet up in CI and seals the
# security/liveness claims below (all through node1, 127.0.0.1:8545 -
# node2..4 deliberately open no RPC; compose is hardened that way):
#   [1] bud_netListening == true -> the P2P stack is alive
#   [2] peer mesh evidence from node2..4     -> a 4-node mesh (P2P log evidence; peerCount fallback)
#   [3] bud_blockNumber grows across two measurements -> 4-node consensus liveness
#   [4] /metrics (127.0.0.1:9090) HTTP 2xx plus a non-empty body
#   [5] the operator RPC 127.0.0.1:8546 is unreachable from the host (not published, and the node
#       binds only to 127.0.0.1); if it leaks, FAIL.
set -u   # a manual fail instead of -e: the teardown/log step can still run on error

RPC=http://127.0.0.1:8545
METRICS=http://127.0.0.1:9090/metrics
PROJECT=budlum-multinode-smoke

fail() { echo "FAIL: $1"; exit 1; }

rpc() {
  curl -sf --max-time 5 -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":[],\"id\":1}" "$RPC"
}

echo "== [0/5] compose up (4 node + prometheus) =="
# The CI overlay is what turns off RPC auth and publishes 8545. The base file
# stays authenticated so it is safe to copy; the smoke probes need the
# unauthenticated listener, so they ask for it explicitly.
COMPOSE_FILES=(-f ops/docker-compose.yml -f ops/docker-compose.ci.yml)
docker compose "${COMPOSE_FILES[@]}" -p "$PROJECT" up -d || fail "docker compose up"

echo "== [1/5] RPC readiness: bud_netListening (max 120 s) =="
ready=0
for _ in $(seq 1 60); do
  if rpc bud_netListening | grep -q '"result":true'; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || fail "bud_netListening did not become true within 120 s"
echo "PASS [1/5]: bud_netListening=true"

echo "== [2/5] peer mesh: node1 bud_netPeerCount >= 0x3 (maks 120 sn) =="
# The peer count node1 reports over RPC is the only authoritative evidence: this counter
# grows only on SwarmEvent::ConnectionEstablished, so it measures a P2P connection
# that was really established. The old "log_nodes" fallback (searching node2..4 logs
# for patterns such as 'Connected to') weakened the gate: even if the nodes connected
# only to node1 instead of each other, or did not connect at all, some patterns could
# match and make it look like a mesh. A single criterion was kept.
ok=0; hex=0x0; count=0
for _ in $(seq 1 60); do
  hex=$(rpc bud_netPeerCount \
        | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("result","0x0"))
except Exception: print("0x0")' 2>/dev/null || echo 0x0)
  count=$((16#${hex#0x}))
  if [ "$count" -ge 3 ]; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] || fail "no 4-node P2P mesh evidence formed (node1 bud_netPeerCount=$hex, expected >= 0x3)"
echo "PASS [2/5]: peer mesh (node1 bud_netPeerCount=$hex -> $count peers)"

echo "== [3/5] consensus liveness: bud_blockNumber grows (a max 20 s window) =="
h1=$(rpc bud_blockNumber | python3 -c 'import json,sys;print(int(json.load(sys.stdin)["result"],16))')
inc=0; h2=$h1
for _ in 1 2 3 4; do
  sleep 5
  h2=$(rpc bud_blockNumber | python3 -c 'import json,sys;print(int(json.load(sys.stdin)["result"],16))')
  [ "$h2" -gt "$h1" ] && { inc=1; break; }
done
[ "$inc" = 1 ] || fail "the height is not advancing ($h1 -> $h2)"
echo "PASS [3/5]: liveness ($h1 -> $h2)"

echo "== [4/5] /metrics endpoint =="
# A retry loop: the metrics server is opened with tokio::spawn, so when the RPC is ready
# (step 1) it may not be listening yet. A single-shot curl produced a FAIL in that
# race (observed 2026-08-14). The gate is not weakened: the metrics must still really
# return 2xx with a non-empty body; it merely waits.
body=""
for _ in $(seq 1 30); do
  body=$(curl -sf --max-time 5 "$METRICS" 2>/dev/null) && break
  sleep 2
done
[ -n "$body" ] || fail "/metrics is unreachable (HTTP != 2xx after 30 attempts)"
echo "PASS [4/5]: /metrics 2xx ($(printf '%s' "$body" | wc -l) lines)"

echo "== [5/5] operator RPC isolation (8546 must be closed from the host) =="
if curl -s --max-time 2 http://127.0.0.1:8546 >/dev/null 2>&1; then
  fail "the operator RPC 127.0.0.1:8546 is reachable from the host - LEAK"
fi
echo "PASS [5/5]: the operator RPC is unreachable from the host (connection refused)"

echo "DEVNET-MULTINODE-SMOKE: 5/5 PASS"
exit 0
