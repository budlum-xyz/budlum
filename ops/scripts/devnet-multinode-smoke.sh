#!/usr/bin/env bash
# -- devnet-multinode-smoke.sh -----------------------------------------------
# Brings the 4-node PoS docker-compose devnet up in CI and seals the
# security/liveness claims below (all through node1, 127.0.0.1:8545 -
# node2..4 deliberately open no RPC; compose is hardened that way):
#   [1] bud_netListening == true -> the P2P stack is alive
#   [2] node1 bud_netPeerCount >= 3 and every follower's own connected-peer
#       gauge >= 1 -> the star that compose dials (node2..4 -> node1) is up,
#       seen from both ends. Follower-to-follower links are not asserted:
#       compose dials only node1, so a mesh between followers would be
#       discovery luck, not a property this file can promise.
#   [3] bud_blockNumber grows across two measurements -> 4-node consensus liveness
#   [4] /metrics (127.0.0.1:9090) HTTP 2xx plus a non-empty body
#   [5] the operator RPC 127.0.0.1:8546 is unreachable from the host (not published, and the node
#       binds only to 127.0.0.1); if it leaks, FAIL.
#   [6] node2's chain height reaches node1's -> a follower really syncs. Steps 1-5 were all
#       measured through node1, which produces the blocks itself; a network whose followers
#       never sync passed them (found 2026-09-02: sync requests were published to gossip,
#       where every receiver drops them). node2 opens no RPC, so its height is read from its
#       own /metrics inside the container.
set -u   # a manual fail instead of -e: the teardown/log step can still run on error

RPC=http://127.0.0.1:8545
METRICS=http://127.0.0.1:9090/metrics
PROJECT=budlum-multinode-smoke

fail() { echo "FAIL: $1"; exit 1; }

rpc() {
  curl -sf --max-time 5 -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":[],\"id\":1}" "$RPC"
}

echo "== [0/6] compose up (4 node + prometheus) =="
# The CI overlay is what turns off RPC auth and publishes 8545. The base file
# stays authenticated so it is safe to copy; the smoke probes need the
# unauthenticated listener, so they ask for it explicitly.
COMPOSE_FILES=(-f ops/docker-compose.yml -f ops/docker-compose.ci.yml)
docker compose "${COMPOSE_FILES[@]}" -p "$PROJECT" up -d || fail "docker compose up"

echo "== [1/6] RPC readiness: bud_netListening (max 120 s) =="
ready=0
for _ in $(seq 1 60); do
  if rpc bud_netListening | grep -q '"result":true'; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || fail "bud_netListening did not become true within 120 s"
echo "PASS [1/6]: bud_netListening=true"

echo "== [2/6] peer connectivity: node1 bud_netPeerCount >= 0x3, node2..4 gauge >= 1 (max 120 s) =="
# The peer count node1 reports over RPC grows only on
# SwarmEvent::ConnectionEstablished, so it measures connections that were
# really established. On its own it proves node1's fanout, nothing about the
# other end: the same three connections are therefore read again from each
# follower's own budlum_p2p_peers_connected gauge, inside the container
# (node2..4 open no RPC). The old "log_nodes" fallback that grepped follower
# logs for 'Connected to' was dropped; a log pattern is not a connection.
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
[ "$ok" = 1 ] || fail "node1 did not reach three peers (bud_netPeerCount=$hex, expected >= 0x3)"
# Each follower, from its own side. The gauge is registered at 0 and set on
# every connection change, so a follower that never connected reads 0.
follower_peers() {
  docker compose "${COMPOSE_FILES[@]}" -p "$PROJECT" exec -T "$1" \
    curl -sf --max-time 4 http://127.0.0.1:9090/metrics 2>/dev/null \
    | awk '$1 == "budlum_p2p_peers_connected" { print int($2); found = 1 } END { if (!found) print -1 }'
}
follower_report=""
for node in node2 node3 node4; do
  peers=-1
  for _ in $(seq 1 30); do
    peers=$(follower_peers "$node")
    [ "$peers" -ge 1 ] && break
    sleep 2
  done
  [ "$peers" -ge 1 ] || fail "$node reports no connected peer (budlum_p2p_peers_connected=$peers; -1: gauge unreadable)"
  follower_report="$follower_report $node=$peers"
done
echo "PASS [2/6]: connectivity (node1 bud_netPeerCount=$hex -> $count peers; follower gauges:$follower_report)"

echo "== [3/6] consensus liveness: bud_blockNumber grows (a max 20 s window) =="
h1=$(rpc bud_blockNumber | python3 -c 'import json,sys;print(int(json.load(sys.stdin)["result"],16))')
inc=0; h2=$h1
for _ in 1 2 3 4; do
  sleep 5
  h2=$(rpc bud_blockNumber | python3 -c 'import json,sys;print(int(json.load(sys.stdin)["result"],16))')
  [ "$h2" -gt "$h1" ] && { inc=1; break; }
done
[ "$inc" = 1 ] || fail "the height is not advancing ($h1 -> $h2)"
echo "PASS [3/6]: liveness ($h1 -> $h2)"

echo "== [4/6] /metrics endpoint =="
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
echo "PASS [4/6]: /metrics 2xx ($(printf '%s' "$body" | wc -l) lines)"

echo "== [5/6] operator RPC isolation (8546 must be closed from the host) =="
if curl -s --max-time 2 http://127.0.0.1:8546 >/dev/null 2>&1; then
  fail "the operator RPC 127.0.0.1:8546 is reachable from the host - LEAK"
fi
echo "PASS [5/6]: the operator RPC is unreachable from the host (connection refused)"

echo "== [6/6] follower sync: node2 budlum_chain_height reaches node1 bud_blockNumber (max 120 s) =="
# node1 produces the blocks, so its height says nothing about whether anyone
# else follows. node2 has no RPC by design; its height is the
# budlum_chain_height gauge on its own metrics listener, read from inside the
# container. Units: bud_blockNumber is the tip index (chain length minus one),
# budlum_chain_height is the chain length; the gauge is converted to a tip
# index before comparing. The bar is "within one block of node1 at the moment
# of reading": node1 keeps producing while the two reads happen, so exact
# equality would race against block production, and a lag of one is what a
# live follower looks like. A follower that cannot sync stays at genesis (or
# wherever it lost the stream) and fails this step.
# The read is two steps so a failure names its cause: -1 means the metrics
# page could not be fetched inside the container (exec or curl failed), -2
# means the page came back without the gauge. A registered gauge is exported
# at 0 before its first write, so a follower still at genesis reads 0 - 1 =
# -1 as a tip index would be ambiguous; the gauge value is printed raw and
# converted below.
node2_metrics_dump=""
node2_parsed_chain_height=-1
node2_chain_height() {
  node2_metrics_dump=$(docker compose "${COMPOSE_FILES[@]}" -p "$PROJECT" exec -T node2 \
    curl -sf --max-time 4 http://127.0.0.1:9090/metrics 2>&1) || { node2_parsed_chain_height=-1; return; }
  node2_parsed_chain_height=$(printf '%s\n' "$node2_metrics_dump" \
    | awk '$1 == "budlum_chain_height" { print int($2); found = 1 } END { if (!found) print -2 }'
  )
}
# Second witness, independent of the metrics listener: the follower logs
# "Added block #N to local chain" for every block it validates. The highest N
# in node2's log is its tip as seen by the node itself.
node2_logged_tip() {
  docker compose "${COMPOSE_FILES[@]}" -p "$PROJECT" logs --no-color --no-log-prefix node2 2>/dev/null \
    | sed -n 's/.*Added block #\([0-9][0-9]*\) to local chain.*/\1/p' \
    | sort -n | tail -1
}
synced=0; n1=0; n2=-1; h2=-1; l2=""
for _ in $(seq 1 60); do
  n1=$(rpc bud_blockNumber | python3 -c 'import json,sys;print(int(json.load(sys.stdin)["result"],16))' 2>/dev/null || echo 0)
  node2_chain_height
  h2=$node2_parsed_chain_height
  l2=$(node2_logged_tip)
  # chain length -> tip index; a length of 0 (never emitted) stays at -1 ("no tip yet").
  if [ "$h2" -ge 1 ]; then n2=$((h2 - 1)); else n2=-1; fi
  # The log witness is used when it is ahead of the gauge (the gauge is
  # written once per block add; the log line is written on the same path).
  if [ -n "$l2" ] && [ "$l2" -gt "$n2" ]; then n2=$l2; fi
  # Lag is bounded in both directions: a follower tip ahead of node1 is a
  # divergent or stale reading, not a synced follower.
  if [ "$n1" -gt 0 ] && [ "$n2" -ge 0 ] && [ "$n2" -le "$n1" ] && [ $((n1 - n2)) -le 1 ]; then synced=1; break; fi
  sleep 2
done
if [ "$synced" != 1 ]; then
  echo "node2 metrics read: raw gauge=$h2 (-1: fetch failed, -2: gauge absent); logged tip=${l2:-none}"
  printf '%s\n' "$node2_metrics_dump" | head -5
  fail "node2 did not catch up with node1 (node1=$n1, node2 tip=$n2)"
fi
echo "PASS [6/6]: follower sync (node1=$n1, node2=$n2)"

echo "DEVNET-MULTINODE-SMOKE: 6/6 PASS"
exit 0
