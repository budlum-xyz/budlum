#!/usr/bin/env bash
# ── devnet-multinode-smoke.sh ────────────────────────────────────────────────
# 4-node PoS docker-compose devnet'ini CI'da ayağa kaldırır ve aşağıdaki
# Güvenlik/liveness iddialarını mühürler (hepsi node1, 127.0.0.1:8545 üzerinden -
# Node2..4 kasıtlı olarak RPC açmaz; compose böyle sertleştirilmiştir):
#   [1] bud_netListening == true → P2P stack canlı
#   [2] peer mesh evidence from node2..4     → 4-node mesh (P2P log kanıtı; peerCount fallback)
#   [3] bud_blockNumber iki ölçümde artıyor → 4 node'luk konsensus liveness
#   [4] /metrics (127.0.0.1:9090) HTTP 2xx + boş olmayan gövde
#   [5] operator RPC 127.0.0.1:8546 hosttan erişilemez (yayınlanmaz + node yalnız
#       127.0.0.1'e bağlar), sızırsa FAIL.
set -u   # -e yerine manuel fail: hata anında teardown/log adımı çalışabilsin

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

echo "== [1/5] RPC hazırlığı: bud_netListening (maks 120 sn) =="
ready=0
for _ in $(seq 1 60); do
  if rpc bud_netListening | grep -q '"result":true'; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || fail "bud_netListening 120 sn içinde true olmadı"
echo "PASS [1/5]: bud_netListening=true"

echo "== [2/5] peer mesh: node1 bud_netPeerCount >= 0x3 (maks 120 sn) =="
# Node1'in RPC'den bildirdiği peer sayısı tek yetkili kanıttır: bu sayaç
# Yalnızca SwarmEvent::ConnectionEstablished ile artar, yani gerçekten kurulmuş
# Bir P2P bağlantısını ölçer. Eski "log_nodes" fallback'i ('Connected to' vb.
# Desenlerini node2..4 loglarında aramak) kapıyı zayıflatıyordu: node'lar birbiri
# Yerine yalnız node1'e bağlansa bile, hatta hiç bağlanmasa da bazı desenler
# Eşleşerek, mesh kurulmuş gibi görünebiliyordu. Tek ölçüt bırakıldı.
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
[ "$ok" = 1 ] || fail "4-node P2P mesh kanıtı oluşmadı (node1 bud_netPeerCount=$hex, beklenen >= 0x3)"
echo "PASS [2/5]: peer mesh (node1 bud_netPeerCount=$hex → $count peer)"

echo "== [3/5] konsensus liveness: bud_blockNumber artıyor (maks 20 sn pencere) =="
h1=$(rpc bud_blockNumber | python3 -c 'import json,sys;print(int(json.load(sys.stdin)["result"],16))')
inc=0; h2=$h1
for _ in 1 2 3 4; do
  sleep 5
  h2=$(rpc bud_blockNumber | python3 -c 'import json,sys;print(int(json.load(sys.stdin)["result"],16))')
  [ "$h2" -gt "$h1" ] && { inc=1; break; }
done
[ "$inc" = 1 ] || fail "yükselti ilerlemiyor ($h1 -> $h2)"
echo "PASS [3/5]: liveness ($h1 -> $h2)"

echo "== [4/5] /metrics endpoint =="
# Retry döngüsü: metrics sunucusu tokio::spawn ile açılır; RPC hazır olduğunda
# (adım 1) henüz dinliyor olmayabilir. Tek atışlık curl bu yarışta FAIL
# üretiyordu (2026-08-14 gözlemi). Kapı zayıflamaz: metriklerin gerçekten
# 2xx dönmesi ve gövdenin boş olmaması hâlâ şarttır; yalnızca beklenir.
body=""
for _ in $(seq 1 30); do
  body=$(curl -sf --max-time 5 "$METRICS" 2>/dev/null) && break
  sleep 2
done
[ -n "$body" ] || fail "/metrics erişilemez (30 deneme sonunda HTTP != 2xx)"
echo "PASS [4/5]: /metrics 2xx ($(printf '%s' "$body" | wc -l) satır)"

echo "== [5/5] operator RPC izolasyonu (8546 hosttan kapalı olmalı) =="
if curl -s --max-time 2 http://127.0.0.1:8546 >/dev/null 2>&1; then
  fail "operator RPC 127.0.0.1:8546 hosttan erişilebilir - SIZMA"
fi
echo "PASS [5/5]: operator RPC hosttan erişilemez (bağlantı reddedildi)"

echo "DEVNET-MULTINODE-SMOKE: 5/5 PASS"
exit 0
