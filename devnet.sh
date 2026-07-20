#!/usr/bin/env bash
# ── devnet.sh — Budlum tek-komut multi-node devnet başlatıcı ────────────────
#
# docker-compose ile 4-node (PoW, difficulty=0) devnet ağını tek komutla
# ayağa kaldırır, sağlık kontrolü yapar, durum/log gösterir ve temizler.
#
# Kullanım:
#   ./devnet.sh up        # ağı başlat + sağlık kontrolü (varsayılan)
#   ./devnet.sh down      # ağı durdur (volume'lar kalır)
#   ./devnet.sh reset     # durdur + volume'ları sil (temiz zincir)
#   ./devnet.sh status    # node/consensus durumu (RPC sorguları)
#   ./devnet.sh health    # liveness: listening + peer sayısı + blok üretimi
#   ./devnet.sh logs [N]  # node logları (varsayılan node1; N=1..4)
#   ./devnet.sh ps        # container durumları
#   ./devnet.sh rpc <method> [params_json]   # ham RPC çağrısı (node1)
#
# Örnek:
#   ./devnet.sh up
#   ./devnet.sh rpc bud_blockNumber
#   ./devnet.sh rpc bud_getBalance '["0x.."]'
#   ./devnet.sh logs 2
#
# Ortam değişkenleri (opsiyonel):
#   RPC_URL   node1 public RPC (varsayılan http://127.0.0.1:8545)
#   METRICS   node1 metrics      (varsayılan http://127.0.0.1:9090/metrics)
#   COMPOSE   compose proje adı  (varsayılan budlum-devnet)
#   WAIT_SECS sağlık kontrolü üst sınırı, sn (varsayılan 120)
#
# CI'daki scripts/devnet-multinode-smoke.sh ile aynı RPC uçlarını kullanır;
# bu script operatör/kullanıcı odaklı sarmalayıcıdır (smoke testi iddia mühürler).

set -u

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
METRICS="${METRICS:-http://127.0.0.1:9090/metrics}"
COMPOSE="${COMPOSE:-budlum-devnet}"
WAIT_SECS="${WAIT_SECS:-120}"

# ── renkler (tty değilse düz metin) ──────────────────────────────────────────
if [ -t 1 ]; then
  B='\033[1m'; G='\033[32m'; R='\033[31m'; Y='\033[33m'; C='\033[36m'; N='\033[0m'
else
  B=''; G=''; R=''; Y=''; C=''; N=''
fi

say()  { printf '%b\n' "${C}[devnet]${N} $*"; }
ok()   { printf '%b\n' "${G}[devnet] ✔${N} $*"; }
warn() { printf '%b\n' "${Y}[devnet] !${N} $*"; }
fail() { printf '%b\n' "${R}[devnet] ✘${N} $*" >&2; exit 1; }

# ── ön koşullar ──────────────────────────────────────────────────────────────
require_docker() {
  command -v docker >/dev/null 2>&1 || fail "docker bulunamadı. Kurulum: https://docs.docker.com/get-docker/"
  if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
  else
    fail "docker compose (v2 plugin) ya da docker-compose bulunamadı."
  fi
  docker info >/dev/null 2>&1 || fail "docker daemon çalışmıyor (docker info başarısız)."
}

# node1 public RPC'sine JSON-RPC çağrısı. Başarısızsa boş döner (set -u uyumlu).
rpc() {
  local method="$1"; local params="${2:-[]}"
  curl -sf --max-time 5 -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
    "$RPC_URL" 2>/dev/null
}

# RPC sonucunun "result" alanını çıkarır (python3 varsa; yoksa ham).
rpc_result() {
  local method="$1"; local params="${2:-[]}"
  local out; out="$(rpc "$method" "$params")"
  [ -z "$out" ] && { echo ""; return; }
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$out" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin)
  r=d.get("result")
  print("" if r is None else (json.dumps(r) if isinstance(r,(dict,list)) else r))
except Exception:
  print("")' 2>/dev/null
  else
    printf '%s' "$out"
  fi
}

# hex string -> decimal (0x.. için). Boş/hatalıysa 0.
hex2dec() {
  local h="$1"
  case "$h" in
    0x*|0X*) printf '%d' "$h" 2>/dev/null || echo 0 ;;
    '' ) echo 0 ;;
    * ) echo "$h" 2>/dev/null || echo 0 ;;
  esac
}

# ── sağlık / liveness ────────────────────────────────────────────────────────
wait_ready() {
  say "RPC hazırlığı bekleniyor: $RPC_URL (maks ${WAIT_SECS} sn)"
  local i=0
  while [ "$i" -lt "$WAIT_SECS" ]; do
    if [ -n "$(rpc bud_netListening)" ]; then
      ok "RPC cevap veriyor."
      return 0
    fi
    sleep 2; i=$((i+2)); printf '.'
  done
  printf '\n'
  return 1
}

health() {
  local listening peers bn1 bn2
  listening="$(rpc_result bud_netListening)"
  peers="$(rpc_result bud_netPeerCount)"; peers="$(hex2dec "$peers")"
  bn1="$(rpc_result bud_blockNumber)"; bn1="$(hex2dec "$bn1")"
  say "blok üretimi doğrulanıyor (5 sn ara ile iki ölçüm)..."
  sleep 5
  bn2="$(rpc_result bud_blockNumber)"; bn2="$(hex2dec "$bn2")"

  printf '%b\n' "${B}── devnet sağlık ──${N}"
  printf '  netListening : %s\n' "${listening:-?}"
  printf '  peerCount    : %s\n' "${peers:-?}"
  printf '  blockNumber  : %s -> %s\n' "$bn1" "$bn2"

  local good=1
  [ "$listening" = "True" ] || [ "$listening" = "true" ] || { warn "netListening true değil"; good=0; }
  [ "${peers:-0}" -ge 1 ] 2>/dev/null || warn "peerCount düşük (<1) — node'lar henüz eşleşmemiş olabilir"
  if [ "${bn2:-0}" -ge "${bn1:-0}" ] 2>/dev/null && [ "${bn2:-0}" -gt 0 ]; then
    ok "konsensus canlı (blok üretiliyor)."
  else
    warn "blok üretimi doğrulanamadı (difficulty/consensus ayarlarını kontrol edin)."
  fi
  # metrics (bilgi amaçlı; başarısızlık ölümcül değil)
  if curl -sf --max-time 3 -o /dev/null "$METRICS"; then
    ok "metrics erişilebilir: $METRICS"
  else
    warn "metrics erişilemedi: $METRICS (opsiyonel)"
  fi
  [ "$good" -eq 1 ] && return 0 || return 1
}

# ── komutlar ─────────────────────────────────────────────────────────────────
cmd_up() {
  require_docker
  say "multi-node devnet başlatılıyor (compose projesi: $COMPOSE)"
  $DC -p "$COMPOSE" up -d --build || fail "docker compose up başarısız"
  ok "container'lar başlatıldı."
  $DC -p "$COMPOSE" ps
  if wait_ready; then
    health || warn "sağlık kontrolü tam yeşil değil (yine de ayakta)."
    printf '\n'
    ok "devnet hazır. RPC: $RPC_URL"
    say "örnek: ./devnet.sh rpc bud_blockNumber   |   ./devnet.sh status   |   ./devnet.sh logs"
    say "block explorer: tarayıcıda explorer/index.html açın (RPC: $RPC_URL)"
  else
    warn "RPC hazır değil; loglara bakın: ./devnet.sh logs"
    return 1
  fi
}

cmd_down() {
  require_docker
  say "devnet durduruluyor (volume'lar korunuyor)..."
  $DC -p "$COMPOSE" down || fail "docker compose down başarısız"
  ok "durduruldu."
}

cmd_reset() {
  require_docker
  say "devnet durduruluyor ve volume'lar siliniyor (temiz zincir)..."
  $DC -p "$COMPOSE" down -v || fail "docker compose down -v başarısız"
  ok "temizlendi (zincir sıfırlandı)."
}

cmd_ps() {
  require_docker
  $DC -p "$COMPOSE" ps
}

cmd_logs() {
  require_docker
  local n="${1:-1}"
  $DC -p "$COMPOSE" logs -f --tail=200 "node${n}"
}

cmd_status() {
  local cid chainid height peers validators
  cid="$(rpc_result bud_chainId)"; chainid="$(hex2dec "$cid")"
  height="$(rpc_result bud_blockNumber)"; height="$(hex2dec "$height")"
  peers="$(rpc_result bud_netPeerCount)"; peers="$(hex2dec "$peers")"
  validators="$(rpc_result bud_getValidatorSet)"
  printf '%b\n' "${B}── Budlum devnet durum ──${N}"
  printf '  RPC         : %s\n' "$RPC_URL"
  printf '  chainId     : %s\n' "${chainid:-?}"
  printf '  blockNumber : %s\n' "${height:-?}"
  printf '  peerCount   : %s\n' "${peers:-?}"
  if [ -n "$validators" ]; then
    printf '  validators  : %s\n' "$validators"
  fi
  # consensus domain'leri (varsa)
  local domains; domains="$(rpc_result bud_getConsensusDomains)"
  [ -n "$domains" ] && printf '  domains     : %s\n' "$domains"
  # global header (settlement katmanı, varsa)
  local gh; gh="$(rpc_result bud_getGlobalHeader)"
  [ -n "$gh" ] && printf '  globalHeader: %s\n' "$gh"
}

cmd_rpc() {
  local method="${1:-}"; shift || true
  local params="${1:-[]}"
  [ -z "$method" ] && fail "kullanım: ./devnet.sh rpc <method> [params_json]"
  local out; out="$(rpc "$method" "$params")"
  if [ -z "$out" ]; then
    fail "RPC çağrısı başarısız/erişilemez: $method ($RPC_URL)"
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$out" | python3 -m json.tool 2>/dev/null || printf '%s\n' "$out"
  else
    printf '%s\n' "$out"
  fi
}

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

# ── giriş ────────────────────────────────────────────────────────────────────
main() {
  local cmd="${1:-up}"; shift || true
  case "$cmd" in
    up)     cmd_up "$@" ;;
    down)   cmd_down "$@" ;;
    reset)  cmd_reset "$@" ;;
    status) cmd_status "$@" ;;
    health) require_docker; wait_ready && health ;;
    ps)     cmd_ps "$@" ;;
    logs)   cmd_logs "$@" ;;
    rpc)    cmd_rpc "$@" ;;
    -h|--help|help) usage ;;
    *) usage; fail "bilinmeyen komut: $cmd" ;;
  esac
}

main "$@"
