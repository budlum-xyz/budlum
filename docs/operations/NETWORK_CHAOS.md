# Network Chaos —  Extension

**Status:** ADIM 5 — chaos scenario artifacts.
**Purpose:** partition, byzantine, eclipse, sybil smoke/chaos kanıtları.
**Gate:** `scripts/check-network-hardening-gate.sh` — yeni chaos test isimleri.
**Budlumdevnet:** salt-okunur; dokunulmadı.

---

## 1. Giriş

Network hardening gate () unit/invariant testlerini kapsar. Bu belge,
**chaos scenario** testlerini tanımlar: multi-node partition, byzantine, eclipse,
sybil, ban TTL ve disconnect/reconnect long-run soak.

## 2. Chaos senaryoları

| Senaryo | Açıklama | Test adı |
|---|---|---|
| partition | 4-node devnet'te network partition; iki bölünmüş grup ayrı block üretir | `task11_12_chaos_network_partition_isolates_groups` |
| byzantine | 1/3 node sahte blok gönderir; diğerleri reddeder | `task11_12_chaos_byzantine_block_rejected` |
| eclipse | 1 node yalnızca 1 peer'e bağlanır; diğerlerinden izole | `task11_12_chaos_eclipse_single_peer_isolation` |
| sybil | 50 sahte node aynı /24 subnet'ten bağlanır; admission reddedilir | `task11_12_chaos_sybil_subnet_bound_rejects_excess` |
| ban-ttl | Banlanan peer timeout sonra yeniden kabul edilir | `task11_12_chaos_ban_ttl_allows_reconnect_after_expiry` |
| reputation-fuzz | 1000 rastgele mesajla peer score decay | `task11_12_chaos_reputation_fuzz_decay` |

## 3. Devnet chaos smoke

```bash
# 4-node devnet partition testi
docker-compose -f docker-compose.devnet.yml up -d
# node1-2 bir grup, node3-4 başka grup
# partition sonrası her grup kendi bloklarını üretmeli
# partition kaldırıldığında chain merge olmalı
```

## 4. Long-run soak

- 24 saat: 4-node devnet, 1 dakikada 1 partition/reconnect döngüsü.
- Ban TTL: 1000 ban/unban döngüsü.
- Reputation: 10.000 rastgele mesaj, score decay doğrulaması.

## 5. Gate Marker

Bu dosya, `scripts/check-network-hardening-gate.sh` tarafından doğrulanır:

```bash
check_contains "$root/docs/operations/NETWORK_CHAOS.md" "Network Chaos"
check_contains "$root/docs/operations/NETWORK_CHAOS.md" "chaos scenario"
```

---

*Bu dosya, `Network Hardening ()` CI gate'i tarafından doğrulanır.*
