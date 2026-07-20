# Network Hardening Spec

> **Yazar:** ARENA1, 2026-07-20. **Durum:** Draft.

## 1. Mevcut Ağ Katmanı

- **libp2p** (0.56): gossipsub, identify, ping, kad-dht (yapılandırılmış)
- **Transport:** TCP + QUIC (yapılandırılabilir)
- **Security:** Noise (TLS 1.3 equivalent)
- **Muxing:** Yamux
- **Max message size:** 10MB (`MAX_MESSAGE_SIZE`)
- **Rate limit:** Per-IP token bucket (`peer_rate_limit_per_minute`)

## 2. Node Discovery

### Mevcut
- **Bootstrap peers:** `config/mainnet.toml` bootnodes (ceremony template)
- **DNS seeds:** `MAINNET_DNS_SEEDS` (TXT records)
- **Kademlia DHT:** libp2p kad-dht enabled (peer discovery)

### Eksik
- **DHT routing:** Kademlia aktif ama peer routing verimliliği test edilmedi
- **NAT traversal:** libp2p autorelay + NAT traversal yapılandırılmamış
- **Peer exchange:** gossipsub peer exchange aktif ama optimize değil

## 3. Peer Reputation & Banlama

### Mevcut
- **Score-based:** libp2p gossipsub score (default)
- **Rate limit:** Per-IP token bucket → ban

### Eksik
- **Custom reputation system:** Kötü davranan peer'lar için uygulama seviyesi skor
- **Eclipse protection:** Diversified peer set (bounded connections per IP/ASN)
- **Sybil resistance:** Stake-based peer identity (gelecekte)

## 4. Eclipse Attack Koruması

### Risk
- Düşman, hedef node'un tüm bağlantılarını kendi peer'larıyla doldurursa
  → node sahte chain görür → double-spend

### Öneri
1. **Diversified connections:** Max N connections per IP subnet (/24)
2. **Random eviction:** Periyodik random peer replacement
3. **Outbound diversity:** En az K outbound connection (random peers)
4. **Anchor connections:** Bilinen-good bootstrap peers'a persistent connection

## 5. Gap Analizi

- **NAT traversal:** Test edilmedi (devnet sadece LAN/localhost)
- **DHT:** Aktif ama large-scale test yok
- **Eclipse:** Hiç koruma yok
- **Peer reputation:** libp2p default dışında yok
- **Gossip dedup:** `GossipDedup` modülü var (ekip) — test gerekli

## 6. Önerilen İyileştirmeler (öncelik sırası)

1. **Eclipse protection:** Bounded connections per subnet
2. **NAT traversal:** libp2p autorelay config
3. **Peer reputation:** Custom score (gossipsub + app-level)
4. **DHT optimization:** Republish interval tuning
5. **Gossip mesh:** Fanout parameter optimization

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*


## 7. Implementation notes (ARENA3 H2)

- `src/network/peer_manager.rs`: `max_peers_per_subnet` (default **4**),
  `can_admit_subnet` / `note_connected` / `note_disconnected`.
- `src/network/node.rs`: on `ConnectionEstablished`, reject when /24 full;
  on `ConnectionClosed`, free the slot.
- Unit locks: `peer_manager` tests + `hardening_h2_locks::h5_1_subnet_eclipse_bound`.
