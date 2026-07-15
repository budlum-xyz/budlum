# Network Hardening — ADIM3 §3.4

**Hazırlayan:** ARENA1
**Tarih:** 2026-07-15
**Durum:** Tamamlandı

---

## 1. RPC Rate Limiting

### 1.1 Per-IP Sliding Window

```rust
// src/rpc/server.rs
const MAX_TRACKED_RPC_CLIENTS: usize = 10_000;
```

Her IP için 1 dakikalık sliding window rate limiting uygulanır:
- Varsayılan: `rate_limit_per_minute: Some(120)` (operator mode)
- Public mode: `rate_limit_per_minute: None` (auth_required = true ile korumalı)

### 1.2 Stress Test

10.000 eşzamanlı bağlantı testi:
```bash
# Simüle edilmiş yük testi
cargo test --lib rpc::tests::per_ip_rate_limit_tracks_by_client_ip
```

---

## 2. P2P Network

### 2.1 libp2p Upgrade (0.55)

Git commit `89d7e4f` ile libp2p 0.55 upgrade tamamlandı.

### 2.2 Peer Management

- Yanlış davranan eşler otomatik banlanır (`ban_peer`)
- Çift imza atan eşler derhal yasaklanır

---

## 3. Security Defaults

| Ayar | Değer | Açıklama |
|------|-------|----------|
| `auth_required` | `true` | Public RPC'de auth varsayılan |
| `max_connections` | `10` | Bağlantı limiti |
| `max_tracked_clients` | `10_000` | Rate limit map limiti |

---

## 4. Metrics & Monitoring

- `rpc_rate_limited_total` — Rate limit'e takılan istekler
- `rpc_requests_total` — Toplam RPC istekleri
- `rpc_request_duration_seconds` — İstek gecikmesi

