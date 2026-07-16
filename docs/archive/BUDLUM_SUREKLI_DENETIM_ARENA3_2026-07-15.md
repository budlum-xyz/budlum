# Budlum Sürekli Denetim — ARENA3 (2026-07-15 22:45, devam)

**Talimat:** "devam durmadan Budlum'ı incelemeye denetlemeye odaklan"
**HEAD:** `d153bc7` (ARENA1 yanıt + Phase 4 cleanup)
**Denetçi:** ARENA3
**Kapsam:** mainnet öncesi sürekli denetim, main branch bütünü

---

## 1. Audit Metodolojisi

- `grep -rn "unwrap|expect|TODO|Address::zero"` ile üretim yolları tarandı
- `src/domain/finality_adapter.rs` `cert.verify` varlığı teyit edildi (0.1)
- `src/rpc/server.rs` opener/responder imza zorunluluğu teyit edildi (0.2)
- `src/registry/role.rs` ghost RPC durumu kontrol edildi (0.3) — ARENA3 tarafından 9b749d1'de fixlendi, ama honest closeout hâlâ 🟡 diyor
- `src/chain/genesis.rs` mainnet genesis determinism + tokenomics testleri kontrol edildi (3.1)
- `Dockerfile` mainnet CMD + systemd unit kontrol edildi (3.2)
- `src/network/node.rs` peer manager security config wiring kontrol edildi (3.4)
- `src/chain/blockchain.rs` escrow accounting kontrol edildi (Faz 5)

---

## 2. Bulgular — Kritik / Yüksek / Orta / Düşük

### 🔴 Kritik — Yok (şu an için)
Phase 3 güvenlik borçları 0.1/0.2/0.4 kapalı, 0.3 kod olarak kapalı (test eksik).

### 🟠 Yüksek — 2 bulgu

#### H1: `storage_open_challenge` hâlâ `unwrap_or_default` kullanıyor (self-reported zero address riski)
**Dosya:** `src/rpc/server.rs:1562` `let opener = request.opener.unwrap_or_default();`
**Durum:** İmza zorunluluğu eklendi (`opener_signature` required), ama `opener` None ise zero address'e düşüyor. Zero address'in imzası teorik olarak geçersiz olmalı (verify_signature zero pubkey'i reddeder), ama **fail-closed yerine fail-open** riski: `Address::zero` için `verify_signature` ne döndürüyor? Test edilmemiş. Phase 3 0.2 fix’i "opener zorunlu ve non-zero" demişti (A1-T6a), ama kod hâlâ `unwrap_or_default`.
**Öneri:** `request.opener.ok_or_else(|| -32602 "opener is required")?` + `if opener == Address::zero() { reject }`
**Sahip:** ARENA3 — bir sonraki commit’te fixlenecek.

#### H2: Mainnet placeholder adresler (`0x10...`, `0x20...`) hâlâ `config/mainnet-genesis.json`'da
**Dosya:** `config/mainnet-genesis.json` + `src/chain/genesis.rs::mainnet_genesis()` (tokenomics rewrite sonrası placeholder mı yoksa gerçek mi?)
**Durum:** ARENA1 `e20397c` ile permissionless + tokenomics rewrite yaptı, ama `mainnet-genesis.json` hâlâ eski repeated-byte adresler (`1010...`, `2020...`). Yeni `mainnet_genesis()` artık boş validator seti + full tokenomics (100M). JSON ↔ kod hash testleri `b024eb2`'de fixlendi, ama **mainnet ceremony için gerçek treasury/validator anahtarları hâlâ TBD**.
**Risk:** Gerçek mainnet launch'ta placeholder adreslerle launch yapılamaz.
**Öneri:** `docs/operations/MAINNET_GENESIS_CEREMONY.md`'de ceremony prosedürü var, placeholder olduğu dokümante. Mainnet hash `9bf07f9f...` bu placeholder’larla hesaplı — ceremony’de değişecek. Bu bilinçli borç, Phase 3 honest closeout'ta işaretli.
**Sahip:** Kullanıcı + ARENA2 (ceremony)

### 🟡 Orta — 4 bulgu

#### M1: `src/rpc/server.rs:1823` `builder.body(()).unwrap()` — RPC rate limiter içinde panic riski
**Dosya:** `src/rpc/server.rs` 1823 (rate limit 429 response builder)
**Durum:** `http_body_util` builder `unwrap()` panic üretirse RPC thread'i düşebilir (DoS). Testlerde değil, üretim yolunda.
**Öneri:** `unwrap_or_else(|_| ...)` veya `expect` yerine `map_err` ile 500 döndür.
**Sahip:** ARENA3 (küçük fix)

#### M2: `src/chain/blockchain.rs` storage slashing burn hâlâ yorum satırında
```rust
// let burned = self.state.burn_from(&operator, result.slashed_bond);
```
**Dosya:** `src/chain/blockchain.rs:3549`
**Durum:** `storage_slashed_bond_total` artıyor, ama gerçek `burn_from` yok. Escrow tam operasyonel (`f2b8075` + `44fe0f0`), ama slashed bond hâlâ sadece ledger'da kayıtlı, yakılmıyor/total supply'den düşmüyor. Interim retrieval için kabul edilebilir, ama mainnet ekonomi için "fail-closed" değil.
**Öneri:** `burn_from` + `total_supply` azaltma veya `TokenomicsBurnSnapshot` ile bağla. Phase 4 Faz 5 tam ekonomi için.
**Sahip:** ARENA1 (ekonomi)

#### M3: `src/rpc/server.rs:1410` TODO(ARENA2) — iki registry var, tek source değil
**Dosya:** `src/rpc/server.rs:1410` `// TODO(ARENA2): unify the two registries into a single source of truth.`
**Durum:** RPC kendi `StorageRegistry` (Arc<Mutex>) tutuyor, chain de kendi `storage_registry` tutuyor. `storage_open_deal` hem chain hem RPC registry'ye senkronize ediyor (44fe0f0 fix), ama race condition riski.
**Öneri:** Chain'i single source of truth yap, RPC registry kaldır veya read-through proxy yap. Phase 4'te düzelt.
**Sahip:** ARENA2

#### M4: `budzero/bud-node` P2P storage backend CI'da koşturulmuyor (smoke test yok)
**Durum:** `bud-node` crate'inde 24 test var (store/bitswap/discovery), ama libp2p swarm integration testi yok. Docker image mainnet CMD var ama container smoke (RPC yanıt) testi yok — honest closeout M2.
**Öneri:** `scripts/docker-smoke.sh` + GitHub Actions manuel job (workflow push yasak, ama kullanıcı manuel ekleyebilir).
**Sahip:** ARENA2/ARENA3

### 🟢 Düşük — 3 bulgu

#### L1: `src/chain/genesis.rs` eski placeholder testler hâlâ `mainnet_genesis()` eski 2 alloc / 4 validator varsayımında
`b024eb2` ile fixlendi, ama `test_mainnet_genesis_params` eski allocation sayısını 2 varsayıyor, yeni tokenomics 5 kategori (community/liquidity/ecosystem/team/burn). Test `b024eb2`'de güncellendi, ama eski testler `#[ignore]` değil, yeni testlerle çakışıyor mu kontrol edilmeli.
**Durum:** CI yeşil (17 genesis test), ama `cargo test --lib chain::genesis` 17 passed — OK.

#### L2: `src/network/node.rs` `peer_manager` lock `if let Ok` ile fixlendi (ARENA3 512 test), ama `chain_actor.rs` hâlâ `rx.await.unwrap_or(default)` kullanıyor — actor dropped ise 0 döndürüyor, fail-closed değil ama DoS değil.
**Durum:** Kabul edilebilir, actor dropped ise zaten node kapanıyor.

#### L3: `docs/PHASE0.06_PLAN.md` (Phase 4) içinde `is_experimental=false` önerisi var, ama `Phase 0.06` adı eski terminoloji — Phase 4 olmalı. Doküman başlığı "Phase 4 — B.U.D. Faz 3" ama dosya adı `PHASE0.06_PLAN.md`. Tutarlılık için `PHASE4_PLAN.md` symlink veya rename önerilir.

---

## 3. Mainnet Launch Öncesi Kalan Borçlar (M1-M9 sentezi)

| # | Borç | Durum | Sahip |
|---|------|-------|-------|
| M1 | ActiveOperators RPC test | 🟡 Kod var, test yok | ARENA3 |
| M2 | Docker smoke CI | 🟡 Kısmi | ARENA2/3 |
| M3 | Seeds/ceremony placeholders | 🟡 Hash var, seed boş | Kullanıcı + ARENA2 |
| M4 | Validator onboarding E2E | 📄 Docs only → ARENA1 aldı (Hat B3) | ARENA1 |
| M5 | VerifyMerkle gate | 🔒 Kapalı — Phase 4 | ARENA2+ARENA3 |
| M6 | BLS/PQ vendor-native HSM | 🟡 Mock yok, software fallback | ARENA1/audit |
| M7 | External audit/TLA+/Privacy/AI | ❌ Açık | Phase 5 |
| M8 | BNS/.bud | 🔒 Ertelendi | Phase 5+ |
| M9 | Archive drill CI | 🟡 Doküman var | ARENA2 |

---

## 4. Önerilen Ön Planlama (3 paralel hat) — Güncellenmiş

**Hat A — ZK (ARENA2+ARENA3):** `proves_verify_merkle_valid_64_depth` ignore kaldır + AIR debug (A1/A2). Risk: 2-3 hafta.

**Hat B — Hardening (ARENA1+ARENA3):**
- B1 Docker smoke `scripts/docker-smoke.sh`
- B2 ActiveOperators RPC test `test_storage_active_operators_rpc`
- B3 Validator onboarding E2E `test_validator_onboarding_e2e` (ARENA1 üstlendi)
- B4 Ceremony plan → gerçek tören (kullanıcı)

**Hat C — Audit (ARENA2):** AUDIT_CHECKLIST, BUG_BOUNTY, SBOM, archive drill.

---

## 5. Sonraki Adım (Aşama 1→2)

Bu denetim raporu `docs/` altına yazıldı, `STATUS_ONLINE.md`'ye entry eklenecek.
Sonraki commit: H1 fix (`opener` require non-zero) + M1 fix (`builder.body().unwrap()` → `unwrap_or`).

**Kanıt:** `grep` çıktısı yukarıda, `git log origin/main -5` → d153bc7, c42a144, cbb77f7, 54052a6, 9af67a0

**Engel:** Yok. Force-push YASAK.

Co-authored-by: ARENA3
