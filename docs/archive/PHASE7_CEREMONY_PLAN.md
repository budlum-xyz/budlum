# Phase 7 — Mainnet Launch Ceremony Plan

**Hazırlayan:** ARENA5  
**Tarih:** 2026-07-15  
**Branch:** `arena/019f63ce-budlum`  
**HEAD referans:** `origin/main` = `dc3325e`  
**Durum:** Aktif Planlama — Kullanıcı onayı bekleniyor

---

## 1. Phase 7 Hedefi

Budlum L1'in **gerçek mainnet genesis**'ini oluşturmak: placeholder'lardan gerçek
anahtarlara, dummy bootnodes'tan gerçek altyapıya, devnet config'den production
config'e geçiş. Tören (ceremony) formatında, şeffaf ve doğrulanabilir.

## 2. Önkoşul Durumu (Phase 7 Başlangıcı)

| Engelleyici | Durum | Phase 7'ye Etkisi |
|-------------|-------|-----------------|
| M1 Kuyruk drain | ✅ DONE | Engel yok |
| M2 E2E testler | ✅ DONE | Engel yok |
| M3 Ceremony seeds | 🟡 Template var | **Phase 7 görevi** |
| M4 storage_root V3 | ✅ DONE | Engel yok |
| **M5 VerifyMerkle** | 🔒 Kapalı | **Bilinçli kapalı** — `M5_VERIFYMERKLE_RAPOR_ARENA5.md` detay |
| **M6 HSM vendor-native** | 🟡 Config var, donanım yok | Ceremony'ye bağlı |
| **M7 External audit** | ❌ Açık | Bug bounty ile başla (Phase 2 kararı C) |
| M8 BNS Phase 6 | ✅ DONE | Engel yok |
| M9 Archive drill | 🟡 Docs var | Post-launch |
| M10 SocialFi/Hub | 🔒 Revert sonrası | Post-launch |

**ARENA5 kararı (M5 raporu):** M5 kapalı iken launch **yapılabilir** (Seçenek A).
L1 core, bridge, BLS finality, B.U.D. Faz 1-2+5, BNS tamamen bağımsız.

## 3. Phase 7 Görev Detayları

### 3.1 Görev 7.1: Genesis Keys Ceremony 🔴 P0

**Mevcut durum:**
```json
{
  "allocations": [],    // ← BOŞ — gerçek adresler gerekli
  "validators": [],     // ← BOŞ — gerçek validator set gerekli
  "chain_id": 1,        // ← Doğru
  "block_reward": 50,   // ← Tokenomics hazır
  "bud_tokenomics": { ... }  // ← Tam yapılandırılmış
}
```

**Gereksinimler:**

| Alan | Mevcut | Gerekli | Format |
|------|--------|---------|--------|
| `validators` | `[]` | N-of-M validator set (min 4) | `[{pubkey, bls_pubkey, pq_pubkey, stake, commission}]` |
| `allocations` | `[]` | Treasury + Ecosystem + Team + Community + Liquidity + Burn Reserve cüzdanları | `[{address, amount, vesting_schedule?}]` |
| `timestamp` | `0` | Gerçek genesis zamanı (UNIX epoch) | `u64` |
| `chain_id` | `1` | `1` (mainnet) | Değişmez |

**Prosedür:**
1. Kullanıcı gerçek Ed25519 + BLS12-381 + Dilithium5 anahtar çiftlerini üretir
2. Validator set belirlenir (coğrafi dağılım, stake miktarları)
3. Treasury allocation adresleri belirlenir
4. `mainnet-genesis.json` güncellenir
5. Genesis hash hesaplanır → `PRODUCTION_RUNBOOK.md` §8.2'ye yazılır
6. Hash freeze: bir kez yazıldıktan sonra **değiştirilemez**

**ARENA5 sorumluluğu:** Template hazırlama, hash doğrulama scripti, dokümantasyon.
**Kullanıcı sorumluluğu:** Gerçek anahtar üretimi ve dağıtımı.

### 3.2 Görev 7.2: Bootnodes + DNS Seeds 🔴 P0

**Mevcut durum (`config/mainnet.toml`):**
```toml
bootnodes = [
  "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWDummyBootstrap1Placeholder...",  # DUMMY
  "/ip4/203.0.113.11/tcp/4001/p2p/12D3KooWDummyBootstrap2Placeholder...",  # DUMMY
  "/ip4/203.0.113.12/tcp/4001/p2p/12D3KooWDummyBootstrap3Placeholder...",  # DUMMY
]
dns_seeds = [
  "_dnsaddr.dummy-seed-1.mainnet.budlum.example",  # DUMMY
  "_dnsaddr.dummy-seed-2.mainnet.budlum.example",  # DUMMY
]
```

**Gereksinimler:**

| Alan | Mevcut | Gerekli |
|------|--------|---------|
| `bootnodes` | 3 dummy (203.0.113.x = RFC 5737 TEST-NET) | 3+ gerçek multiaddr, coğrafi dağılımlı |
| `dns_seeds` | 2 dummy (.example TLD) | 2+ gerçek DNS seed (DNS TXT record) |
| `identity_file` | `./secrets/mainnet-node-id.key` | Her node için ayrı libp2p identity |

**Prosedür:**
1. 3+ sunucu temin edilir (farklı coğrafi bölgeler: EU, US, AS)
2. Her sunucuda `budlum-core --network mainnet` çalıştırılır
3. `peer_id` ve `multiaddr` kaydedilir
4. `mainnet.toml` `bootnodes` güncellenir
5. DNS `_dnsaddr` TXT record'ları oluşturulur
6. `ceremony_status` → `"frozen"` olarak işaretlenir

### 3.3 Görev 7.3: HSM Vendor-Native Ceremony 🟠 P1

**Mevcut durum:**
- `src/crypto/pkcs11.rs`: Ed25519 PKCS#11 aktif, BLS/PQ vendor mechanism config desteği var (`c92125b`)
- `config/mainnet.toml`: `[validator.signer.pkcs11]` section **commented out**
- `THREAT_MODEL.md` §3.3: Mainnet'te düz metin BLS/PQ anahtarları **yasak** (fail-closed)

**Gereksinimler:**
1. HSM donanım temini (Utimaco, Thales, YubiHSM2 vb.)
2. PKCS#11 module (.so/.dll) kurulumu
3. BLS key label: `BUD_BLS_KEY`, PQ key label: `BUD_PQ_KEY`
4. Vendor-specific mechanism ID (`pkcs11_bls_mechanism`, `pkcs11_pq_mechanism`)
5. Token PIN: `BUDLUM_PKCS11_TOKEN_PIN` env variable

**Prosedür (donanım temin edildiğinde):**
1. HSM cihazına BLS + PQ anahtarları üretilir (HSM içinde, dışarı çıkmaz)
2. `module_path`, `slot_id`, `token_pin_env` yapılandırılır
3. Vendor mechanism ID'ler belirlenir (örn: `0x80000001`)
4. `budlum-core --network mainnet` başlatılır — BLS/PQ sign HSM üzerinden
5. İlk mainnet bloğu HSM-imzalı olarak üretilir

**Kullanıcı notu:** HSM donanımı yoksa, mainnet launch **Ed25519-only validator set** ile başlar; BLS/PQ HSM entegrasyonu post-launch eklenir. `validate_mainnet_disk_policy` BLS/PQ disk anahtarlarını reddeder → HSM olmadan BLS/PQ validator **çalışmaz**. Bu durumda PoA domain ile başlanabilir (Ed25519 yeterli).

### 3.4 Görev 7.4: Genesis Hash Freeze 🟠 P1

**Prosedür:**
1. `mainnet-genesis.json` finalize edilir (7.1 tamamlanınca)
2. `sha256sum config/mainnet-genesis.json` → genesis hash
3. Hash `PRODUCTION_RUNBOOK.md` §8.2'ye yazılır
4. Hash `config/mainnet.toml` comment olarak eklenir
5. Bu hash **asla değişmez** — değişirse farklı bir zincir başlar

**Mevcut referans (`config/mainnet.toml`):**
```
# Genesis block hash (ARENA1 tokenomics mainnet, timestamp=0):
# 9bf07f9f9bda9bf1fba9f12e859e4184dd468c0138cd6327710284629c30df4f
```
**NOT:** Bu hash `allocations=[], validators=[]` ile hesaplanmış. Gerçek keys eklendiğinde hash değişecek.

### 3.5 Görev 7.5: Mainnet Launch Checklist 🔴 P0

**Pre-launch (T-7 gün):**
- [ ] 7.1 Genesis keys ceremony tamamlandı
- [ ] 7.2 Bootnodes çalışıyor (3/3 ping OK)
- [ ] `cargo test --lib` → tüm testler yeşil
- [ ] `cargo clippy -- -D warnings` → temiz
- [ ] `cargo fmt --check` → temiz
- [ ] Snapshot round-trip test geçti (`02dae79` fix doğrulandı)
- [ ] `THREAT_MODEL.md` "VerifyMerkle kapalı" notu güncel
- [ ] `README.md` "30/31 opcode" düzeltmesi yapıldı
- [ ] Bug bounty programı dokümante edildi (`docs/BUG_BOUNTY.md`)

**Launch günü (T-0):**
- [ ] Genesis hash freeze edildi
- [ ] İlk 4 validator node başlatıldı
- [ ] BLS finality ilk prevote/precommit başarılı
- [ ] İlk blok üretildi (block 0 → block 1)
- [ ] RPC endpoint'ler erişilebilir (`bud_health`, `bud_blockNumber`)
- [ ] Prometheus metrics akıyor
- [ ] P2P peer discovery çalışıyor

**Post-launch (T+1 hafta):**
- [ ] Archive node backup drill
- [ ] Incident response runbook testi
- [ ] Bug bounty duyurusu
- [ ] VerifyMerkle 64-depth debug devam (ARENA2/ARENA3)
- [ ] HSM vendor-native aktivasyonu (donanım temin edildiğinde)

## 4. Timeline (Tahmini)

| Faz | Süre | Bağımlılık |
|-----|------|------------|
| 7.1 Genesis keys | Kullanıcıya bağlı (1-7 gün) | Yok |
| 7.2 Bootnodes | Altyapıya bağlı (1-3 gün) | 7.1 |
| 7.3 HSM ceremony | Donanıma bağlı (1-4 hafta) | 7.1 |
| 7.4 Hash freeze | 1 saat | 7.1 |
| 7.5 Launch | 1 gün | 7.1 + 7.2 + 7.4 |

**Minimum launch:** 7.1 + 7.2 + 7.4 (7.3 olmadan PoA/Ed25519 ile)

## 5. Riskler

| Risk | Olasılık | Etki | Azaltma |
|------|----------|------|---------|
| HSM donanım temin edilemez | Orta | Yüksek | Ed25519-only launch, BLS/PQ post-launch |
| VerifyMerkle uzun süre kırmızı | Orta | Orta | M5 kapalı launch (rapor Seçenek A) |
| Genesis keys sızıntısı | Düşük | Kritik | HSM içinde üretim, ceremony air-gap |
| Bootnode sunucu arızası | Düşük | Orta | 3+ coğrafi dağılım, DNS seed fallback |

## 6. Kanıt

- `config/mainnet-genesis.json` → allocations=[], validators=[] (placeholder)
- `config/mainnet.toml` → dummy bootnodes (203.0.113.x), PKCS#11 commented out
- `docs/THREAT_MODEL.md` → §3.2 VerifyMerkle fail-closed, §3.3 disk keys forbidden
- `M5_VERIFYMERKLE_RAPOR_ARENA5.md` → M5 kapalı launch analizi

---

**Force-push YASAK. Workflow push YASAK.**  
Co-authored-by: ARENA5
