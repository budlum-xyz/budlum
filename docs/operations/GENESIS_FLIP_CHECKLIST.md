# Genesis Flip Checklist ( — Ceremony Sonrası Kod Çevirmeleri)

**Amaç:** Mainnet genesis ceremony'si (bkz. `docs/operations/MAINNET_GENESIS_CEREMONY.md`)
tamamlandıktan sonra, **placeholder durumu bilinçli olarak kodlayan** noktaların
tek-tek ve **sıralı** çevrilmesi. Her maddenin yanında kanıt/konnotasyon vardır.

**Kural:** Bu checklist'in hiçbir maddesi ceremony'den ÖNCE uygulanmaz
(placeholder'lar CI ve fail-closed guard'ların test girdisidir). Ceremony'den
sonra ise hiçbir madde açık KALMAZ — açık madde = launch blokörü.

---

## F1 — Genesis JSON + hash freeze

- [ ] **F1.1** `config/mainnet-genesis.json` ceremony çıktılarıyla dolduruldu
      (allocations, validators, timestamp). Yöntem: `budlum-core genesis build`
      veya kanonik belge §A şablonu. Şema kaynağı: `GenesisConfig` serde düzeni.
- [ ] **F1.2** `cargo run --example print_genesis_hash` çıktısı kaydedildi.
- [ ] **F1.3** `sha256sum config/mainnet-genesis.json` →
      `docs/operations/PRODUCTION_RUNBOOK.md` §8.2 tablosuna ve
      `config/mainnet.toml` yorum satırına işlendi. **Bu hash DEĞİŞTİRİLEMEZ.**
- [ ] **F1.4** Genesis dosya yolu `placeholder`/`devnet`/`testnet` İÇERMİYOR —
      CLI Rule 4 (`src/cli/commands.rs:877`) aksi halde boot'u bloklar.

## F2 — Derlenmiş sabitlerin çevrilmesi

- [ ] **F2.1** `src/chain/genesis.rs` → `mainnet_genesis()` placeholder
      vektörleri (tekrarlı-byte adresler) ceremony değerleriyle çevrildi.
      Eşleşme testi `test_mainnet_genesis_json_matches_code` (genesis.rs:424)
      artık gerçek JSON↔kod eşitliğini korumalı — F1.1 ile F2.1 **aynı girdiden**
      üretilmezse bu test düşer (bilinçli çift-kaynak korumasıdır).
- [ ] **F2.2** `src/core/chain_config.rs` `MAINNET_BOOTNODES` ve
      `MAINNET_DNS_SEEDS` gerçek multiaddr/`_dnsaddr` kayıtlarıyla dolduruldu.
      **Q5 guard uyarısı:** `dummy`/`placeholder`/`203.0.113.`/`.example`
      marker'ı taşıyan herhangi bir kayıt kalırsa
      `first_placeholder_peer` () mainnet boot'u CRITICAL exit 1 ile
      bloklar — çevirme TAM olmalı (kısmi çevirme = boot bloklu).
- [ ] **F2.3** `config/mainnet.toml` `[p2p] bootnodes` / `dns_seeds` gerçekleri
      yazıldı; `ceremony_status = "frozen"` olarak çevrildi.

## F3 — Placeholder-kodlayan testlerin çevrilmesi

- [ ] **F3.1** `src/chain/genesis.rs:330` — `assert!(mainnet.validators.is_empty())`
      artık **non-empty** beklemeli (ceremony validator seti).
- [ ] **F3.2** `src/chain/genesis.rs:416-417` — allocations/validators
      `is_empty` assert'leri gerçek sete çevrildi.
- [ ] **F3.3** `src/core/chain_config.rs` Q5 testi
      (`test_placeholder_peer_detection_blocks_dummy_mainnet_entries`):
      MAINNET_BOOTNODES/DNS_SEEDS artık `first_placeholder_peer` döndürmemeli
      (gerçek kayıtlar) — test **negatif kontrolünü yapay dummy listelerle**
      sürdürecek şekilde güncellenir (guard kendisi silinmez; yalnızca
      derlenmiş sabitlerin dummy olduğu varsayımı kalkar).

## F4 — Launch öncesi duman testi (fail-closed doğrulaması)

- [ ] **F4.1** `budlum-core --config config/mainnet.toml --network mainnet`
      boot oluyor: genesis placeholder reddi YOK (F1.1 ✓), peer placeholder
      reddi YOK (F2.2/F2.3 ✓), mDNS reddi YOK (config'te `mdns_enabled = false` ✓).
- [ ] **F4.2** Validator PKCS#11: disk BLS/PQ yok (`validate_mainnet_disk_policy`
      yeşil) veya bilinçli Ed25519-only launch kararı dakikalara işlendi (M6 borcu).
- [ ] **F4.3** `bud_health` + `bud_blockNumber` + `bud_finalizedHeight`
      kanonik belge §3.6 akışıyla gözlendi.
- [ ] **F4.4** `scripts/docker-smoke-mainnet.sh` mainnet yolu (Q12 fallback'e
      düşmeden) yeşil.

## F5 — Kapsam dışı (launch'ta kapalı kalır)

- M5 VerifyMerkle Z-B gate, M6 HSM vendor-native, M7 external audit,
  M10 SocialFi/Hub/Marketplace aktivasyonu — bilinçli borçlar
  (kanonik belge §5.1). Bu checklist bu borçları **kapatmaz**.

---

**Kapanış tanımı:** F1–F4 tüm kutular işaretli + `cargo test --lib` yeşil +
CI 8/8 yeşil + ceremony minutes (N-of-M imzalı) `docs/operations/` altında
(tag'e bağlı) arşivli.

*Yazıldı:  Dalga 5, kullanıcı kararı Q-C(a), 2026-07-16 (ARENA2).*
