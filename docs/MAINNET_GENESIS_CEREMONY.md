# Mainnet Genesis Ceremony — TR Özet ve Yönlendirme

> **2026-07-16 konsolidasyonu (, kullanıcı kararı Q2):** Tek kanonik
> prosedür **`docs/operations/MAINNET_GENESIS_CEREMONY.md`** dosyasıdır.
> Bu dosya yalnızca TR özet + JSON şablon annex'i taşır; prosedür metni,
> tablolar ve doldurma alanları kanonik belgede yaşar. Güncelleme yaparken
> önce kanonik belgeyi düzenleyin.

**Önceki sürüm:** ARENA5, v1.0 taslak (2026-07-15) — benzersiz içeriği
(validator tabloları, treasury havuzları, ilk-blok kontrolleri, imza tablosu,
bilinçli borçlar) kanonik belgeye taşındı.

---

## 1. Tören tanımı (özet)

Budlum Mainnet Genesis Ceremony, placeholder konfigürasyondan gerçek
production konfigürasyona **şeffaf, doğrulanabilir ve geri dönülemez**
geçişin yapıldığı törendir. Katılımcılar: kullanıcı (ceremony master),
doğrulama ekibi, validator operatörleri (N-of-M). Güvenlik kuralları:
air-gap üretim, HSM (BLS/PQ dışarı çıkmaz), tercihan ≥2 gözlemci.

## 2.  haritası (kanonik belgedeki karşılıklar)

|  | İçerik | Kanonik bölüm |
|-----|--------|---------------|
| Key üretimi (Ed25519 `keygen` CLI — binary'de mevcut) | §2.1 |
| Treasury allocation (5 havuz, 100T BUD) | §3.1 |
| Genesis JSON finalize (`genesis build` + §A şablonu) | §3.1 |
| Hash freeze + PRODUCTION_RUNBOOK'a işleme | §3.2 |
| Bootnode/DNS yayını (fail-closed guard notu) | §3.4, §4, §6 |
| İlk blok (T-0) kontrolleri | §3.6 |
| Minutes + imza tablosu | §3.5 |
| Bilinçli borçlar (M5/M6/M7/M10) | §5.1 |

## 3. Önkoşullar (özet)

- `cargo test --lib` / `clippy -D warnings` / `fmt --check` yeşil.
- M5 raporu (`docs/M5_VERIFYMERKLE_RAPOR_ARENA5.md`) ve  planı
  (`docs/TASK7_CEREMONY_PLAN.md`) okunmuş.
- HSM donanım kararı verilmiş (yoksa Ed25519-only launch, M6 borcu).
- Koordinasyon checklist'i: `docs/TASK7_CEREMONY_BIRLESTIRME_ARENA5_ARENA1.md`.

---

## §A. Genesis JSON şablon annex'i

Elle yazım durumunda doldurulacak tam şablon (tek gerçek şema kaynağı:
`GenesisConfig` serde düzeni; kanonik belge §3.1):

```json
{
  "chain_id": 1,
  "allocations": [
    {"address": "___COMMUNITY_ADDR___", "amount": 10000000000000},
    {"address": "___LIQUIDITY_ADDR___", "amount": 10000000000000},
    {"address": "___ECOSYSTEM_ADDR___", "amount": 20000000000000},
    {"address": "___TEAM_ADDR___", "amount": 20000000000000, "vesting": {"cliff": 52560, "period": 210240}},
    {"address": "___BURN_RESERVE_ADDR___", "amount": 40000000000000}
  ],
  "validators": [
    {"pubkey": "___V1_ED25519___", "bls_pubkey": "___V1_BLS___", "pq_pubkey": "___V1_PQ___", "stake": 1000000, "commission": 500},
    {"pubkey": "___V2_ED25519___", "bls_pubkey": "___V2_BLS___", "pq_pubkey": "___V2_PQ___", "stake": 1000000, "commission": 500},
    {"pubkey": "___V3_ED25519___", "bls_pubkey": "___V3_BLS___", "pq_pubkey": "___V3_PQ___", "stake": 1000000, "commission": 500},
    {"pubkey": "___V4_ED25519___", "bls_pubkey": "___V4_BLS___", "pq_pubkey": "___V4_PQ___", "stake": 1000000, "commission": 500}
  ],
  "block_reward": 50,
  "base_fee": 10,
  "gas_schedule": {
    "base_fee": 10,
    "gas_per_byte": 2,
    "gas_per_signature": 1000,
    "transfer_gas": 21000,
    "stake_gas": 45000,
    "vote_gas": 35000,
    "contract_call_gas": 50000
  },
  "timestamp": ___GENESIS_TIMESTAMP___,
  "bud_tokenomics": {
    "community": 10000000000000,
    "liquidity": 10000000000000,
    "ecosystem": 20000000000000,
    "team": 20000000000000,
    "burn_reserve": 40000000000000,
    "epochs_per_year": 52560,
    "annual_burn_ratio_fixed": 100000,
    "team_cliff_epochs": 52560,
    "team_vesting_epochs": 210240,
    "tx_fee_burn_ratio_fixed": 10000,
    "block_reward": 50,
    "validator_annual_yield_ratio_fixed": 50000,
    "slot_duration_secs": 10,
    "epoch_length_slots": 32
  }
}
```

---

**Force-push YASAK.**
