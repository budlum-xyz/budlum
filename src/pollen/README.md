# Pollen — B.U.D. Veri Marketplace (modül README'si)

**Bu dosya, Phase 10 Bölüm 4 modül-ayrımı kuralı gereği Pollen'ın kendi README'sidir.**
Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları burada yaşar.

## Durum

- **Olgunluk:** P0 tipler + ARENA4 ADIM1 Data Rights gate. `DataAsset` ve
  `AccessGrant` primitifleri artık kodda; AI input_ref Pollen/B.U.D. verisine
  işaret ediyorsa grant olmadan reddedilir (strict no-override).
- **Kod konumu:** `src/pollen/` — `mod.rs` (temel tipler: `AssetId`, `Signature64`,
  `GrantId`), `data_rights.rs` (`DataAsset`, `AccessGrant`, `SaleAuthorization`,
  `AiDataInputRef`), `offers.rs` (`MarketplaceRegistry` + geçici `DataOffer`).
- **Test sayısı:** CI summary doğrulamalı; Data Rights regresyonları
  `pollen_ai_data_rights` ve `pollen::data_rights/offers` testlerindedir.
- **İsimlendirme:** 2026-07-18 kullanıcı emriyle `bud_marketplace` → `pollen` rename.

## RFC

- `docs/RFC_ACCESSGRANT_V2_BUD_MARKETPLACE.md` — v2 APPROVED (K1-K6 kullanıcı
  kararları: Address-bağlı grant · değişmez kapsam · ayrı-ödeme · zincir-üstü ReadOnce ·
  tek-buyer · SaleAuthorization). Faz-1 soft-enforcement + Faz-2 HPKE hard-enforcement.

## Olgunluk uyarıları (Bölüm 4 kuralı: toplamın altında kaybolmaz)

- ⚠️ **Faz-1 = protocol admission enforcement.** AI inference request, Pollen
  `AiDataInputRef` taşıyorsa geçerli `AccessGrant` olmadan kabul edilmez.
  Bu güçlü bir on-chain okuma yasağıdır; fakat storage node plaintext görüyorsa
  kriptografik gizlilik garanti etmez. Hard enforcement (HPKE key-wrapping)
  Faz-2'de (HSM/encryption domain'i).
- ✅ **P0/P1 temel tipler mevcut** (`AssetId` JSON-safe, `Signature64`
  sentinel-default, `DataAsset`, `AccessGrant`, `AiDataInputRef`).
  Sıradaki genişleme: HPKE key-wrapping, DAO encryption parametreleri ve
  transaction-backed grant/authorization registration RPC yüzeyi.

## Veri egemenliği

Honest-storage-node varsayımı. Storage node kötü-niyetli olduğunda yalnızca
ekonomik yaptırım (Faz-1). HPKE (Faz-2) → storage node plaintext'i ASLA görmez.

## Sıradaki (P1)

`src/pollen/marketplace.rs` (P1) — RFC §3.2 primitifleri + imza yardımcıları
(RFC §5). P0 main'de (PR #52), P1 ARENA1 aday.
