# Pollen — B.U.D. Veri Marketplace (modül README'si)

**Bu dosya, Phase 10 Bölüm 4 modül-ayrımı kuralı gereği Pollen'ın kendi README'sidir.**
Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları burada yaşar.

## Durum

- **Olgunluk:** iskelet (P0 tipler ship edildi, P1+ primitifler bekliyor).
- **Kod konumu:** `src/pollen/` — `mod.rs` (temel tipler: `AssetId`, `Signature64`,
  `GrantId`), `offers.rs` (`DataOffer` — geçici offer modeli, P1 yerini alacak).
- **Test sayısı:** 8 (`#[test]` sayımı, CI summary doğrulamalı).
- **İsimlendirme:** 2026-07-18 kullanıcı emriyle `bud_marketplace` → `pollen` rename.

## RFC

- `docs/RFC_ACCESSGRANT_V2_BUD_MARKETPLACE.md` — v2 APPROVED (K1-K6 kullanıcı
  kararları: Address-bağlı grant · değişmez kapsam · ayrı-ödeme · zincir-üstü ReadOnce ·
  tek-buyer · SaleAuthorization). Faz-1 soft-enforcement + Faz-2 HPKE hard-enforcement.

## Olgunluk uyarıları (Bölüm 4 kuralı: toplamın altında kaybolmaz)

- ⚠️ **Faz-1 = soft enforcement.** AccessGrant'ın on-chain kontrolü ekonomik
  caydırıcıdır (stake/slashing), **kriptografik garanti DEĞİL**. Storage node ham
  veriyi izinsiz sunabilir. Hard enforcement (HPKE key-wrapping) Faz-2'de (HSM
  domain'i). "İzinsiz erişemez" iddiası Faz-1'de teknik olarak YANLIŞ.
- ⚠️ **P0 tipler mevcut** (`AssetId` JSON-safe, `Signature64` sentinel-default).
  P1 primitifleri (`DataAsset`/`StorageCommitment`/`AccessGrant`/`SaleAuthorization`)
  henüz main'de değil — RFC §10 sırası: P0 → P1 (ARENA1) → P2 snapshot → P3 RPC.

## Veri egemenliği

Honest-storage-node varsayımı. Storage node kötü-niyetli olduğunda yalnızca
ekonomik yaptırım (Faz-1). HPKE (Faz-2) → storage node plaintext'i ASLA görmez.

## Sıradaki (P1)

`src/pollen/marketplace.rs` (P1) — RFC §3.2 primitifleri + imza yardımcıları
(RFC §5). P0 main'de (PR #52), P1 ARENA1 aday.
