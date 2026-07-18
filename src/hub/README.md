# Hub Registry (modül README'si)

**Bu dosya, Phase 10 Bölüm 4 modül-ayrımı kuralı gereği Hub'ın kendi README'sidir.**
Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları burada yaşar.

## Durum

- **Olgunluk:** iskelet — kayıt/resolve tipi mevcut, ekonomi/yönetişim mainnet sonrası.
- **Kod konumu:** `src/hub/` — `mod.rs` (`HubRegistry`), `types.rs` (`AppRecord`).
- **Test sayısı:** 0 (yazılım testi yok; davranış `MarketplaceRegistry` deseniyle
  parent test'lerde örtüşüyor).
- **Snapshot:** `StateSnapshotV2.hub: Option<HubRegistry>` (GAP-2 digest'inde).

## Olgunluk uyarıları (Bölüm 4 kuralı)

- ⚠️ **Mainnet v1 kapsam dışı.** Hub (uygulama registry'si — DeEd/SocialFi/dApp
  listesi) Phase 10 §4.4 gereği post-launch. Mainnet'te boş kalır, governance
  activation sonrası.
- ⚠️ **Ekonomi modeli yok.** Listing fee / curation / slashing mainnet sonrası
  tasarım.

## Sıradaki

Hub genişletmesi (mainnet sonrası, kullanıcı emriyle).
