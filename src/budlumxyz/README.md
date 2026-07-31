# budlumxyz Registry (modül README'si)

**Modül-ayrımı kuralı gereği budlumxyz'ın kendi README'sidir.**
Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları burada yaşar.

## Durum

- **Olgunluk:** iskelet — kayıt/resolve tipi mevcut, ekonomi/yönetişim mainnet sonrası.
- **Kod konumu:** `src/budlumxyz/` — `mod.rs` (`BudlumxyzRegistry`), `types.rs` (`AppRecord`).
- **Test sayısı:** 0 (yazılım testi yok; davranış `MarketplaceRegistry` deseniyle
  parent test'lerde örtüşüyor).
- **Snapshot:** `StateSnapshotV2.budlumxyz: Option<BudlumxyzRegistry>` (GAP-2 digest'inde).

## Olgunluk uyarıları

- ⚠️ **Mainnet v1 kapsam dışı.** budlumxyz (uygulama registry'si — DeEd/SocialFi/dApp
  listesi)  gereği post-launch. Mainnet'te boş kalır, governance
  activation sonrası.
- ⚠️ **Ekonomi modeli yok.** Listing fee / curation / slashing mainnet sonrası
  tasarım.

## Sıradaki

budlumxyz genişletmesi (mainnet sonrası, kullanıcı emriyle).
