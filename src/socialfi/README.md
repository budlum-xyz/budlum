# SocialFi / NFT Registry (modül README'si)

**Bu dosya, Phase 10 Bölüm 4 modül-ayrımı kuralı gereği SocialFi'nin kendi
README'sidir.** Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları
burada yaşar.

## Durum

- **Olgunluk:** canlı (NFT registry + boost ekonomisi).
- **Kod konumu:** `src/socialfi/` — `mod.rs` (`NftRegistry`), `types.rs` (`Nft`).
- **Test sayısı:** parent suite'te (Core test'leri içinde, ayrı modül gate'i YOK).
- **Snapshot:** `StateSnapshotV2.nft_registry: Option<NftRegistry>` (GAP-2 digest).

## Olgunluk uyarıları (Bölüm 4 kuralı)

- ⚠️ **Boost ekonomisi.** NftBoost: `%4 B.U.D. share` operatör havuzuna
  (`distribute_bud_boost_share`, F4 fix). `NftBurn` → storage pruning hook
  (`NodeCommand::StoragePrune`).
- ⚠️ **Mainnet v1 kapsam dışı** (M10 borcu — SocialFi/Hub/Marketplace post-launch).
  Mainnet'te nft_registry boş kalır, governance activation sonrası.
- ⚠️ **NftBoost integer overflow** (SECURITY_AUDIT_HACKER H3) — `saturating_mul`
  ile kapatıldı.

## Sıradaki

SocialFi genişletmesi (mainnet sonrası). Boost ekonomi modeli dokümante.
