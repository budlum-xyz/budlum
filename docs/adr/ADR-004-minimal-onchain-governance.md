# ADR-004: Minimal On-Chain Governance

**Durum:** Kabul Edildi
**Tarih:** 2026-07-20
**Karar Verici:** Kullanıcı (onay) —  karar turu q4

## Bağlam
Mimari'de governance hiç geçmedi. Parametre değişikliği (slashing ratios, fees, validator set) nasıl? Tam on-chain governance kompleks + governance attack vektörleri; tam off-chain yavaş.

## Karar
**Minimal on-chain governance:** Sadece güvenlik-kritik parametreler (slash ratios, min stake, fee bounds, liveness parametreleri) on-chain proposal + stake-ağırlıklı vote ile değiştirilebilir. **Kod upgrade'leri (hard fork) off-chain.** Timelock (kabul → N epoch → aktif). Cosmos/Polkadot hibrit modeli.

**Whitelist prensibi:** governance parametre whitelist'ine permissionless core davranışları (registry approval, PoA izolasyonu) ASLA eklenemez.

## Sonuçlar
- **Pozitif:** Yanlış parametre hızlı düzeltilebilir (hard fork gerekmez); stake-ağırlıklı vote sybil'e dirençli; kod upgrade'leri hard fork ile güvenli.
- **Negatif:** Vote manipulation (stake transfer ile vote çalma) test edilmeli; timelock UX'i yavaşlatır.
- **Risk:** Parametre whitelist'ine yanlışlıkla kritik davranış eklenirse sansür vektörü → invariant test (q4) zorunlu.

## Uygunluk
Master-context (permissionless, PoA izolasyonu) — governance'in bunlara dokunmaması invariant'ı.

## İlgili
- `src/core/governance.rs` (genişletme — )
- `docs/BUDLUM_CONSTITUTION.md` (parametre alanları)
- ADR-010 (constitution engine — Pollen parametreleri)
