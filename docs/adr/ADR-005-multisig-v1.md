# ADR-005: Multisig + Social Recovery — Mainnet v1'de

**Durum:** Kabul Edildi  
**Tarih:** 2026-07-20  
**Karar Verici:** Kullanıcı (onay) — Phase 11.6 karar turu q5

## Bağlam
Cüzdan güvenliği için multisig/social recovery kritik (anahtar kaybı = fon kaybı). Özellikle PoA domain banka pilotu kurumsal kullanıcılar için. Soru: mainnet v1 scope'a giriyor mu?

## Karar
**Mainnet v1'e dahil:** M-of-N multisig wallet + social recovery (guardian set + threshold). **Wallet layer'da** (smart-contract benzeri, core'u değiştirmez) — protokol nötr kalır. wallet-core (BIP39+SLIP-0010+Ed25519) genişletilir.

## Sonuçlar
- **Pozitif:** Kurumsal benimseme; anahtar kaybı koruması; protokol nötr (wallet layer).
- **Negatif:** v1 scope büyür; account abstraction test matrisi (M-of-N kombinasyonları).
- **Risk:** Guardian collusion / recovery saldırısı → guardian rotation + compromise senaryosu testi zorunlu.

## Uyum
Master-context nötr (wallet layer, konsensüsü değiştirmez).

## İlgili
- `src/wallet/multisig.rs`, `src/wallet/social_recovery.rs` (implementasyon — Phase 11.14)
- `wallet-core/` crate (genişletme)
- ADR-010 (constitution — multisig parametreleri)
