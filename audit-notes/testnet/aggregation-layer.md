# Testnet Tasarımı: Agregasyon Katmanı ve Özyinelemeli STARK Kanıtları

## 1. Gereksinim
`THE_BUDLUM_AGREGASYON_DIREKTIF.md` uyarınca:
- Binlerce işlemi tek bir blokta toplayıp özyinelemeli (recursive) STARK ile tek bir kanıta indirgeme,
- `Claim::Prog`, gizli m-of-n çoklu imza (multisig), `Account.auth_program_hash`,
- `AggMerge` BudAir, kompakt `AggFoldAir` StarkBackend ve `ShadowAuditor` ile anında teyit,
- `ClaimedDomainFinalityAdapter` ile dış domain kanıtlarının birleştirilmesi.

## 2. Mevcut Durum ve Faz Dağılımı
- **Faz 0**: `Claim` tipleri, blok kuralları, Merkle ağacı, yerel backend (`ed5faed7`).
- **Faz 1**: `Aggregator`, havuz, düğüm entegrasyonu, RPC kapıları (`ed5faed7`).
- **Faz 2**: Referans programlar, Keccak ve ML-DSA NTT STARK çipleri (`b034a9ee`, `PR #192`).
- **Faz 3**: `AggMerge` BudAir, katlama backend'i, `ShadowAuditor` (`PR #193`).
- **Faz 4**: `Claim::Prog`, gizli m-of-n multisig, `ClaimedDomainFinalityAdapter` (`PR #195`).

## 3. İlgili Dosyalar
- `src/aggregation/aggregator.rs`
- `src/aggregation/chain.rs`
- `src/aggregation/claim.rs`
- `src/aggregation/envelope.rs`
- `src/aggregation/frame.rs`
- `src/aggregation/node.rs`
- `src/aggregation/pool.rs`
- `src/aggregation/programs/`
- `src/aggregation/schemes.rs`

## 4. Doğrulama ve Testler
- `cargo test --lib aggregation::`
- `tests/aggregation/`
- `xtask/gates/src/gates/agg_native_backend.rs`
