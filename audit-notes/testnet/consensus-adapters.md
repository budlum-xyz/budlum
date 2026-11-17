# Testnet Tasarımı: Konsensüs Adaptörleri ve Evrensel Uzlaşma Katmanı

## 1. Gereksinim
`THE_BUDLUM_DIREKTIF.md` ve `BUDLUM_DIREKTIF.md` uyarınca Budlum, tüm harici ve dahili konsensüs modellerini (Bitcoin PoW, Ethereum PoS Casper/LMD-GHOST, Tendermint BFT, Solana PoH, Chia PoSpace, DAG tabanlı Aleph/Narwhal) tek bir mutlak uzlaşma katmanında (Universal Settlement Layer) doğrulamalı ve kanonik duruma bağlamalıdır.

## 2. Mevcut Durum
- `src/domain/plugin.rs` içerisinde `DomainPlugin` trait'i tanımlıdır.
- `DagDomainPlugin`, `PohDomainPlugin`, `PospaceDomainPlugin` yapıları `ConsensusKind` enum variantları ile kayıtlıdır.
- `src/domain/types.rs` üzerinde variant indeksleri: `AiInference = 5`, `Dag = 6`, `Poh = 7`, `Pospace = 8`.

## 3. Eksikler ve Çözülen Bulgular
- **STRX-194-01**: Bincode discriminant index shift çözüldü.
- **STRX-194-02**: Çoklu ebeveyn sıralama manipülasyonu çözüldü.
- **STRX-194-05**: ZkVerifier `Raw` kanıt kabulü yasaklandı.

## 4. İnşa Adımları
1. **Bitcoin SPV / ZK Light Client Adaptörü**: Blok başlık zincirini (header chain) SHA-256d ile doğrular, zorluk hedefi (difficulty retargeting) ve Merkle inclusion kanıtlarını ZK-STARK devresinde kanıtlar.
2. **Ethereum Sync Committee Adaptörü**: Altair/Bellatrix sync committee BLS12-381 toplu imzalarını doğrular, yürütme kökü (execution state root) kanıtlarını çözer.
3. **Tendermint / IBC Adaptörü**: Ed25519 2/3 stake çoğunluklu commit sertifikalarını ve ICS-23 Merkle kanıtlarını `DomainCommitment` olarak kaydeder.
4. **DAG Adaptörü**: Çoklu ebeveyn hash'lerini kanonik sıralayıp tekilleştirir, kural dışı ebeveynleri fail-closed eler.
5. **PoH Adaptörü**: Bounded tick limiti ile VDF durum geçişlerini doğrular.
6. **PoSpace Adaptörü**: Küresel blok başlığı ve doğrulayıcı adresi ile bağlanan plot kanıtlarını doğrular.

## 5. İlgili Dosyalar
- `src/domain/plugin.rs`
- `src/domain/types.rs`
- `src/consensus/zk_verifier.rs`
- `src/consensus/dag.rs`
- `src/consensus/poh.rs`
- `src/consensus/pospace.rs`
- `src/settlement/domains.rs`

## 6. Doğrulama ve Testler
- `cargo test --lib domain::plugin`
- `cargo test --lib consensus::dag`
- `cargo test --lib consensus::poh`
- `cargo test --lib consensus::pospace`
