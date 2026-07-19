# Fuzzing (Phase 2 §1.7)

> **Durum:** Setup tamamlandı. Uzun fuzz run CI'da çalıştırılmaz; build/check ve
> manuel run harici audit/mainnet hazırlığında kullanılır.

## Fuzz target'leri

| Target | Amaç | Durum |
|--------|------|-------|
| `block_deserialize` | Rastgele bytes → `Block` bincode deserialize panik/DoS kontrolü | ✅ Mevcut |
| `transaction_deserialize` | Rastgele bytes → `Transaction` bincode deserialize panik/DoS kontrolü | ✅ Mevcut |
| `snapshot_deserialize` | `StateSnapshot` + `StateSnapshotV2::from_bytes` parse/migration hook fuzz | ✅ Mevcut |
| `consensus_validate` | Rastgele header alanlarıyla `BlockHeader` serialize güvenliği | ✅ Mevcut |
| `fuzz_blockchain_serialize` | Minimal byte-slice harness; gelecek roundtrip genişletmesi için placeholder | ✅ Mevcut |
| `evm_rlp_decode` | F10.1 RLP decoder: rastgele relayer bytes → canonical decode/error, panic yok | ✅ Mevcut |
| `evm_mpt_verify` | F10.1 MPT verifier: bounded key/proof parçaları → verify/error, panic yok | ✅ Mevcut |

## Çalıştırma

**Önkoşul:** Rust nightly toolchain (sadece fuzzing için).

```bash
rustup install nightly
cargo +nightly install cargo-fuzz

cargo +nightly fuzz run block_deserialize
cargo +nightly fuzz run transaction_deserialize
cargo +nightly fuzz run snapshot_deserialize
cargo +nightly fuzz run consensus_validate
cargo +nightly fuzz run fuzz_blockchain_serialize
cargo +nightly fuzz run evm_rlp_decode
cargo +nightly fuzz run evm_mpt_verify
```

Kısa smoke-run örneği:

```bash
cargo +nightly fuzz run snapshot_deserialize -- -max_total_time=30
cargo +nightly fuzz run evm_rlp_decode -- -max_total_time=300
cargo +nightly fuzz run evm_mpt_verify -- -max_total_time=300
```

## Seed corpus

ZKVM odaklı seed corpus dosyaları `fuzz/corpus/zkvm/` altındadır. EVM target
seedleri `fuzz/corpus/evm_rlp_decode/` ve `fuzz/corpus/evm_mpt_verify/` altında;
bunlar in-tree F10 testlerinin kanonik boş RLP ve boş trie başlangıç girdileridir,
resmî Ethereum fixture paketi değildir. Yeni seed üretimi için:

```bash
./scripts/generate_zkvm_seed_corpus.sh
```

## CI entegrasyonu sınırı

Bu repo için GitHub App token'ında workflow güncelleme yetkisi bulunmadığı
önceki oturumlarda doğrulandı. Bu nedenle Phase 2 §1.7 kapsamında `.github/workflows`
değiştirilmez; fuzz target seti ve scriptler repo içinde teslim edilir. Uzun fuzz
run'lar release/audit öncesi manuel veya ayrı yetkili CI job'ı ile çalıştırılır.

## Kabul kriteri

- [x] `fuzz/Cargo.toml` mevcut.
- [x] `fuzz/fuzz_targets/` içinde 7 target mevcut.
- [x] Target'lar `Cargo.toml` içinde explicit `[[bin]]` olarak kayıtlı.
- [x] F10.1 RLP + MPT panic/DoS target'leri kayıtlı; MPT inputu 64 node ve node başına 128 byte ile bounded.
- [x] Deserialization target'ları panic yerine `Result` tüketir.
- [ ] Yetkili ortamda `cargo +nightly fuzz check` temiz.
- [ ] Uzun fuzz run raporları release öncesi artifact olarak saklanır.

## İlgili

- `scripts/audit-deps.sh` — dependency audit raporu.
- `scripts/generate-sbom.sh` — CycloneDX SBOM üretimi.
- `docs/operations/DEPENDENCY_AUDIT.md` — son dependency audit durumu.
- `docs/operations/SBOM.md` — SBOM üretim prosedürü.


## Phase 11.2 targets (ARENA3)

| Target | Oracle |
|--------|--------|
| `consensus_state_transition` | produce_block + try_reorg panic-freedom / MAX_REORG_DEPTH |
| `relayer_escrow` | bridge lock→mint→burn→unlock + UniversalRelayer proof path |
| `zk_verifier` | ProofEnvelope bincode + DefaultAdapter::verify fail-closed |

Quick CI: 60s × 8 listed targets (see `ci.yml`). Nightly: 4h matrix includes the three new targets.
