# Plan (tur 1)

Kontrol listesi. Her satır bir iş paketi; işaretli olan bu turda yapıldı.

## Okunan alanlar
- [x] src/consensus/ (12 dosya, yüzey taraması)
- [x] src/domain/ (17 dosya; finality_adapter.rs satır satır)
- [x] src/settlement/ (global_block.rs V7 başlığı)
- [x] src/cross_domain/evm/ (sync_committee.rs başlık ve güvenlik notları)
- [x] src/cross_domain/external/ (spec.rs sözleşmesi)
- [x] src/registry/permissionless.rs (slash_from_report, MIN_REGISTRATION_STAKE)
- [x] src/light_client/mod.rs, src/bin/budlum-light.rs
- [x] xtask/gates/src/gates/domain_tags.rs, ve kapı gerçekten çalıştırıldı
- [x] docs/CONTRIBUTING.md (kapı düzeni, baseline kuralları)
- [x] .github/workflows/ci.yml (job adları, 33 workflow)
- [x] src/storage/bud3/ (yalnız budlum-stack dalında; replace.rs ve registry.rs oradan okundu)
- [ ] budzero/ (ISA ve AIR; Faz 2)
- [ ] src/network/, src/rpc/ (bu turda yüzey taraması yapılmadı)

## Açık PR'lar (canlı)
- [x] #126 testnet (main <- testnet), 1249 commit, blocked
- [x] #164 Garden (testnet <- garden), 51 commit, blocked
- [x] #183 Budlum (garden <- budlum-stack), 22 commit, blocked
- [x] #188 Aggregation Phase 1 (main <- aggregation-phase1), bu turda açıldı

## İşletim sistemleri
- [x] Ubuntu (bu sandbox: Linux x86_64, 1.98 GB)
- [ ] Ubuntu CI runner
- [ ] macOS (CI)
- [ ] Windows (CI)
- [ ] Alpine/musl (docker-smoke)
- [ ] Android (mobil doğrulayıcı, TLG maddesi)
- [ ] iOS (fırsatçı sınıf)

## Komutlar
- [x] cargo test (harness, 73 geçti)
- [x] cargo clippy --all-targets -- -D warnings
- [x] rustfmt --check
- [x] budlum-gates domain-tags ve --self-test
- [ ] cargo test --lib (tam crate, B-0002)
- [ ] cargo clippy --all-targets --all-features
- [ ] cargo doc -D warnings
- [ ] fuzz, Miri, kani, benchmark
