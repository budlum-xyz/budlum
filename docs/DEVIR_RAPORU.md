# Arena devir raporu — Tur 13 / 13.5 sonrası

**Güncelleme:** 2026-07-14  
**Sabit çalışma dalı:** `arena/019f5dd7-budlum`  
**Başlangıç commit'i:** `03c3bf5` (Tur 13)

## Proje kararı

Budlum L1 ile BudZero/BudZKVM artık tek repository'de çalışır. Kanonik yol:

- L1: repository root (`budlum-core`)
- ZK workspace: `budzero/`
- B.U.D.: Tur 14; Tur 13 serisine kod olarak karıştırılmayacak

Eski `lubosruler/BudZero` yalnız tarihsel kaynak kabul edilir. Yeni ajan sibling
checkout veya commit pin'i geri getirmemelidir.

## Tur 13 özeti (devralınan)

- User / developer / enterprise PoA persona config'leri.
- Org roadmap denetimi ve B.U.D. Tur 14 ayrımı.
- BudZero Z-B ilerlemesi; `VerifyMerkle` Production gate **açılmadı** çünkü
  pozitif 64-depth proof hâlâ yeşil değil.

## Tur 13.5 özeti

Ayrıntı: [`TUR13_5_RAPOR.md`](TUR13_5_RAPOR.md).

- BudZero tam kaynak ağacı `budzero/` altına taşındı; CI/Docker tek checkout.
- Gerçek bounded PoW header-chain adapter'ı; legacy declared proof mint-gated.
- Archive fail-closed policy, atomik doğrulanan backup, restore/integrity drill.
- Production/PoA/RPC/HSM runbook'ları.
- Bounded per-IP quota ve operator-only imzasız admin helper'ları.
- Canlı latency histogram wiring.
- BudZero proof time/size baseline bench.

## Değiştirilmemesi gereken güvenlik sınırları

1. PoW/PoS/BFT validator/verifier/relayer katılımına whitelist ekleme. PoA KYC
   registry'si ayrı kalmalı.
2. `pow-confirmation-depth` proof'una bridge mint izni verme.
3. `VerifyMerkle` pozitif 64-depth proof doğrulanmadan Production ISA gate'ini
   açma.
4. Mainnet disk `ValidatorKeys` yasağını BLS/PQ HSM yolu gerçekten gelmeden
   kaldırma.
5. Harici audit yapılmadan README'de “audited/mainnet ready” yazma.
6. B.U.D. storage fazlarını Tur 13.9'a çekme; Tur 14 kararı sabit.

## Sonraki tur: 13.9

1. BLS/PQ anahtar capability/policy ve mümkün HSM abstraction.
2. Prevote/precommit/cert/QC live coordinator son taraması + negatif testler.
3. ConsensusStateV2 staged migration planı ve minimum hook.
4. External audit teslim paketi/checklist; audit tamamlandı iddiası yok.
5. Org Budlum+BudZero roadmap kapanış matrisi; araştırma satırları dürüstçe açık.
6. Bu dosyayı test/CI/commit/PR sonuçlarıyla güncelle.

## Doğrulama komutları

```bash
cargo fmt --all -- --check
cargo clippy --lib --tests -- -D warnings
cargo test --lib
cargo fmt --manifest-path budzero/Cargo.toml --all -- --check
cargo clippy --manifest-path budzero/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --manifest-path budzero/Cargo.toml --workspace
```

Bench (release, süre alır):

```bash
cargo bench --manifest-path budzero/Cargo.toml -p bud-proof --bench proof_baseline
```
