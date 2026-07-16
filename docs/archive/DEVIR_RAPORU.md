# Arena devir raporu — Phase 0.36 / 0.37 sonrası

**Güncelleme:** 2026-07-14  
**Sabit çalışma dalı:** `arena/019f5dd7-budlum`  
**Başlangıç commit'i:** `03c3bf5` (Phase 0.36)

## Proje kararı

Budlum L1 ile BudZero/BudZKVM artık tek repository'de çalışır. Kanonik yol:

- L1: repository root (`budlum-core`)
- ZK workspace: `budzero/`
- B.U.D.: Phase 0.38; Phase 0.36 serisine kod olarak karıştırılmayacak

Eski `lubosruler/BudZero` yalnız tarihsel kaynak kabul edilir. Yeni ajan sibling
checkout veya commit pin'i geri getirmemelidir.

## Phase 0.36 özeti (devralınan)

- User / developer / enterprise PoA persona config'leri.
- Org roadmap denetimi ve B.U.D. Phase 0.38 ayrımı.
- BudZero Z-B ilerlemesi; `VerifyMerkle` Production gate **açılmadı** çünkü
  pozitif 64-depth proof hâlâ yeşil değil.

## Phase 0.37 özeti

Ayrıntı: [`PHASE0.37_RAPOR.md`](PHASE0.37_RAPOR.md).

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
6. B.U.D. storage fazlarını Phase 0.378'a çekme; Phase 0.38 kararı sabit.

## Sonraki tur: 13.9

1. BLS/PQ anahtar capability/policy ve mümkün HSM abstraction.
2. Prevote/precommit/cert/QC live coordinator son taraması + negatif testler.
3. ConsensusStateV2 staged migration planı ve minimum hook.
4. External audit teslim paketi/checklist; audit tamamlandı iddiası yok.
5. Org Budlum+BudZero roadmap kapanış matrisi; araştırma satırları dürüstçe açık.
6. Bu dosyayı test/CI/commit/PR sonuçlarıyla güncelle.

## Phase 0.38 özeti (B.U.D. Faz 1-2 iskeleti)

**Sabit çalışma dalı:** `arena/019f5f77-budlum`  
**PR:** #6 (açık, CI yeşil — `gh pr checks 6` 2026-07-14)  
**Kaynak planlar:** `the-plan/PHASE0.38_PLAN.md`, `the-plan/PHASE0.39_PLAN.md`  
**Kaynak vizyon:** `budlum-xyz/B.U.D./BUD_Merkeziyetsiz_Depolama_Vizyonu.md`
(495 satır, 12 bölüm — Phase 0.38 planı yazılırken vizyon **mevcut değildi**;
Phase 0.40 planı yazılırken vizyon **referans alınmalı**).

**PR #6 kapsamı (gerçek):**

- `ConsensusKind::Storage` enum varyantı → **yok** (HEAD'de sadece
  `PoW/PoS/PoA/Bft/Zk/Custom`).
- `STORAGE_OPERATOR = RoleId(5)` → **yok**.
- `src/storage/content_id.rs` → **yok** (`src/storage/` sadece
  `db.rs, mod.rs, traits.rs`).
- `src/storage/manifest.rs` → **yok**.
- `src/domain/storage_deal.rs` → **yok**.
- `src/tests/bud_e2e.rs` → **yok** (3-aktör E2E + ekip-bağımsızlık
  invariantları yazılmadı).
- `docs/BUD/` dizini → **yok** (`DEALS.md`, `E2E-TEST.md` vb. yazılmadı).

**PR #6 diff:** `docs/ORG_ROADMAP_AUDIT.md` §4a güncellemesinden ibaret
(+152/-9 satır). Kod tabanı değişmedi.

**Vizyonun karar bekleyen noktaları (Phase 0.40 planında netleşmeli):**

- §3 vs §8.1 çelişkisi: `ConsensusKind::Custom("StorageProofOfReplication")`
  (enum'a yeni varyant eklemez) **veya**
  `ConsensusKind::StorageAttestation(StorageDomainParams)` (yeni varyant).
- Faz 1 = muhasebe (kanıt yok), Faz 3 = `VerifyMerkle` Z-B gate'ine bağımlı,
  Faz 4 = `GlobalBlockHeader.storage_root`, Faz 5 = ekonomi, Faz 6 = BNS/.bud.

## Phase 0.39 özeti (mevcut durum)

**Plan:** `the-plan/PHASE0.39_PLAN.md` (mevcut, referans).  
**Kod:** PR'a girmedi (PR #6 sadece audit güncellemesi içeriyor).

Planlanan kapsam (referans, uygulanmamış):

- `ContentManifest` + `ShardRef` (`src/storage/manifest.rs`) — çok-parçalı
  içerik, deterministik manifest üretimi.
- `StorageDeal` + `DealStatus` + `StorageEconomicsParams`
  (`src/domain/storage_deal.rs`) — operatör + shard + bond + fee + epoch.
- `RetrievalChallenge` + `RetrievalResponse` + `ChallengeOutcome` —
  byte-range erişilebilirlik testi (vizyonun "anlık erişilebilirlik"
  seviyesinde, sürekli saklama kanıtı DEĞİL).
- `StorageRegistry` (BTreeMap-backed, permissionless, admin hooksuz).
- 7 yeni RPC (`bud_storageRegisterManifest`, `bud_storageGetManifest`,
  `bud_storageGetDealsByManifest`, `bud_storageGetDealsByShard`,
  `bud_storageOpenChallenge`, `bud_storageAnswerChallenge`,
  `bud_storageGetOutcome`).
- 3-aktör E2E testi (`src/tests/bud_e2e.rs`) + ekip-bağımsızlık
  invariantları (9 test).

## Phase 0.398 özeti (denetim turu)

**Kapsam:** Kod yazılmadı, sadece denetim yapıldı.

**Denetim sonuçları (kanıtlanmış):**

- PR #6 CI yeşil (Budlum Core + BudZero, son run `29343443725`).
- `budlum-xyz/B.U.D.` vizyon dokümanı paylaşılmış (495 satır).
- Phase 0.38 planı vizyon olmadan yazılmış (plan §6'da açıkça belirtilmiş).
- `permissionless.rs` PoA izolasyon testi sağlam (88-104 satırları).
- `budlum.com` URL koda girmedi.
- StorageRegistry admin/pause/freeze/force hook'u yok (çünkü
  Storage kodu yok).

**Açık bulgular (Phase 0.398 kapanışı):**

1. Phase 0.38 (Faz 1-2) Rust implementasyonu PR #6'ya girmedi.
2. Phase 0.38 planı vizyon olmadan yazılmış; Phase 0.40 planı vizyonu referans
   almalı.
3. Vizyon §3 vs §8.1 kararı (Custom mı, yeni varyant mı) Phase 0.40'te
   netleşmeli.
4. Phase 0.378 maddeleri hâlâ açık.
5. PR #6 §4a tablosunda 10 yanlış commit referansı (bu audit'te düzeltildi).
6. `docs/DEVIR_RAPORU.md` Phase 0.38 + 14.5 + 14.9 bölümleri eksikti (bu
   güncelleme ile tamamlandı).

**Sonraki tur önerisi (Phase 0.40):** Phase 0.38'ü sıfırdan başlatmak için
önce iki karar netleşmeli (Custom vs StorageAttestation + Phase 0.378
paralel borç). Vizyon artık referans alınabilir.

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
