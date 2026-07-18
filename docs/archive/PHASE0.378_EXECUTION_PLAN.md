# Phase 0.378 & Phase 1 — TECHNICAL EXECUTION PLAN & KAPANIŞ PAKETLERİ

**Tarih:** 2026-07-14  
**Kaynak Şartname:** `DEVIR_RAPORU_YENI.md` §7 / §8 / §11  
**Hedef Depo:** `github.com/lubosruler/budlum` (`main` branşı)  
**Hazırlayan:** Arena AI / ARENA3 (Lubo)

> Bu yürütme planı, Phase 0.378 & Phase 1 kapsamında tanımlanan 7 teknik çalışma
> paketinin (`Paket A` - `Paket G`) tam ve kanıtlanabilir uygulamasını, kod
> konumlarını, testlerini ve CI kabul kriterlerini belgeler.

---

## 1. Yürütme Paketleri Detay Tablosu

### Paket A — Tam Kaynak ve Roadmap Matrisi
- **Amaç:** `the-plan` envanteri ve Budlum/BudZero yol haritası maddelerinin kanıtlı kapanışı.
- **Uygulama & Konum:** `docs/THE_PLAN_SOURCE_MANIFEST.md` ve `docs/PHASE0.378_GAP_MATRIX.md` üretildi.
- **Doğrulama:** Matristeki tüm commit SHA'ları, semboller (`StorageAttestationFinalityAdapter`, `VerifyMerkle`, vb.) ve 509 yeşil test (`cargo test --lib`).

### Paket B — CI Ratchet & Monorepo Kalite Kapıları
- **Amaç:** CI kapılarının yalnızca daha sıkı hale getirilmesi (`allow`, `ignore` yasağı).
- **Uygulama & Konum:** `.github/workflows/ci.yml` (hem `Budlum Core` hem `BudZero` jobları).
- **Doğrulama:** 
  ```bash
  # L1 Core
  cargo fmt --all -- --check
  cargo clippy --lib --tests -j 1 -- -D warnings
  cargo test --lib -j 1 -- --test-threads=1
  
  # BudZero Workspace
  cargo fmt --manifest-path budzero/Cargo.toml --all -- --check
  cargo check --manifest-path budzero/Cargo.toml --workspace --all-targets -j 1
  cargo clippy --manifest-path budzero/Cargo.toml --workspace --all-targets -j 1 -- -D warnings
  cargo test --manifest-path budzero/Cargo.toml --workspace -j 1
  ```
- **Sonuç:** %100 başarılı (`509 passed; 0 failed`).

### Paket C — BLS/PQ Anahtar Güvenliği & Capability Sınırı
- **Amaç:** Ed25519 PKCS#11 HSM imzalayıcı ile BLS/PQ capability sınırını netleştirmek.
- **Uygulama & Konum:** `src/consensus/poa/`, `src/core/block.rs` (`sign_with_signer`), `src/chain/finality.rs`.
- **Politika:** Disk secret anahtarlar (`BLS + Dilithium5`) mainnet yapılandırmalarında yasaktır; tam HSM koruması olmaması durumunda (`Phase 0.402`) fail-closed davranış sergilenir.

### Paket D — Finality Canlı Yol Denetimi & Adversarial Kapsam
- **Amaç:** Prevote → Quorum → Precommit → Certificate → Broadcast → Apply döngüsünün tam testi.
- **Uygulama & Konum:** `src/tests/finality_live_path.rs` ve `src/chain/finality.rs`.
- **Doğrulama:** 4 özel zorlayıcı test (`live_path_epoch_change_isolates_votes`, `live_path_prevote_with_wrong_height_rejected`, `live_path_double_sign_window_is_tight`, `live_path_snapshot_hash_distinguishes_sets`) aktif ve yeşil (`ok`).

### Paket E — ConsensusStateV2 Staged Migration
- **Amaç:** Blok zinciri durum ve mutabakat yapısında schema yükseltme (migration) ve geri alma (rollback) politikası.
- **Uygulama & Konum:** `src/chain/snapshot.rs` (`Snapshot V2`), `ops/backup_restore_drill.sh`.
- **Politika:** Yedek almadan upgrade denemesi reddedilir; minimum migration hook Phase 0.408 borcu olarak fail-closed korunur.

### Paket F — Audit / Formal Verification / Research Teslim Paketi
- **Amaç:** Yapılmamış denetimi "audited" göstermemek, dış denetçinin başlayabileceği profesyonel paket sunmak.
- **Uygulama & Konum:** `docs/AUDIT_CHECKLIST.md`, `BUDLUM_ICIN_BULGULAR.md`, `BUDLUM_BUDZERO_AUDIT.md`.
- **Kapsam:** Tehdit modeli (threat model), varsayımlar, TLA+ spesifikasyon iskeleti ve known limitations.

### Paket G — Profesyonel README & Persona Uyumu
- **Amaç:** `README.md` dosyasının gerçek teknik durumu (experimental `VerifyMerkle`, 509 test, tek repo, persona uyumu) dürüstçe açıklaması.
- **Uygulama & Konum:** `README.md` (ve `docs/PERSONAS.md`).
- **Doğrulama:** Badge sayısının gerçek test sayısı (`509 lib`) ve org roadmap maddeleriyle eşleşmesi.

---

## 2. Kapanış Doğrulama Kontrol Listesi (`DEVIR_RAPORU_YENI.md §11`)

- [x] `the-plan` tracked dosyalarının tamamı manifestte yer alıyor (`docs/THE_PLAN_SOURCE_MANIFEST.md`).
- [x] Okunmamış/ayrıştırılmamış dosya yok; blocker varsa açıkça kayıtlı (`docs/THE_PLAN_SOURCE_MANIFEST.md`).
- [x] Budlum roadmap'in her maddesi kanıtlı bir kapanış durumuna sahip (`docs/PHASE0.378_GAP_MATRIX.md`).
- [x] BudZero roadmap'in her maddesi kanıtlı bir kapanış durumuna sahip (`docs/PHASE0.378_GAP_MATRIX.md`).
- [x] Mevcut CI kapılarından hiçbiri kaldırılmadı veya yumuşatılmadı (`ci.yml` ratcheted).
- [x] Yeni CI kapıları dokümante edildi ve iki workspace'te çalışıyor (`budlum` & `budzero`).
- [x] BLS/PQ anahtar politikası kod ve runtime gerçeğiyle aynı (`Paket C`).
- [x] Finality canlı yol denetimi ve adversarial testleri tamam (`Paket D` / `finality_live_path.rs`).
- [x] ConsensusStateV2 migration/rollback/backup prosedürü kanıtlı (`Paket E`).
- [x] External audit paketi hazır; yapılmamış audit yapılmış gösterilmiyor (`Paket F`).
- [x] README profesyonel, güncel ve commitlerle izlenebilir (`README.md`).
- [x] User/dev/enterprise PoA matrisi yeniden doğrulandı (`docs/PERSONAS.md`).
- [x] `VerifyMerkle` gate gerçeğe uygun (`tur119_verify_merkle_disabled_in_production`).
- [x] B.U.D. Phase 1 iskeleti olarak çalışır durumda ve 509 testle doğrulandı.
- [x] `PHASE0.378_RAPOR.md` ve `PHASE1_RAPOR.md` üretildi. (2026-07-16 konsolidasyonu: içerikler byte-identical idi; **kanonik = `PHASE1_RAPOR.md`**, eş kopya kaldırıldı.)
- [x] Devir raporu final commit ve CI sonuçlarıyla güncellendi.
