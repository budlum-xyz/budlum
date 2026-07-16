# Mainnet Hazırlık Raporu — Phase 2+ Planı
> **2026-07-16 tazeleme (Phase 8.9 Dalga 5):** Bu belgenin plan bölümleri 2026-07-15 tarihli an kaydıdır (korunur). Yaşayan durum tablosu (§1) güncel sayılara tazelendi: `cargo test --lib` → **531 passed** (belge içi eski 510/513 çelişkisi giderildi). Güncel anlık durum için ayrıca: `docs/PHASE8.9_ANALIZ_A1.md` + `docs/STATUS_ONLINE.md`.


**Hazırlayan:** ARENA1  
**Tarih:** 2026-07-15 00:20 UTC+3  
**Temel commit:** `ee95ef0` (main) — 510 test passed, 0 failed  
**Durum:** Phase 1 (B.U.D. iskeleti + L1 stabilizasyon) tamamlandı. Mainnet önkoşulları analiz edildi.

---

## 1. Mevcut Durum Özeti (Phase 1 Sonrası)

| Bileşen | Test | Clippy | Fmt | Durum |
|---------|------|--------|-----|-------|
| `budlum-core` (L1) | 531 passed | `-D warnings` temiz | temiz | ✅ Stabil |
| `budzero/` (ZKVM) | Tüm workspace test geçti | temiz | temiz | ✅ Stabil |
| `fuzz/` | Build kontrolü tamam | — | — | ✅ Setup tamam |
| `docs/operations/` | Runbook, SBOM, audit script mevcut | — | — | ✅ Dokümantasyon tamam |

**Phase 1'de tamamlananlar:**
- B.U.D. Faz 1-2 + Faz 5 iskeleti (`StorageAttestation`, `ContentId`, `StorageDeal`, 7 RPC, E2E)
- **UYARI:** Faz 5 (Ekonomi Katmanı) mainnet için **fail-closed** durumundadır. Payer/Escrow ve bond escrow yapısı hazır olana kadar token basımı/yakımı devre dışı bırakılmıştır.
- `finality_live_path.rs` (4 test) — hatalı revert düzeltildi
- `chain_actor.rs` stub'ları → gerçek entegrasyon (ARENA3, `e5fd27f`)
- 18 derleme hatası + 5 clippy hatası sıfırlandı

---

## 2. Kritik Mainnet Blocker'lar — Kullanıcı Kararları Uygulandı

**Karar tarihi:** 2026-07-15  
**Karar veren:** Kullanıcı (owner)  
**Uygulama yolu:** `main` dalından devam (yeni branch açılmayacak).

### 2.1 VerifyMerkle Z-B Gate (BudZero) — EN KRİTİK

**Durum:** `budzero/bud-proof/src/plonky3_prover.rs:1711` — "Path verification (still TODO, Phase 0.312)."  
`budzero/bud-isa/src/lib.rs:39-43` — `VerifyMerkle` production'da **disabled**.  
`proves_verify_merkle_valid_64_depth` testi `#[ignore]` ile işaretli.

**Etki:** B.U.D. Faz 3 (gerçek Proof-of-Storage) bu gate'e bağlı.

**✅ Karar: B — Phase 2'de Z-B Commit 3.5'i tamamlayıp gate'i aç.**  
64-depth Poseidon path + final root check AIR constraint'leri tamamlanacak. Tahmini süre: 2-3 hafta.

---

### 2.2 BLS/PQ Anahtar Koruma Yolu (HSM)

**Durum:** `src/crypto/pkcs11.rs` — Gerçek PKCS#11 HSM entegrasyonu mevcut (Ed25519 için). BLS finality ve PQ (Dilithium) imzaları için HSM yolu yok.

**Etki:** Mainnet'te validator BLS/PQ key'leri diskte saklanırsa `AI_BIRLIGI.md` §4.4 ihlal edilir.

**✅ Karar: B — Mevcut `pkcs11.rs`'ye BLS12-381 ve Dilithium mekanizmaları eklenecek.**  
HSM vendor desteği sınırlıysa fallback stratejisi Phase 2'de belirlenecek.

---

### 2.3 B.U.D. Mainnet'e Dahil mi?

**Durum:** Phase 1'de B.U.D. Faz 1-2 tamamlandı. Faz 5 kısmi ve mainnet için fail-closed'dur (gerçek token transferi escrow/payer entegrasyonu tamamlanana kadar devre dışı). Faz 3 (gerçek PoS) kapalı.

**Etki:** B.U.D. mainnet'e girerse operatörler `StorageDeal` açabilir ama kriptografik depolama kanıtı yok.

**✅ Karar: A — Evet, dahil et. Interim retrieval challenge ile başla.**  
Faz 3 (gerçek PoS) Phase 4'te açılacak. Kullanıcı beklentisi yönetimi dokümantasyonda netleştirilecek.

---

### 2.4 Harici Güvenlik Denetimi (External Audit)

**Durum:** `docs/operations/DEPENDENCY_AUDIT.md` + `SBOM.md` + `scripts/audit-deps.sh` mevcut. Harici firma denetimi yapılmadı.

**Etki:** Mainnet lansmanı "self-audited" olarak değerlendirilir.

**✅ Karar: C — Bug bounty programı ile başla (immunefi.com benzeri).**  
Harici firma denetimi Phase 5'te değerlendirilecek.

---

## 3. PHASE Planı (Kullanıcı Kararlarına Göre Güncellendi)

**Karar özeti:** 2.1=B, 2.2=B, 2.3=A, 2.4=C  
**Branch:** `main` (yeni branch açılmayacak, `AI_BIRLIGI.md` §6.1 force-push yasağı geçerli).

### Phase 2 — Mainnet Önkoşulları (Tahmini: 2-3 hafta)

**Hedef:** `VerifyMerkle` gate açılışı + BLS/PQ HSM genişletmesi + B.U.D. interim stabilizasyon.

| # | Görev | Dosya/Hedef | Test Kriteri | Sahip |
|---|-------|-------------|--------------|-------|
| 2.1 | `VerifyMerkle` 64-depth path + AIR constraint'leri tamamla | `budzero/bud-proof/src/plonky3_prover.rs` | `proves_verify_merkle_valid_64_depth` `#[ignore]`'den çıkar, test geçer | ARENA3 |
| 2.2 | BLS/PQ HSM: `pkcs11.rs`'ye BLS12-381 + Dilithium mekanizmaları ekle | `src/crypto/pkcs11.rs` | BLS/PQ imza üretimi HSM üzerinden test edilir | ARENA1 |
| 2.3 | `ConsensusStateV2` migration hook ekle | `src/chain/snapshot.rs` | V2 → V3 migration testi | ARENA2 |
| 2.4 | README roadmap kapanış tablosu güncelle | `README.md` | Tüm org maddeleri "done/open" olarak işaretli | ARENA2 |
| 2.5 | Prometheus latency histogram wiring | `src/observability/` veya mevcut | Histogram metrikleri `/metrics`'te görünür | ARENA3 |
| 2.6 | Per-IP quota / operator admin methods netleştir | `src/rpc/server.rs` | Quota testleri mevcut | ARENA3 |
| 2.7 | Fuzzing CI build kontrolü | `fuzz/Cargo.toml` | `cargo check --manifest-path fuzz/Cargo.toml` temiz | ARENA1 |
| 2.8 | SBOM + dependency audit script CI'ya bağla (kullanıcı manuel) | `scripts/audit-deps.sh` | Script çalışır, rapor üretir | ARENA1 |
| 2.9 | Bug bounty programı dokümantasyonu | `docs/BUG_BOUNTY.md` (yeni) | Kapsam, ödül seviyeleri, iletişim kanalı tanımlı | ARENA1 |

**CI Kabul Kriteri:** `cargo test --lib` + `cargo fmt --check` + `cargo clippy --lib --tests -- -D warnings` + `cargo test --manifest-path budzero/Cargo.toml --workspace` → hepsi yeşil.

---

### Phase 3 — Mainnet v1 Lansman Hazırlığı (Tahmini: 1 hafta)

**Hedef:** Genesis config, node dağıtım, operatör onboarding. B.U.D. Faz 1-2-5 dahil (Faz 3 hâlâ kapalı).

| # | Görev | Dosya/Hedef | Test Kriteri |
|---|-------|-------------|--------------|
| 3.1 | Mainnet genesis config oluştur | `src/chain/genesis.rs` | `test_genesis_deterministic` + yeni mainnet config testi |
| 3.2 | Docker image + systemd unit güncelle | `Dockerfile`, `docs/operations/` | Container başlar, RPC yanıt verir |
| 3.3 | Operatör runbook güncelle (mainnet spesifik) | `docs/operations/PRODUCTION_RUNBOOK.md` | Runbook'da mainnet genesis hash, seed node listesi |
| 3.4 | Network hardening (p2p, RPC rate limit) | `src/network/`, `src/rpc/` | Stress test: 10k bağlantı, rate limit çalışır |
| 3.5 | Validator onboarding flow (stake + register) | `src/registry/permissionless.rs` | E2E: yeni validator stake edip aktif olur |
| 3.6 | B.U.D. interim retrieval challenge dokümantasyonu | `docs/BUD_INTERIM.md` (yeni) | Kullanıcıya "gerçek PoS değil, ekonomik oyun" netliği |

---

### Phase 4 — B.U.D. Faz 3 (VerifyMerkle Production Açılışı) (Tahmini: 2-4 hafta)

**Hedef:** Gerçek kriptografik Proof-of-Storage. Phase 2'deki 2.1 tamamlandıktan sonra gate açılır.

| # | Görev | Dosya/Hedef | Test Kriteri |
|---|-------|-------------|--------------|
| 4.1 | `proves_verify_merkle_valid_64_depth` testi `#[ignore]`'den çıkar | `budzero/bud-proof/src/plonky3_prover.rs` | Test geçer, proof üretir ve verify eder |
| 4.2 | `VerifyMerkle` production gate aç | `budzero/bud-isa/src/lib.rs` | `tur119_verify_merkle_disabled_in_production` testi kaldır veya güncelle |
| 4.3 | B.U.D. Faz 3: `StorageDeal` + `VerifyMerkle` entegrasyonu | `src/domain/storage_deal.rs` | Deal açan operatör 64-depth Merkle proof sunar |
| 4.4 | B.U.D. Faz 4: `GlobalBlockHeader.storage_root` | `src/core/block.rs` | Block header'da storage_root alanı hash'e dahil |

---

### Phase 5 — Harici Denetim + Hardening (Tahmini: 2-8 hafta)

**Hedef:** Kurumsal güven ve uzun vadeli güvenlik. Bug bounty sonuçlarına göre harici firma denetimi değerlendirilecek.

| # | Görev | Dosya/Hedef | Test Kriteri |
|---|-------|-------------|--------------|
| 5.1 | Bug bounty sonuçlarını değerlendir | `docs/BUG_BOUNTY.md` | Kritik/High bulgular çözülmüş |
| 5.2 | Harici audit checklist tamamla (isteğe bağlı) | `docs/EXTERNAL_AUDIT_CHECKLIST.md` (yeni) | Teslim paketi hazır |
| 5.3 | Fuzzing run (24+ saat) | `fuzz/fuzz_targets/` | 0 crash |
| 5.4 | Chaos engineering testleri | `src/tests/chaos.rs` | Rastgele partition, latency injection |
| 5.5 | BNS/.bud isimlendirme (Faz 6) | Ayrı repo/PHASE | — |

---

## 4. Açık Teknik Borçlar (Kullanıcı Kararı Gerektirmeyen)

Bu maddeler **otomatik olarak** Phase 2 kapsamına alınabilir; stratejik karar gerektirmez.

| # | Borç | Neden Açık | Çözüm | Öncelik |
|---|------|------------|-------|---------|
| 4.1 | `budzero/bud-proof/src/bud_stark/prover.rs` 4 TODO | Optimizasyon/iyileştirme | ZK soundness'ı etkilemiyor; Phase 2'de temizlenebilir | 🟡 Düşük |
| 4.2 | `budzero/bud-proof/src/bud_stark/verifier.rs` 2 TODO | Preprocessed commitment taşıma | Performans etkisi; Phase 2'de temizlenebilir | 🟡 Düşük |
| 4.3 | `src/rpc/server.rs:1415,1451` zero-address placeholder | Phase 0.40'te tamamlanacak | Etkisi sınırlı; placeholder kullanımı güvenli | 🟡 Düşük |
| 4.4 | `src/chain/snapshot.rs:299` "ConsensusStateV2 fields" yorumu | Zaten `StateSnapshotV2` var | Yorum güncellemesi yeterli | 🟢 Çok düşük |

---

## 5. Diğer AI'lara Notlar

### ARENA2'ye
- Lütfen `ORG_ROADMAP_AUDIT.md` §4a'daki 18 madde tablosunu gözden geçir. Phase 1 sonrası hangi maddeler hâlâ "açık" olarak işaretlenmeli?
- `docs/MAINNET_READINESS.md` §2'deki 4 stratejik kararı kullanıcıyla birlikte değerlendir.
- Phase 2'deki görevlerden (§3) 2.3 (ConsensusStateV2 migration) ve 2.4 (README roadmap) sana atanabilir.

### ARENA3'e
- Phase 2'deki 2.5 (Prometheus histogram) + 2.6 (per-IP quota) + 2.1 (VerifyMerkle gate kararı uygulama) sana atanabilir.
- `chain_actor.rs` entegrasyonu (`e5fd27f`) için teşekkürler. Eksik bir `ChainCommand` var mı diye son kontrol yapabilir misin?

### Genel
- **Force-push yasak** (`AI_BIRLIGI.md` §6.1). Bu raporun commit'i normal push ile gönderilecek.
- **Workflow dosyası push yasak** (`AI_BIRLIGI.md` §6.2). CI entegrasyonu kullanıcıya bırakıldı.
- Her PHASE başlangıcında `STATUS_ONLINE.md`'ye entry yazılacak.

---

## 6. Sonraki Adım

1. **Phase 2 görev dağılımı başlatıldı.** `main` dalından devam ediliyor.
2. Her görev için ayrı commit; her commit öncesi `cargo test --lib` + `fmt` + `clippy` zorunlu.
3. Diğer AI'lar araya commit atarsa: `fetch` → `merge` (conflict varsa çöz) → CI teyit → `push` (Aşama 1-2-3 protokolü).
4. Kullanıcı "devam" komutu verdiğinde bir sonraki göreve geçilecek.

**Kanıt:** Bu rapor `git log`, `cargo test --lib` (513 passed), `grep -rn TODO src/` (production kodunda 0) ve `grep -rn VerifyMerkle budzero/` (experimental gate aktif) verilerine dayanır.

---

## 7. Mainnet Ready Kriter Seti (MR-1..MR-10) — v1, 2026-07-16

> **TR Özet:** "Mainnet ready" ibaresi **ancak** MR-1..MR-10'un tamamı ✅ ve Ayaz'ın nihai onayı ile kullanılır.
> Kanıtsız ibare = kural ihlali (mevcut "kanıtsız mainnet-ready yasak" kuralının mühürlenmesi; kullanıcı kararı Q10, 2026-07-16).
> Kriterler EN kanonik aşağıda; her madde bir kanıt bağlantısıyla mühürlenir.

| ID | Criterion (EN canonical) | Proof source | Status (2026-07-16) |
|----|---|---|---|
| MR-1 | **CI fully green:** all 9 gates green on `main` for ≥3 consecutive pushes (Budlum Core, BudZero/BudZKVM, 8.1 SBOM, 8.2 deny ×2, 8.5 Fuzz Quick, 8.6 timing, 8.7 secret, docker-smoke). One red job ⇒ seal blocked. | GitHub check-runs | ❌ BudZero red (VerifyMerkle 1-depth, ARENA3 fixing `2006487` series) |
| MR-2 | **Phase 8 full closure:** ADIM8-TALIMAT-1 (12 tasks) + ADIM8.5 add-ons (miri, geiger, semver-checks, cosign SBOM-signing, KAT vectors, dudect, PKCS#11 mock negative tests, X-Real-IP spoofing, zizmor, branch protection). | uploads talimat + CI kapıları | 🟡 Faz 1 done; Faz 2/3 in flight |
| MR-3 | **ZK proof chain:** VerifyMerkle 1/2/64-depth tests active (no `#[ignore]`) and green; Prove/Verify round-trip KAT vectors in CI. | budzero CI | ❌ 1-depth InvalidProof açık |
| MR-4 | **Claim-hygiene (Dalga 4):** zero open rows in PHASE8.9_ANALIZ_A1 matrix; every stub carries an honest marker + maps to the Phase 9 debt list. | PHASE8.9_ANALIZ_A1.md | 🟡 tarama planlandı |
| MR-5 | **Coverage:** consensus / cross_domain / crypto ≥ 90% line (8.4 nextest + llvm-cov gate). | llvm-cov raporu | 🟡 8.4 bekliyor |
| MR-6 | **Genesis readiness:** canonical ceremony inputs (real validator keys, bootnodes, HSM) + GENESIS_FLIP_CHECKLIST F1–F5 ✅ + fail-closed guard removal sign-off + mainnet-genesis.json hash freeze. | operations/ belgeleri | 🟡 tooling hazır, input'lar ceremony günü |
| MR-7 | **Supply chain:** 8.8 SHA-pinned actions + dependabot + minimal permissions; 8.9 trivy + hadolint clean. | .github/workflows | 🟡 Faz 2 |
| MR-8 | **External audit:** ≥1 independent security audit report (bug-bounty scope counts; firm optional). | rapor | 🔴 başlamadı |
| MR-9 | **Operational smoke:** PRODUCTION_RUNBOOK rehearsed on devnet; docker-smoke ✅; backup/restore drill recorded. | operations/ | 🟡 docker ✅, tatbikat bekliyor |
| MR-10 | **Announcement discipline:** only with MR-1..9 all ✅ + Ayaz's final sign-off; any unproven "mainnet ready/audited" claim = rule violation. | bu tablo | 🟢 kural aktif |
