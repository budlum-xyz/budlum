# Budlum —  Yöneticisi Eksiklik Analizi + ARENA2/ARENA3 Talimatları

> **Yazar:** ARENA1 ( yöneticisi, kullanıcı emri 2026-07-18)
> **Temel:** main `5638988` · 824 lib test · CI yeşil
> **Kapsam:**  🔴 bulgularının güncel durum denetimi + ARENA2/3'e
> sahipli, koşul-bağlı, mainnet-prep odaklı iş dağıtımı.
> **Metodoloji:** her talimat net  + kabul kapısı + koordinasyon notu.
> Hiçbir talimat "kullanıcı kararı beklemeden başla" demez — karar kapıları
> belirtilir.

---

## 0. Güncel durum (2026-07-18 20:17 UTC+3)

**Bu oturumda kapananlar:**
- ✅ **Pollen rename** (PR #50 merged) — `bud_marketplace` → `crate::pollen`.
- ✅ **F10.1** (PR #52 merged) — in-tree RLP + MPT verifier (H4 kriptografik temel).
- ✅ **F17** — README governance crate linki eklendi (F17 🔴 → 🟢 closed).
- ✅ **F06 kısmen kapandı** — ARENA2 P5 (ADIM2+5): `request_deadline_blocks`,
  `result_deadline_blocks`, deadline-rejected testleri, equivocation detection,
  fee reclaim (escrow). F06'nın "dispute/timeout" çekirdeği LARGELY solved.
- 🔄 **F10.2 ilerliyor** (ARENA1): `receipt.rs` + `header.rs` yazıldı (workspace
  WIP, commit'siz), `adapter.rs` + `verify_evm_receipt` + test matrisi kaldı.

**Test sayısı:** 824 lib (CI-kanıtlı, badge `37f7615`).

---

## 1. Eksiklik analizi —  🔴'lerin GÜNCEL durumu

| ID | Bulgı | Durum (güncel) | Kalan |
|---|---|---|---|
| **F01** 🔴 | ContentManifest'te `owner` YOK | ❌ **Hâlâ açık** — `src/storage/manifest.rs:50-55` alanlar yalnız `manifest_id/total_size/shard_count/shards`. Teyit: kod-okuma. | Owner backlink (manifest'te mi, ayrı registry'de mi — tasarım kararı) |
| **F02** 🔴 | AccessGrant Gorev-1 = soft-enforcement | ❌ **Açık** — HPKE Gorev-2 bekleyen (RFC §8). Gorev-1 dokümante ama hard enforcement mainnet-engeli olarak işaretlenmedi. | MR-benzeri kriter önerisi |
| **F06** 🔴 | AI dispute/timeout/slashing YOK | 🟡 **Largely closed** (ARENA2 P5) — deadline + equivocation + fee reclaim var. Kalan: disagreement "no-consensus outcome" + canlılık edge-case'leri. | Edge-case test matrisi |
| **F10** 🔴 | Universal Relayer gerçek adapter YOK | 🔄 **İlerliyor** (ARENA1) — F10.1 (RLP+MPT) merged; F10.2 (receipt+header+adapter) WIP. | F10.2-F10.5 |
| **F17** 🔴 | Governance README iddiası kodda yok | ✅ **Closed** — `src/core/governance.rs` MEVCUT + README crate linki eklendi. | — |
| **F27** 🔴 | Ceremony keys/bootnodes boş | ❌ **Açık** — MR-6 blocker. Ceremony playbook gerek. | MAINNET_GENESIS_CEREMONY.md'ye MPC key-gen + witness + imha |
| **F29** 🔴 | External audit başlamadı | ❌ **Açık** — MR-8. BUG_BOUNTY.md YOK. | BUG_BOUNTY.md + firm seçimi |

**Netice:** 6 🔴'den **2 closed** (F17), **1 largely closed** (F06), **1 ilerliyor** (F10),
**3 hâlâ açık** (F01, F27, F29). Açık PR triyajı (8 dependabot + #49/#51 WIP) de bekliyor.

---

## 2. ARENA2 talimatları (chain/snapshot/rpc/AI-inference domain)

> ARENA2 domain'i: `src/chain/`, `src/execution/`, `src/rpc/`, `src/ai/`,
> snapshot (`src/chain/snapshot.rs`), BudZKVM host-call. AI Inference layer
> (Bölüm 1) ana sahibi.

### ARENA2-T1: F06 edge-case test matrisi (F06'ı 🔴→✅ kapatma)
**:** P5 (deadline/equivocation/fee reclaim) üstüne **edge-case negatif
matris** ekle: (a) deadline tam sınır-block'ta submit, (b) equivocation sonrası
ikinci verifier sonuç retry, (c) fee reclaim sonrası re-entry, (d) min_verifier_count
eşik border'ları, (e) output_commitment hash collision (aynı hash farklı output_ref).
**Kapı:** `src/ai/` test'leri + CI `Budlum Core` yeşil; F06 STATUS'ta ✅ işaretlenir.
**Koordinasyon:** ARENA3 review (kripto domain), ARENA1'in F10.2 AI ↔ B.U.D. grant
entegrasyonundan (F10.5-07) bağımsız.
**Öncelik:** 🟡 (F06 largely closed, bu mühürleme).

### ARENA2-T2: P5 schema-4 snapshot hook (ARENA3 P2 ile koordineli)
**:** `StateSnapshotV2` schema-4 alan haritasının **chain tarafını** hazırla:
`ai_registry` snapshot'a giriyor mu (teyit `snapshot.rs`), AccessGrant alanları
(data_assets/storage_commitments/access_grants/once_consumed/revocations/
marketplace_listings — RFC §3.3) için `from_snapshot_v2`/`to_bytes` stub'ları.
**Kapı:** `cargo check` + snapshot roundtrip test (alanların digest'e girdiği).
**Koordinasyon:** **ARENA3 P2 ile TEK PR** (GAP-1+GAP-2+marketplace+pollen,
RFC §4 "tek-taraflı root değişikliği YASAK"). ARENA2 chain tarafı, ARENA3
schema/digest. **İlan gerekli** (STATUS'ta) — başkasının domain'ine dokunuyor.
**Öncelik:** 🟡 (P2 koordinasyon).

### ARENA2-T3: bridge_state snapshot bütünlüğü (GAP-2 destek)
**:** `bridge_state` zaten snapshot'a giriyor (`snapshot.rs:440`). B2 (ARENA1
PR #49, GAP-2'ye ertelendi) geldiğinde `cross_domain::AssetId` struct'a dönüşecek
— chain_actor/snapshot tarafında serde roundtrip testi ekle (B2 merge sonrası).
**Kapı:** `bridge_state_json_roundtrip` test.
**Koordinasyon:** ARENA1 B2 (PR #49) merge sonrası başlar.
**Öncelik:** 🟢 (B2 bekler).

### ARENA2-T4: AI ↔ B.U.D. AccessGrant entegrasyonu (F10.5-07, P5 RFC)
**:** `AiInferenceRequest.input_ref` opak `Vec<u8>`; eğer bir B.U.D.
`DataAsset`'ine işaret ediyorsa `AiVerifier` hesaplamadan ÖNCE geçerli `AccessGrant`
kontrolü ZORUNLU (Bölüm 2.2). Tasarım: `input_ref` formatı `(asset_id, grant_id)`
veya opak + ayrı grant-check host-call.
**Kapı:** Ayrı RFC (`docs/RFC_AI_BUD_GRANT_CHECK.md`) → onay → implementasyon.
**Koordinasyon:** ARENA3 pollen (marketplace) primitifleri P1 sonrası; ARENA1
F10.2 receipt decode (grant ID format) ile temas.
**Öncelik:** 🟡 (AccessGrant P1 main'e inince).

---

## 3. ARENA3 talimatları (CI/fuzz/chaos/kripto/schema/P4/triyaj)

> ARENA3 domain'i: `fuzz/`, `.github/workflows/`, chaos, CI kök-neden, PR/dependabot
> triyaj, HSM/kripto, snapshot schema (P2), CI gate'ler (P4).

### ARENA3-T1: P2 schema-4 tek PR (GAP-1+GAP-2+marketplace+B2) — EN KRİTİK
**:** RFC §3.3 + §4'ün uygulaması. TEK atomik PR:
- GAP-1 manifest imza (`manifest_signer`/`manifest_signature`, approved RFC).
- GAP-2 hash-kapsam genişletme: `tokenomics`, `tokenomics_burn`, `registry`,
  `liveness`, `invalid_votes`, `bns_registry`, `socialfi`, `pollen` (marketplace),
  `hub`, `storage_registry`, `bridge_state`, `message_registry`, `external_roots`,
  `finality_certificates`, `created_at` — hepsi `calculate_hash` digest'ine girer.
- B2 (`cross_domain::AssetId` alias→struct, PR #49 WIP) — ARENA1'in 30-site E0308
  haritası `9bc3094` STATUS'ta; migration bu PR'da.
- Domain-separation prefix (`budlum.snapshot.v4`) + LegacyImport.
**Kapı:** snapshot roundtrip (alan digest'e girer) + GAP-2 pin test
(`..._unhashed_field_forgery_gap`) + B2 `bridge_state_json_roundtrip`.
**Koordinasyon:** ARENA2-T2 (chain tarafı) ile **TEK PR**. İlan zorunlu.
**Öncelik:** 🔴 (mainnet-prep schema bütünlüğü; çok modülü tek seferde kapatır).

### ARENA3-T2: P4 pollen CI gate (pollen primitifleri P1 main'e inince)
**:** BNS desenini kopyala: `src/tests/pollen_marketplace.rs` (isim-kilitli
test seti) + `scripts/check-pollen-gate.sh` (vacuous-kanaryalı, `check-bns-gate.sh`
deseni) + `.github/workflows/ci.yml` job `Pollen Marketplace Invariants` + branch
protection 16→17 zorunlu check.
**Kapı:** self-test (tam=PASS, eksik/FAILED=FAIL) + CI yeşil.
**Koordinasyon:** **DİKKAT modül artık `pollen`** (eskiden `bud_marketplace`,
ARENA1 PR #50). P1 primitifleri (ARENA1) main'e inince başlar. README dashboard'a
pollen satırı (Core 755 → güncel sayı).
**Öncelik:** 🟡 (P1 sonrası).

### ARENA3-T3: Açık PR triyajı (8 dependabot + #49/#51 WIP)
**:**
- **PR #49 (B2, ARENA1 draft):** GAP-2'ye ertelendi (ARENA3-T1 içinde çözülecek).
  → **KAPAT** ("superseded by P2 schema-4", yorumla).
- **PR #51 (RLP dublikat, ARENA1 draft):** F10.1 PR #52 ile main'e girdi (farklı
  branch). → **KAPAT** ("superseded by #52", yorumla).
- **Dependabot #45 toml** (YEŞİL aday): TOML 1.1 davranış incelemesi → merge
  değerlendirmesi (config parsing etkisi).
- **Dependabot #43 tower** (KIRMIZI): recreate sonrası hâlâ kırık → gerçek kırılım
  analizi, kapat veya fix'le.
- **Dependabot #36/#37/#38/#39/#41** (KIRMIZI): her biri ayrı değerlendirme
  commit'i; budzero p3 serisi koordineli göç mümkün mü.
**Kapı:** her PR için kanıt-yorum (merge/kapat/ertele + gerekçe).
**Koordinasyon:** #49/#51 ARENA1 WIP (kapatma onayı implicit — GAP-2/P2 ve #52
supersede).
**Öncelik:** 🟡 (mainnet-prep dep dondurma ilkesiyle çelişebilir — kullanıcı kararı).

### ARENA3-T4: F10.1 fuzz target (F10.2 güvenlik destek)
**:** `fuzz/fuzz_targets/`'a `evm_rlp_decode` + `evm_mpt_verify` target'ları
ekle (F10.1 RLP+MPT). Rastgele bytes → decode/verify → RED beklenir, **panic
YOK** (DoS güvenliği mührü). Corpus: Ethereum test-vector'leri.
**Kapı:** `cargo +nightly fuzz run evm_rlp_decode` 5 dk → 0 crash.
**Koordinasyon:** ARENA1 F10.2 (receipt/header decode) için aynı deseni genişlet.
**Öncelik:** 🟡 (F10.2 main'e inince).

### ARENA3-T5: F27 ceremony playbook (MR-6 mainnet-engeli)
**:** `docs/operations/MAINNET_GENESIS_CEREMONY.md`'ye: (a) MPC key-gen
protokolü (multi-party, HSM, witness listesi), (b) bootnode discovery prosedürü,
(c) key-imha kanıtı (ceremony günü), (d) emergency rotation prosedürü.
**Kapı:** doküman review + GENESIS_FLIP_CHECKLIST F1-F5 ✅.
**Koordinasyon:** kullanıcı (ceremony katılımcıları, HSM vendor).
**Öncelik:** 🔴 (MR-6 mainnet-launch engeli).

### ARENA3-T6: F29 BUG_BOUNTY.md (MR-8)
**:** `docs/BUG_BOUNTY.md` oluştur: kapsam (bridge/crypto/consensus öncelikli),
ödül seviyeleri (Critical/High/Medium/Low), iletişim kanalı (güvenli disclosure),
out-of-scope. Immunefi-benzeri yapı (MAINNET_READINESS §2.4 karar C).
**Kapı:** doküman review.
**Koordinasyon:** kullanıcı (ödül bütçesi, platform seçimi).
**Öncelik:** 🔴 (MR-8).

---

## 4. ARENA1 devam (F10.2 —  yöneticisi + cross_domain)

> ARENA1 domain'i: `src/cross_domain/**` (bridge/message/relayer/evm), F10.

### ARENA1-T1: F10.2 (WIP, devam)
**Durum:** `receipt.rs` + `header.rs` yazıldı (workspace, commit'siz). Kalan:
- `adapter.rs` — `EvmChainAdapter: ChainAdapter` impl (`verify_receipt_proof`
  on-chain deterministik; generate/submit/wait off-chain stub).
- `verify_evm_receipt` orchestrator: header chain (N-conf) → MPT verify (F10.1) →
  receipt decode → deposit log match → replay check.
- Negatif matris: bozuk proof/receipt/header, yanlış root, replay, <N-conf,
  yanlış emitter/topic0.
- CI gate (`scripts/check-evm-adapter.sh` + workflow job, P4 deseni).
**Kapı:** H4 🔴 kapanır (gerçek kriptografik receipt verify). mainnet-öncesi
(kullanıcı kararı `f10_before_mainnet`).
**Öncelik:** 🔴.

---

## 5. Öncelik matrisi (mainnet-prep kritik yol)

| Sıra |  | Sahip | Tip | Mainnet-engeli? |
|---|---|---|---|---|
| 1 | **F10.2** (H4 kapatma) | ARENA1 | kod | 🔴 EVET |
| 2 | **ARENA3-T1 P2 schema-4** (GAP-1+GAP-2+B2) | ARENA3+ARENA2 | kod | 🔴 EVET (snapshot bütünlük) |
| 3 | **ARENA3-T5 F27 ceremony** | ARENA3 | docs | 🔴 EVET (MR-6) |
| 4 | **ARENA3-T6 F29 bug bounty** | ARENA3 | docs | 🔴 EVET (MR-8) |
| 5 | **F01 ContentManifest owner** | (karar) | tasarım | 🔴 ( yöneticisi karar kapısı) |
| 6 | ARENA2-T1 F06 edge-case matris | ARENA2 | kod | 🟡 (F06 mühürleme) |
| 7 | ARENA3-T2 P4 pollen gate | ARENA3 | CI | 🟡 (P1 sonrası) |
| 8 | ARENA3-T3 PR triyajı | ARENA3 | triyaj | 🟡 |
| 9 | ARENA3-T4 F10.1 fuzz target | ARENA3 | fuzz | 🟡 (F10.2 sonrası) |
| 10 | ARENA2-T3 bridge_state roundtrip | ARENA2 | test | 🟢 (B2 sonrası) |
| 11 | ARENA2-T4 AI↔B.U.D. grant | ARENA2 | RFC | 🟡 (AccessGrant P1 sonrası) |

---

## 6.  yöneticisi notları (süreç)

1. **CI-check'siz push YASAK** (AI_ONBOARDING §3). Bu oturumda ARENA2 ADIM2/P5
   iki kez CI doğrulamadan merge etti → main kırmızı zinciri (fmt+compile+test).
   Her push'ta check-runs bekle (~12 dk/SHA).
2. ** STATUS_ONLINE aktif kullanım zorunlu** — her handoff/ADIM öncesi oku +
   her iş sonrası imzalı girdi aç (kullanıcı emri).
3. **Başkasının domain'ine dokunma** — STATUS'ta ilan + sahibinin onayı. İstisna:
   main kırmızıyken kolektif onarım (committe şeffaf).
4. **Kriptografik sabitleri ezberden yazma** — lokal toolchain yoksa CI assertion
   otorite (F10.1 EMPTY_TRIE_ROOT dersi).
5. **Lokalde toolchain yok** (ARENA1) → CI hakem. ARENA3 lokal cargo ile 4-kapı
   çalıştırabiliyor — bu farkı kabul et, fmt dalgalarında sabırlı ol.

---

## 7. Kullanıcı karar kapıları ( yöneticisi sunar)

1. **F01 owner modeli:** manifest'te `owner` alanı mı, ayrı owner-registry mi?
   (K10.5-1)
2. **F02 AccessGrant hard-enforcement (HPKE):** mainnet-engeli olarak işaretlensin mi?
3. **F10 mainnet-öncesi mi sonrası mı:** kullanıcı `f10_before_mainnet` dedi (bridge
   mainnet'te açık) → F10.2-5 mainnet öncesi.
4. **Dependabot majors (#45 toml vb.):** merge mi, mainnet sonrası dondurma mı?
5. **F27 ceremony + F29 bounty:** bugün başlatılsın mı (docs), yoksa F10.2 sonrası mı?

---

*Co-authored-by: ARENA1 <arena1@budlum.ai> ( yöneticisi)*
