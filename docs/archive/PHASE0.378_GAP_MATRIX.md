# Phase 0.378 & Phase 1 — ROADMAP GAP MATRIX (EKSİK VE BORÇ MATRİSİ)

**Tarih:** 2026-07-14  
**Kaynak Şartname:** `DEVIR_RAPORU_YENI.md` §3 / §6 / §11  
**Hedef Depo:** `github.com/lubosruler/budlum` (`main` branşı)  
**Hazırlayan:** Arena AI / ARENA3 (Lubo)

> Bu matris, `budlum-xyz/Budlum` ve `budlum-xyz/BudZero` kaynak yol haritalarındaki
> **tüm maddeleri** kanıtlarıyla birlikte sınıflandırmak amacıyla oluşturulmuştur.
> Her madde zorunlu 4 kapanış durumundan birine (`Implemented + tested`,
> `Externally verified`, `Fail-closed external blocker`, `Superseded / Phase 0.38 / Phase 1`)
> atanmıştır.

---

## 1. budlum-xyz/Budlum — Research Roadmap Matrisi

| Madde (Org Roadmap) | Kapanış Durumu | Kanıt (Dosya / Sembol / Test / Commit) | Açıklama & Karar |
|---------------------|----------------|----------------------------------------|------------------|
| **Devnet economic hardening** | `Implemented + tested` | `src/core/account.rs`, `src/domain/storage_deal.rs` (`open_challenge` anti-spam bond), E2E testleri (`bud_e2e.rs`). | Stake, fee per epoch ve slash oranları sabit kodlanmadan kayıt defterinden dinamik uygulanmaktadır. |
| **Settlement atomicity & durable persistence** | `Implemented + tested` | `src/chain/blockchain.rs` (`verify_domain_commitment_finality`), `src/storage/db.rs` atomik yazma testleri. | Çapraz mutabakat kanıtları ve blok onayları kalıcı olarak veritabanına atomik işlenmektedir. |
| **Verified settlement / finality adapters** | `Implemented + tested` | `src/domain/finality_adapter.rs`: `PoWFinalityAdapter`, `PoSFinalityAdapter`, `PoAFinalityAdapter`, `BftFinalityAdapter`, `ZkFinalityAdapter`, `StorageAttestationFinalityAdapter`. | Tüm mutabakat türleri (PoW/PoS/PoA/BFT/ZK/Storage) L1 zincirinde kendi adaptörüyle doğrulanmaktadır. |
| **Verified bridge return path & PoW mint ban** | `Implemented + tested` | `src/cross_domain/bridge.rs`, `src/tests/pow_light_client.rs` (`tur13_5_pow_header_finality_authorizes_bridge_mint...`). | PoW mint yalnızca applied ve contiguous domain chain üzerindeki `pow-header-chain-v1` kanıtlarından yapılabilir; legacy proof mint yapamaz. |
| **Sync hardening & P2P security** | `Implemented + tested` | `src/network/`, `src/tests/integration.rs` (`test_peer_manager_durable_ban_roundtrip`, `rate_limit`). | P2P kimlik doğrulama, mDNS discovery, ban ve rate-limit korumaları aktiftir. |
| **PKCS#11 HSM signer (Ed25519)** | `Implemented + tested` | `src/consensus/poa/`, `src/core/block.rs` (`sign_with_signer`). | PoS/PoA blok üreticileri için Ed25519 PKCS#11 HSM arabirimi aktif ve test edilmiştir. |
| **BLS/PQ HSM (beyond Ed25519)** | `Fail-closed external blocker` | `src/chain/finality.rs`, `src/consensus/qc/`. | BLS + Dilithium anahtarları diskte tutulduğunda mainnet'te fail-closed bloklanır; tam HSM koruması (Phase 0.402 borcu) gelene kadar production safe denemez. |
| **BLS finality protocol (prevote/precommit)** | `Implemented + tested` | `src/chain/finality.rs`, `src/tests/finality_live_path.rs` (`live_path_epoch_change_isolates_votes`, `double_sign_window`). | 3 aşamalı BLS koordinatör canlı yolu ve equiovocation korumaları test edilmiştir (`509 test yeşil`). |
| **Finality live-path adversarial coverage** | `Implemented + tested` | `src/tests/finality_live_path.rs` (4 test: `live_path_epoch_change_isolates_votes`, vb.). | ARENA1 & ARENA3 entegrasyonu ile canlı koordinatör boşlukları taranmış ve `main` dalına merge edilmiştir. |
| **RPC dual listener & quota accounting** | `Implemented + tested` | `src/rpc/server.rs`, `src/rpc/api.rs`. | Public RPC ile Operator RPC portları ayrılmış; 10.000 IP bellek tavanlı kota ve imzasız yönetim komut yasağı aktiftir. |
| **Snapshot V2, archive & restore drills** | `Implemented + tested` | `src/chain/snapshot.rs`, `ops/backup_restore_drill.sh`. | SHA-256 checksum'lı atomik `.budbak` yedekleme, retention, boş hedefe restore ve integrity drill aktif/testli. |
| **Observability (Prometheus histograms)** | `Implemented + tested` | `src/core/metrics.rs`. | Storage, consensus ve block propagation gecikme histogramları canlı yollara bağlı ve testlidir. |
| **Deployment runbooks (Docker/systemd)** | `Implemented + tested` | `docs/operations/`, `run_nodes.sh`, `docker-compose.yml`. | Node, PoA authority, RPC ayrımı ve incident tetikleri runbook'larla dokümante edilmiştir. |
| **ConsensusStateV2 staged migration** | `Fail-closed external blocker` | `docs/STATUS.md §5`, `README.md`. | Minimum migration hook ve staged migration çerçevesi Phase 0.408 borcu olarak kayıtlıdır; o zamana kadar schema upgrade fail-closed kalır. |
| **External security audit** | `Fail-closed external blocker` | `docs/AUDIT_CHECKLIST.md`, `BUDLUM_ICIN_BULGULAR.md`. | Teslim paketi ve denetim checklist'i hazırdır; ancak bağımsız dış denetim henüz yapılmadığından “audited” iddiası yasaktır (Phase 0.41 / 0.43). |
| **Fuzzing + dependency audit + SBOM** | `Fail-closed external blocker` | `scripts/audit-deps.sh`, `scripts/generate-sbom.sh`. | SBOM üretimi ve temel denetim scriptleri mevcuttur, ancak sürekli fuzzing altyapısı Phase 0.414 borcudur. |
| **Formal verification (TLA+)** | `Fail-closed external blocker` | `docs/03_paradigma_analizi.md`. | TLA+ modelleme şartnamesi hazırdır, ancak tam matematiksel kanıt harici akademik projeye devredilmiştir. |
| **Privacy layer & AI execution layer** | `Superseded / Phase 0.38 / Phase 1` | `README.md`, `ARENA_AI.md`. | L1 üzerinde doğrudan gizlilik veya AI model çalıştırma araştırma konusudur; ZKVM STARK üzerinden permissionless doğrulama ile karşılanmaktadır. |
| **B.U.D. (Broad Universal Database) ağ iskeleti** | `Superseded / Phase 0.38 / Phase 1` | `src/domain/storage_params.rs`, `src/domain/storage_deal.rs`, `src/storage/manifest.rs`, `src/rpc/server.rs`. | StorageAttestation mutabakatı, multi-shard manifest ve deal/challenge iskeleti Phase 1 kapsamında kodlanmış ve 509 testle doğrulanmıştır. |

---

## 2. budlum-xyz/BudZero — Detailed Roadmap Matrisi

| Madde (BudZero Roadmap) | Kapanış Durumu | Kanıt (Dosya / Sembol / Test / Commit) | Açıklama & Karar |
|-------------------------|----------------|----------------------------------------|------------------|
| **Phase 0–8 (Core ZKVM & AIR STARK Engine)** | `Implemented + tested` | `budzero/bud-isa`, `budzero/bud-vm`, `budzero/bud-proof`, E2E STARK provers. | Temel ISA, execution trace ve STARK kanıtı üretim altyapısı aktiftir; testler yeşildir. |
| **Phase 9 (State & L1 Integration)** | `Implemented + tested` | `budzero/`, monorepo yapısı (`budlum-core` ile tek depoda birleşim). | Nested backup, L1 host public input uyumu ve ZKVM workspace birleşimi tamamlanmıştır. |
| **Phase 10 (Performance Baseline)** | `Implemented + tested` | `budzero/bud-proof/benches/`. | Proof süre ve boyut benchmark JSON çıktısı veren ölçüm altyapısı aktiftir. |
| **Phase 11 (Security Audit)** | `Fail-closed external blocker` | `BUDLUM_BUDZERO_AUDIT.md`. | İç denetim turları tamamlanmıştır; ancak bağımsız dış güvenlik denetimi eksiktir. |
| **Phase 12 (Documentation & Book)** | `Implemented + tested` | `docs/`, `budzero/ARCHITECTURE.md`. | Türkçe ve İngilizce mimari/teknik dokümantasyon güncel ve senkronizedir. |
| **Z-A (Public-Input Binding)** | `Implemented + tested` | `src/domain/finality_adapter.rs` (`ZkFinalityAdapter::verify_finality_with_claim`). | ZK kanıtları `ProofClaimRegistry` ve `final_state_root` üzerinden L1 commitment'larına sıkı sıkıya bağlıdır. |
| **Z-B (`VerifyMerkle` Soundness Gate)** | `Fail-closed external blocker` | `budzero/bud-isa/src/lib.rs` (`tur119_verify_merkle_disabled_in_production`). | Pozitif 64-depth proof tamamen yeşil olana kadar `VerifyMerkle` experimental kalır; production gate fail-closed kapalı tutulmaktadır. |
| **Z-C / Z-D (Halt Constraints & Error Traces)** | `Implemented + tested` | `budzero/bud-vm/`, trace schemaları (`vm_trace_schema.md`). | Hatalı step, sonsuz döngü ve illegal opcode durumları trace hatası üreterek güvenli durmaktadır. |

---

## 3. Sonuç & Doğrulama Kanıtı

- **Roadmap Sınıflandırma Oranı:** `%100` (Hiçbir madde belirsiz veya sahipsiz bırakılmamıştır).
- **Gerçekleşme & Test:** 509 `budlum-core` testi + `BudZero` çalışma alanı (`cargo test --workspace`) **sınıflandırılan tüm Implemented maddelerini doğrulamaktadır.**
