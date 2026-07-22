# BUDLUM MAINNET YOL HARİTASI — Task 11.6 → 11.20

**Tarih:** 2026-07-20
**Yazar:** ARENA1 (görev yöneticisi)
**Durum:** 10 mimari karar onaylı → 8 goreva dönüştürüldü
**Prensip:** Mainnet tarihine bol zaman var → **en sıkı sistemi kur**: spec-first, her gorevda CI kapısı + kabul kriteri + fuzz/security gate, kısayol yok.

---

## 0. Mimari Karar Kayıtları (ADR)

Her gorev kendi kararlarını `docs/adr/ADR-NNN-<başlık>.md` olarak kaydeder. ADR'ler geriye dönük olarak değiştirilemez — yeni karar yeni ADR. Bu, mimari kararların izini sürülebilir kılar (q10 threat model için de gerekli).

---

## Karar → Gorev Eşlemesi

| Karar | Gorev |
|---|---|
| q1 Genesis pool | 11.6 (spec) + 11.8 (kod) |
| q2 Storage spec-first | 11.6 (spec finalize) + 11.10 (kod) |
| q3 Full + Archive node | 11.10 |
| q4 Minimal on-chain governance | 11.16 |
| q5 Multisig v1'de | 11.14 |
| q6 Per-domain fork-choice | 11.6 (spec) + 11.8 (kod) |
| q7 Full ağ sertleştirme | 11.12 |
| q8 MASAK PoA domain | 11.18 |
| q9 EIP-1559 fee | 11.8 |
| q10 Threat model + audit prep + HSM | 11.6 (threat) + 11.20 (audit/HSM) |

---

## TASK 11.6 — MİMARİ TEMEL & SPEC FİNALİZASYONU

**Hedef:** Tüm kodlama gorevlarının temelini atan spec'leri + karar kayıtlarını + tehdit modelini kur. Kod yazmak YOK — bu gorev pure spec + review.

**Bağımlılık:** Hiçbiri (her şeyin temeli).

### Görevler
1. **`docs/adr/` framework** — ADR-000 (şablon) + ADR-001..010 (10 onaylı kararın kaydı).
2. **Genesis Reward Pool tokenomik spec** (`docs/GENESIS_REWARD_POOL_SPEC.md`):
   - Pre-allocation oranı (%8-12), dağıtım schedule'ı (epoch-bazlı).
   - Slash/penalty etkileşimi, treasury governance interface'i.
   - Sabit 100M arzla tutarlılık kanıtı (emisyon hesabı).
3. **`BUD_STORAGE_TECHNICAL_SPEC.md` finalize** (Task 11.4 spec'i):
   - Storage provider trait interface'i (imzalar net).
   - Deal lifecycle state machine (open → prove → challenge → settle).
   - CI spec-review kapısı tanımı (sonraki gorev için).
4. **`DOMAIN_FORK_CHOICE_SPEC.md` finalize**:
   - `ConsensusDomain::fork_choice()` trait method imzası.
   - Per-domain kurallar (PoW longest-chain, PoS LMD-GHOST, BFT instant finality, PoA round-robin).
   - Domain lifecycle (start/stop/upgrade) spec bölümü.
5. **EIP-1559 fee market spec** (`docs/EIP1559_FEE_MARKET_SPEC.md`):
   - Base fee adjustment algoritması (yoğunluk-bazlı), burn yolu.
   - Priority fee → validator dağıtımı.
   - Mevcut metabolic burn ile etkileşim (çakışma/üstüne-binme).
6. **Threat model dokümanı v1** (`docs/THREAT_MODEL.md`):
   - STRIDE kategorileri başına senaryolar (consensus, p2p, wallet, bridge).
   - Eclipse/sybil/long-range/nothing-at-stake analizleri.
   - Her gorevın güvenlik kabul kriterleri için temel.

### Kabul Kriterleri
- [ ] 10 ADR yazıldı, PR ile review edildi.
- [ ] 4 spec (genesis pool, storage, fork-choice, EIP-1559) `docs/spec-review/` checklist'ine göre işaretlendi.
- [ ] Threat model en az 20 tehdit senaryosu listeli, her birine sınıf + etki + azaltma.
- [ ] **CI kapısı:** `scripts/check-spec-coverage.sh` — her spec için "interface frozen" işareti kontrolü.

---

## TASK 11.8 — KONSENSÜS ÇEKİRDEĞİ: EKONOMİ + FORK-CHOICE

**Hedef:** Konsensüs ve ekonomiyi değiştiren 3 kod akışı (konsensüs-kritik, en erken yapılmalı çünkü state machine'i değiştirir).

**Bağımlılık:** 11.6 (spec'ler).

### Görevler
1. **Genesis reward pool implementation** (q1):
   - `src/tokenomics/reward_pool.rs` — epoch-bazlı dağıtım schedule'ı.
   - Genesis config'e pool pre-allocation (`config/mainnet-genesis.json`).
   - Validator reward distribution (active validator set'e orantılı).
   - Burn mekanizmalarıyla tutarlılık testi (toplam arz sabit = kanıt).
2. **EIP-1559 fee market** (q9):
   - `src/chain/fee_market.rs` — base fee adjustment algoritması.
   - Block'da base fee yakımı (deflationary) + priority fee → validator.
   - `Transaction` yapısına `max_fee`/`priority_fee` alanları (geri uyumlu migration).
   - Gas estimation RPC (`bud_estimateGas` zaten var — EIP-1559'a bağla).
3. **Per-domain fork-choice trait + impl** (q6):
   - `ConsensusDomain::fork_choice(&self, candidates) -> ResolvedHead` trait methodu.
   - PoW longest-chain, PoS LMD-GHOST, BFT instant finality, PoA round-robin impl'leri.
   - Domain lifecycle modülü (`src/domain/lifecycle.rs`) — start/stop/upgrade proposal-driven.
4. **Konsensüs-kritik fuzz target** — genesis pool + fee + fork-choice birlikte fuzz.

### Kabul Kriterleri
- [ ] Genesis pool: toplam arz 100M sabit kanıt testi (10K epoch simülasyonu).
- [ ] EIP-1559: base fee yoğunluk senaryolarında stabilize oluyor (property test).
- [ ] Fork-choice: her domain impl'si için fork-resolution test matrisi (PoW reorg, BFT equivocation, PoS nothing-at-stake).
- [ ] **CI kapısı:** yeni "Economy Invariants" job'u — sabit arz + pool + fee dağıtımı tutarlılık.
- [ ] **CI kapısı:** fork-choice fuzz (60s) yeni target.

---

## TASK 11.10 — STORAGE LAYER + NODE SINIFLANDIRMASI

**Hedef:** En büyük boşluk — B.U.D. storage layer'ı spec'ten koda. + Full/Archive node ayrımı.

**Bağımlılık:** 11.6 (storage spec finalize).

### Görevler
1. **CI spec-review kapısı** (`scripts/check-spec-coverage.sh`) — 11.6'da tanımlandı, burada devreye girer: storage kodu spec'le uyumsuzsa FAIL.
2. **Storage provider trait** (`src/storage/provider.rs`):
   - `StorageProvider` trait — put/get/prove/challenge/settle imzaları.
   - Mock impl + fuzz target (spec'i kodla doğrula).
3. **Deal lifecycle state machine** (`src/storage/deal.rs`):
   - Open → Prove → Challenge → Settle (spec'ten kod).
   - Mevcut `StorageDeal` ile entegrasyon (çakışma çözümü).
4. **State pruning** (q3):
   - `src/storage/pruning.rs` — N-blok history pruned (full node default).
   - Archive node flag (`features.pruning = false` → full history).
   - Snapshot retantion (finalized checkpoint'ler her zaman tutulur).
5. **Node classification** (`config/mainnet.toml`):
   - `node.mode = "full" | "archive"`.
   - Disk gereksinim dokümantasyonu (operator guide).

### Kabul Kriterleri
- [ ] Storage trait + mock impl derleniyor, fuzz 60s temiz.
- [ ] Deal lifecycle state machine test matrisi (geçersiz geçişler reddi).
- [ ] Pruning: full node N bloktan eski state erişimi reddediliyor, archive erişiyor.
- [ ] Snapshot restore: finalized checkpoint'ten node başlatma testi.
- [ ] **CI kapısı:** spec-coverage (spec'teki her interface kodda var).

---

## TASK 11.12 — AĞ SERTLEŞTİRME (TAM)

**Hedef:** q7 — full network hardening v1'de. Eclipse/sybil'e karşı dayanıklı p2p katmanı.

**Bağımlılık:** 11.8 (consensus kararlı olmalı ki p2p test edilsin).

### Görevler
1. **Peer reputation/banlama** (`src/network/reputation.rs`):
   - Skorlama (invalid msg, timeout, equivocation) → banlama threshold'u.
   - Ban listesi (persistent + TTL).
2. **DHT bucket tuning** — Kademlia routing parametreleri, bucket size.
3. **NAT hole-punching** — libp2p relay/auto-nat entegrasyonu (config-driven).
4. **Peer diversity enforcement** — ekip H2'de eklediği /24 subnet bound'u genişlet:
   - Max peer per ASN, per IP range.
   - Outbound peer selection çeşitliliği.
5. **Network chaos/fault injection test suite** (`src/tests/network_chaos.rs`):
   - Network partition (Byzantine fault injection).
   - Eclipse saldırı simülasyonu (peer flooding).
   - Sybil saldırı (identity flooding).

### Kabul Kriterleri
- [ ] Reputation: kötü peer 3 ihlalde banlanıyor, ban TTL çalışıyor.
- [ ] Eclipse bound: tek /24'ten max N peer (config-driven, test-pinned).
- [ ] Network chaos suite: partition/Byzantine/eclipse/sybil her biri red veya tolere kanıtı.
- [ ] **CI kapısı:** yeni "Network Chaos" job'u (multi-node simülasyon).
- [ ] **CI kapısı:** reputation fuzz target.

---

## TASK 11.14 — HESAP KATMANI: MULTISIG + SOCIAL RECOVERY

**Hedef:** q5 — multisig/social recovery mainnet v1'de. wallet-core genişletme.

**Bağımlılık:** 11.8 (fee market, multisig tx'leri fee öder).

### Görevler
1. **Account abstraction spec + impl** (`src/wallet/multisig.rs`):
   - M-of-N multisig wallet (smart-contract benzeri, core'da değil — wallet layer).
   - Proposal → sign threshold → execute akışı.
   - Key rotation, owner add/remove.
2. **Social recovery** (`src/wallet/social_recovery.rs`):
   - Guardian set + threshold recovery (friends/key agents).
   - Recovery proposal → guardian approval → new key.
3. **wallet-core genişletme**:
   - wallet-core'a multisig imzalama, recovery guardian yönetimi.
   - wallet-core test matrisi (M-of-N combinations).
4. **Mobile/browser binding** (q5延伸):
   - uniffi (Kotlin/Swift) + wasm-bindgen (JS/TS) interface tanımı.
   - Bu gorevda sadece binding stub'ları (UI sonraki gorev).

### Kabul Kriterleri
- [ ] Multisig: M-of-N tüm kombinasyonlar test matrisi (3-of-5, 2-of-3, vb.).
- [ ] Social recovery: guardian rotation + compromise senaryosu testi.
- [ ] wallet-core: multisig + recovery test coverage ≥ %90.
- [ ] **CI kapısı:** wallet-core fuzz (multisig threshold brute-force).
- [ ] uniffi/wasm binding derleniyor (stub yeterli).

---

## TASK 11.16 — ON-CHAIN GOVERNANCE (MİNİMAL)

**Hedef:** q4 — minimal on-chain parametre değişikliği. Sadece güvenlik-kritik parametreler (slash ratios, min stake). Kod upgrade'leri hard fork ile off-chain.

**Bağımlılık:** 11.8 (parametrelerin runtime'da değişebilir olması).

### Görevler
1. **Governance parametre proposal** (`src/core/governance.rs` genişletme):
   - Proposal: (parametre_adı, yeni_değer, justifikasyon).
   - Sadece whitelist'li parametreler (slash ratios, min stake, fee bounds).
   - Vote/tally (validator stake-ağırlıklı).
2. **Timelock + activation** — proposal kabul → timelock → epoch başında aktif.
3. **Off-chain hard fork koordinasyon dokümanı** (`docs/HARD_FORK_COORDINATION.md`):
   - Versioning, signaling, fork activation rule.
4. **Governance invariant testleri**:
   - Whitelist dışı parametre reddi.
   - Stake-ağırlıklı vote manipülasyonu (sybil validator) reddi.

### Kabul Kriterleri
- [ ] Sadece whitelist'li parametreler değiştirilebiliyor (kod upgrade'leri değil).
- [ ] Timelock: kabul edilen proposal N epoch sonra aktif (deneme-anında-değil).
- [ ] Vote manipulation: stake transfer ile vote çalma reddediliyor.
- [ ] **CI kapısı:** governance invariant test seti.

---

## TASK 11.18 — UYUM: MASAK PoA DOMAIN

**Hedef:** q8 — MASAK AML hook'ları + audit trail, **sadece PoA domain'e izole** (permissionless'e dokunmaz — izolasyon ilkesiyle tutarlı).

**Bağımlılık:** 11.14 (multisig — kurumsal hesaplar için). 11.16 (governance — PoA admin yetkisi).

### Görevler
1. **PoA MASAK compliance modülü** (`src/registry/poa_compliance.rs`):
   - Address screening (blacklist/sanction check — off-chain oracle).
   - Suspicious tx freeze (PoA admin yetkili).
   - Travel rule metadata (off-chain, hash-on-chain).
2. **Audit trail** (`src/registry/poa_audit.rs`):
   - Tüm PoA tx'ler append-only audit log (zaten ledger'da ama indeksli rapor).
   - Compliance report generator (CSV/JSON export).
3. **PoA↔Permissionless izolasyon mührü**:
   - MASAK hook'ları PoA domain'den permissionless'e sızıyor mu test matrisi (q4 izolasyon ilkesinin genişletilmesi).
4. **Regülatör raporlama interface'i** — off-chain tool (PoA admin için).

### Kabul Kriterleri
- [ ] MASAK hook'ları SADECE PoA domain'de aktif (permissionless'e sızma testi pinned).
- [ ] Audit trail: tüm PoA tx'ler raporlanabilir, export test-pinned.
- [ ] Freeze: PoA admin şüpheli hesabı dondurabiliyor, permissionless hesabı değil.
- [ ] **CI kapısı:** PoA Compliance Isolation (MASAK sızma-kilitli, 5+ senaryo).

---

## TASK 11.20 — GÜVENLİK & AUDIT + MAINNET LOCKDOWN

**Hedef:** q10 — threat model finalize + audit prep paketi + HSM policy. Mainnet readiness final review.

**Bağımlılık:** 11.6 (threat model v1) + tüm gorevlar (11.8-11.18).

### Görevler
1. **Threat model finalize** (`docs/THREAT_MODEL.md` v2):
   - 11.6'daki v1'i tüm gorevların gerçekleşmiş azaltmalarıyla güncelle.
   - Kalan açık riskler + mainnet sonrası takip listesi.
2. **Audit prep paketi** (`docs/audit_prep/`):
   - Spec/test/fuzz evidence derlemi (her modül için).
   - Bağımsız auditör için index + okuma sırası.
   - Bilinen sınırlar + kabul edilmiş riskler listesi.
3. **HSM key policy** (`docs/VALIDATOR_KEY_MANAGEMENT.md`):
   - Validator operatörleri için HSM zorunluluğu (mainnet'te).
   - Soft launch → HSM migration yolu.
   - Anahtar rotasyonu, yedekleme, kayıp senaryosu.
4. **Mainnet readiness review** (MR-1..10 + yeni kriterler):
   - Tüm gorevların kabul kriterleri işaretli.
   - Bug bounty + V-bulgu süreci özeti (kapanan/açık).
   - Final integration test (tüm gorevlar birlikte).
5. **Mainnet lockdown:**
   - Tüm güvenlik-kritik parametreler locked (governance sonrası).
   - Emergency procedures (halt, rollback, communication).
   - Launch runbook.

### Kabul Kriterleri
- [ ] Threat model v2: her gorevın azaltmaları gerçekleşmiş, açık risk listeli.
- [ ] Audit prep paketi: bağımsız auditör tarafından okunabilir (dry-run review).
- [ ] HSM policy: validator operatör dokümanı complete.
- [ ] Mainnet readiness: MR-1..10 + 8 gorevın tüm kriterleri yeşil.
- [ ] **CI kapısı:** tüm gorevların CI job'ları main şubesinde yeşil, 7 gün stabil.

---

## Gorev Bağımlılık Grafiği

```
11.6 (Temel: spec + ADR + threat)
  │
  ├──► 11.8 (Konsensüs: economy + fork-choice) [konsensüs-kritik]
  │      │
  │      ├──► 11.10 (Storage + node) [spec-first, en büyük]
  │      │      │
  │      │      └──► 11.12 (Ağ sertleştirme)
  │      │
  │      ├──► 11.14 (Multisig + recovery) [hesap katmanı]
  │      │      │
  │      │      └──► 11.18 (MASAK PoA) [kurumsal]
  │      │
  │      └──► 11.16 (Governance minimal) [parametre runtime]
  │
  └──► 11.20 (Güvenlik + audit + lockdown) [her şey biter → bu]
```

**Paralelleştirme:** 11.10 / 11.14 / 11.16 birbirinden bağımsız, ekip (ARENA2/3/ARENA1) arasında paralel dağıtılabilir. 11.8 ve 11.20 seridir.

---

## En Sıkı Sistemin Kuralları (tüm gorevlar)

1. **Spec-first:** Hiçbir gorev spec'siz kod yazmaz. Spec finalize → CI spec-review kapısı → kod.
2. **CI tek otorite:** Lokal toolchain yok, CI her gorevın kabulünü belirler. Kısayol/allow/ignore YASAK.
3. **Her gorevda fuzz + security gate:** Konsensüs-kritik gorevlar (11.8, 11.16) ekstra fuzz target ekler.
4. **İzolasyon mührü:** PoA↔permissionless izolasyonu her gorevda test-pinned (özellikle 11.18 MASAK).
5. **ADR izi:** Her mimari karar ADR olarak kalıcı. Spec drift = yeni ADR.
6. **Branch protection:** Her gorev `arena/task-NN-X` branch'leri, PR ile merge, main her zaman yeşil.
7. **Görev yöneticisi (ARENA1):** Ekip CI kalıntılarını izler, main RED olursa öncelikli düzeltir (bu oturumda 5+ kez yapılan rol).

---

## Mainnet'e Kadar Toplam Tahmini Yük

| Gorev | Tahmini PR | CI kapısı |
|---|---|---|
| 11.6 | 6 (spec'ler + ADR + threat) | spec-coverage |
| 11.8 | 4-5 (pool, fee, fork-choice, lifecycle) | economy invariants + fork fuzz |
| 11.10 | 4-5 (trait, deal, pruning, node) | spec-coverage + storage fuzz |
| 11.12 | 3-4 (reputation, DHT, NAT, chaos) | network chaos |
| 11.14 | 3-4 (multisig, recovery, binding) | wallet fuzz |
| 11.16 | 2-3 (governance, timelock, invariant) | governance invariant |
| 11.18 | 3-4 (MASAK, audit, isolation) | PoA compliance isolation |
| 11.20 | 3-4 (threat v2, audit prep, HSM, lockdown) | tüm kapılar stabil |
| **Toplam** | **~28-34 PR** | **8 yeni CI job** |

---

## Sonraki Adım

Bu yol haritası onaylanırsa, **Task 11.6** başlatılır: ADR-000 şablonu + ilk 10 ADR + 4 spec finalize + threat model v1. Kod yazılmadan, pure spec — geri dönüş maliyeti en düşük gorev.
