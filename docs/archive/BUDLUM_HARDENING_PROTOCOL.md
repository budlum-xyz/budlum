# Budlum — Tam Sertleştirme Protokolü (Hardening Protocol)

> **Durum:** Kanonik süreç belgesi (ARENA ajanları + insan operatör).  
> **Yazar:** ARENA3 · **Tarih:** 2026-07-20 · **Temel SHA:** `8b66cd4` (güncellenir).  
> **İlişki:** Bu belge `docs/mainnet-hazirligi-talimati.md`, `docs/MAINNET_READINESS.md` (MR-1..10),
> `docs/THREAT_MODEL.md`, `docs/AUDIT_CHECKLIST.md`, `docs/BUDLUM_TASK11.md`,
> `docs/operations/*` ve `CLAUDE.md` ile birlikte okunur. **Çelişkide:**
> (1) CLAUDE.md permissionless/PoA izolasyonu, (2) bu protokolün kapı kuralları,
> (3) MR tablosu — bu sıra geçerlidir.
>
> **Amaç:** Budlum Core + BudZero'yu "mainnet konuşulabilir" seviyeye değil,
> **saldırı yüzeyinin sistematik olarak kapatıldığı, kanıtlı, tekrarlanabilir
> bir sertleştirme rejimine** sokmak. Hız değil derinlik. CI tek hakem.

---

## 0. Tanımlar

| Terim | Anlam |
|-------|--------|
| **Sertleştirme (hardening)** | Bilinen bulgu kapanışı + saldırı yüzeyi daraltma + regresyon kilidi + operasyonel tatbikat. Kod yeşili ≠ sertleştirilmiş. |
| **Kapı (gate)** | Bir sonraki goreva geçmek için zorunlu kanıt demeti. Kapı kırmızıysa yeni kapsam **YASAK**. |
| **Bulgu (V-ID)** | STATUS_ONLINE / denetim raporlarında numaralı güvenlik/davranış açığı. |
| **Regresyon kilidi** | Bir fix'in bir daha sessizce bozulmasını engelleyen isimli test + mümkünse CI gate. |
| **Sahte-yeşil** | Test/CI'nin fail'i gizlemesi (pipefail yok, stub "OK", `#[ignore]` ile "yeşil"). Protokol ihlali. |
| **Permissionless çekirdek** | PoW/PoS/BFT: whitelist/admin kapısı **YOK**. Güvenlik = stake + slashing. |
| **PoA ada** | İzole permissioned domain. Kuralları permissionless registry'ye sızamaz (ve tersi). |

**"Tam sertleştirilmiş" iddiası** ancak §12 mühür tablosundaki tüm satırlar ✅
ve kullanıcı (Ayaz) onayı ile kullanılabilir. Aksi halde bu ibare **yasak**.

---

## 1. Değişmez kurallar (her ADIM'da)

1. **CI tek hakem.** Lokal "geçti sanmak" yetmez. Push sonrası SLEEP; kırmızıysa
   yeni özellik yok — yalnız kök-neden onarımı.
2. **Force-push yasak.** `git merge origin/main` (rebase PR dalında dikkatli).
3. **budlumdevnet salt-okunur.** Referans; değiştirilmez.
4. **Kanıtsız süreç beyanı yok.** STATUS_ONLINE: SHA + run ID/link zorunlu.
5. **Pipefail zorunlu.** `cmd | tee` → `set -euo pipefail` (Core Test sahte-yeşil
   vakası: `d815561` / ARENA3 `e03e2ee`).
6. **Stub dürüstlüğü.** Production path'te "verify OK" dönen stub = 🔴 bulgu.
   Ya gerçek verify, ya fail-closed, ya experimental gate.
7. **PoA sızması yok.** Yeni registry/rol/RPC PoA izin modelini PoW/PoS/BFT'ye
   taşıyamaz. PoA izolasyon testleri (7/7 isim-kilitli) kırmızıysa merge yok.
8. **Scope creep yasağı.** Aktif 🔴/🟡 kapı açıkken yeni RFC/özellik açılmaz
   (mainnet talimatı Madde 15).
9. **Dış commit sorgusuz kabul yok.** Diff + lokal/CI doğrulama (kullanıcı madde 6).
10. **Token/sır sızıntısı yok.** PAT yalnız env; commit'e yazılmaz; gitleaks kırmızı = dur.

---

## 2. Saldırı yüzeyi haritası (ne sertleştiriliyor)

```
                    ┌─────────────────────────────────────┐
                    │         Harici dünya / P2P / RPC      │
                    └───────────────┬─────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
   network/mempool              rpc/gateway                 relayer
   eclipse, DoS,                auth, injection,            permissionless
   gossip poison                rate-limit                  stake+slash
         │                          │                          │
         └──────────────────────────┼──────────────────────────┘
                                    ▼
                         execution / chain_actor
                         tx apply, fees, reorg
                                    │
         ┌──────────────┬───────────┼───────────┬──────────────┐
         ▼              ▼           ▼           ▼              ▼
    consensus      settlement   cross_domain  tokenomics    registry
    PoW/PoS/BFT    merkle/qc    bridge/EVM    burn/vest     slash/PoA
    /PoA ada                    replay
         │              │           │
         └──────┬───────┴───────────┘
                ▼
         crypto / HSM / snapshot / storage
                │
                ▼
         budzero (BudZKVM / STARK / VerifyMerkle)
```

**Birinci sınıf risk alanları (öncelik sırası):**

| P | Alan | Neden |
|---|------|--------|
| P0 | Consensus safety + reorg + finality | Zincir çatalı / çift harcama |
| P0 | Bridge / cross-domain replay & root | Köprü drain |
| P0 | Crypto verify paths (BLS, Ed25519, STARK) | Sahte finality / sahte proof |
| P0 | Economic invariants (balances, escrow, slash) | Sessiz fund loss |
| P1 | Snapshot / genesis / migration | State zehirleme, boot rollback |
| P1 | Network eclipse / DoS | İzolasyon, liveness |
| P1 | RPC surface | Yetkisiz state mutate, bilgi sızıntısı |
| P2 | AI agent payments / inference gates | Escrow, spoof, stub verify |
| P2 | Supply chain / CI gates | Bağımlılık, sahte-yeşil |
| P2 | Ops: HSM, ceremony, runbook, bounty | Mainnet operasyon |

---

## 3. Protokol gorevları (sıralı; atlama yok)

Her gorevın sonunda **Kapı Gx** vardır. Gx kırmızıysa G(x+1) başlamaz.

### Gorev H0 — Yeşil zemin ve ölçüm (zorunlu önkoşul)

**Amaç:** Sertleştirme işinin üzerine bina edileceği CI zemini.

| # | İş | Kanıt |
|---|-----|--------|
| H0.1 | `main` CI: Core, BudZero, Coverage, Fuzz Quick, PoA, BNS, BUD, supply-chain, timing, docker | check-runs 23/23 (veya güncel zorunlu set) |
| H0.2 | Pipefail / sahte-yeşil tarama | `ci.yml` Test+doc `set -euo pipefail`; bilinen kaçak yok |
| H0.3 | Bulgu envanteri dondurma | Tek tablo: açık 🔴/🟡 listesi (STATUS + bu belge §4) |
| H0.4 | Saldırı yüzeyi envanteri | Modül → risk → sahip (ARENA) |

**Kapı G0:** H0.1 yeşil + H0.3 tablosu STATUS'ta mühürlü.

---

### Gorev H1 — Kritik bulgu imhası (🔴 = 0)

**Amaç:** Mainnet blocker sınıfı açıkların tamamını kapatmak.

#### H1.A — Ekonomi / escrow / executor

| ID | Konu | Kabul (minimum) | Sahip adayı |
|----|------|-----------------|-------------|
| **V89** | Non-escrowed payment audit trail | **FIXED (ARENA3):** `settled_agent_payments` + reuse RED + hardening_locks | ARENA3 |
| **V86** | Escrow release/reclaim tx path | `AiAgentPaymentRelease` / `Reclaim` executor + proto + test; fund conservation | ARENA2 |
| Balance | Her value-path: fee+amount tek atomik kontrol | Yetersiz bakiye → state değişmez (proptest/invariant) | ARENA2 |

**V89 notu (kod teyidi, `executor.rs`):** Non-escrowed dalda `agent_payments.remove` var.
Sertleştirme seçenekleri kullanıcı kararı gerektirir (§11 K1).

#### H1.B — Bridge / cross-domain

| ID | Konu | Kabul | Sahip |
|----|------|-------|-------|
| **V24** | BridgeState root scope | `root()` transfer metadata içerir + forged transfer → root mismatch testi | ARENA1 (kodda V24 fix var — **CI+negatif test teyidi zorunlu**) |
| Replay | lock/mint/burn/unlock | Her geçişte replay mark + çift mint RED | ARENA1 |
| Fee cast | u128→u64 | amount **ve** fee overflow guard (V124 sınıfı) | ARENA1 |
| Expired lock | sweep | Owner refund zorunlu (V106 sınıfı) | ARENA1 |

#### H1.C — Finality / light-client / ZK kapıları

| ID | Konu | Kabul | Sahip |
|----|------|-------|-------|
| Sync-committee | Participation threshold | ≥2/3 geçerli imza; tek-pubkey bypass yok (V119 sınıfı) | ARENA1/3 |
| **V110** | VerifyInference | Mainnet'te disabled/fail-closed; stub "success" YOK | ARENA3 (budzero) |
| **V37/V38 / MR-3** | VerifyMerkle 64-depth | Production gate politikası net (§11 K2); sahte PoS iddiası yok | ARENA3 + budzero |
| PoW legacy | Mint-gated | Light-client olmayan path mainnet'te kapalı veya belgelenmiş risk | ARENA1 |

#### H1.D — Consensus / reorg / state tutarlılığı

| ID | Konu | Kabul | Sahip |
|----|------|-------|-------|
| Reorg | try_reorg | Domain/bridge/settlement storage ile sync (V95 sınıfı) | ARENA2 |
| MAX_REORG_DEPTH | | Aşım RED + test | ARENA2 |
| Double-sign / liveness slash | | Evidence actionable olmadan slash YOK; dedup history | ARENA2/3 |

**Kapı G1:** Açık 🔴 = **0** · her kapanışta regresyon kilidi test adı STATUS'ta · CI yeşil.

---

### Gorev H2 — Yüksek bulgu ve invariantlar (🟡 → 0 veya bilinçli risk kaydı)

**Amaç:** Yüksek önemdeki açıklar ya fix ya da **imzalı risk kabulü** (kullanıcı).

| Küme | Örnekler | Yöntem |
|------|----------|--------|
| Overflow/cast | luminance, fee, BNS cost | saturating/checked + property test |
| AuthZ | RPC mutate, hub self-verify | default-deny; self-verify badge güvenilmez işaretlenir veya kapatılır |
| DoS | mempool/peer limits, msg size | üst sınır + fuzz |
| AI registry | domain-sep, expiry max, whitelist mode | state root domain prefix + test |
| Snapshot | hash kapsam, imza (GAP-1) | schema version + verify fail-closed |

**Her 🟡 için zorunlu triyaj etiketi:**

- `FIX-NOW` — H2 içinde kapat
- `FIX-NEXT` — H3'e planlı
- `ACCEPT-RISK` — kullanıcı imzası + docs'ta "bilinen sınır" + izleme

**Kapı G2:** `FIX-NOW` kuyruğu boş · `ACCEPT-RISK` listesi docs'ta · CI yeşil.

### H2 progress (ARENA3, 2026-07-20)

| Item | Status |
|------|--------|
| V130 finalize/vote window | locked (`hardening_h2_locks`) |
| V131 BNS duration=0 | locked |
| V132 burn_from clip | locked (warn+return) |
| V133 challenge cap | locked (`storage_deal::v133_max_open_challenges_per_deal`) |
| V123 hub self-verify honesty | `developer_attested` ≠ `verified` |
| H5.1 eclipse /24 | `PeerManager` + Node admission |
| V111 L1 trie 256-bit | structural lock |

---

### Gorev H3 — Derin dinamik güvenlik (fuzz / chaos / property)

**Amaç:** Birim testin görmediği sınıfları zorlamak.

| # | İş | Minimum kabul |
|---|-----|----------------|
| H3.1 | Fuzz Quick CI (mevcut 10 target) yeşil | Her push |
| H3.2 | Fuzz Nightly 4h/target corpus büyütme | 7 ardışık gece 0 crash (veya crash → fix+repro corpus) |
| H3.3 | Consensus state transition + reorg fuzz | Fund/state root determinism; panic yok |
| H3.4 | Relayer escrow fuzz | lock→mint→burn→unlock conservation |
| H3.5 | ZK verifier fuzz | Invalid proof → RED; panic yok |
| H3.6 | Snapshot/tx/block deserialize fuzz | OOM/panic yok |
| H3.7 | Chaos: kill -9, disk full, clock skew (mevcut suite) | Belgelenmiş senaryolar yeşil |
| H3.8 | Tokenomics + bridge proptest invariants | CI'da düzenli |

**Kapı G3:** H3.1–H3.2 yeşil · yeni crash = 🔴 aç ve G1'e düş.

### H3 progress (ARENA3, 2026-07-20)

| Item | Status |
|------|--------|
| H3.1 Fuzz Quick 8 targets | CI job present (60s×8) |
| H3.2 Fuzz Nightly matrix | 8 targets × 4h (incl. consensus/relayer/zk) |
| H3.3–H5 Task 11.2 targets | present + expanded seed corpus |
| H3.6 deserialize targets | present |
| H3.7 chaos suites | `chaos.rs`, `snapshot_chaos.rs` |
| H3.8 proptest | `tokenomics_proptest`, `proptest_core` |
| V113 recover + bridge | `BRIDGE_STATE_AT:{h}` + rollback on interrupt |

---

### Gorev H4 — Kriptografi ve anahtar koruma

| # | İş | Kabul |
|---|-----|--------|
| H4.1 | Mainnet validator: disk key / hsm_mock **fail-closed** | Negatif test + runbook |
| H4.2 | PKCS#11 Ed25519 yolu | Devnet tatbikat kaydı |
| H4.3 | BLS/PQ vendor-native | §11 K3 vendor seçimi sonrası; mock ile "HSM ready" iddiası YASAK |
| H4.4 | Timing-safe regression (dudect tarzı) | CI job yeşil |
| H4.5 | Domain separation envanteri | Her root/leaf tag listesi docs'ta; çakışma yok |
| H4.6 | Miri (crypto + seçili budzero) | UB = 0 |

**Kapı G4:** H4.1+H4.4+H4.6 yeşil · H4.3 ya tamam ya "mainnet v1 out-of-scope" beyanı.

### H4 progress (ARENA3, 2026-07-20)

| Item | Status |
|------|--------|
| H4.1 disk / mock fail-closed | `mainnet_policy` + CLI wire + `validate_mainnet_disk_policy` locks |
| H4.2 PKCS#11 path | existing `pkcs11.rs` + mainnet requires module/pin |
| H4.3 vendor-native BLS/PQ | **mainnet v1 out-of-scope** (docs honesty lock) |
| H4.4 timing-safe | CI job + `constant_time_eq_str` correctness lock |
| H4.5 domain tags | `docs/CRYPTO_DOMAIN_TAGS.md` inventory + lock |
| H4.6 Miri | existing `miri.yml` crypto+bud-vm |

---

### Gorev H5 — Ağ, RPC, eclipse, DoS

Kaynak: `docs/NETWORK_HARDENING_SPEC.md`, `docs/operations/NETWORK_HARDENING.md`.

| # | İş | Kabul |
|---|-----|--------|
| H5.1 | Per-subnet connection bound (eclipse) | Test: /24 başına max N |
| H5.2 | Outbound diversity + bootstrap anchors | Config + smoke |
| H5.3 | RPC: auth default, mutate endpoint ACL | Anonim mutate RED |
| H5.4 | Rate limit + ban path | Peer flood testi |
| H5.5 | MAX_MESSAGE_SIZE / gossip dedup | Fuzz + unit |
| H5.6 | Multinode smoke (4+ node) | Workflow yeşil |
| H5.7 | NAT/relay (opsiyonel v1.1) | Belge + bayrak |

**Kapı G5:** H5.1–H5.6 yeşil.

### H5 progress (ARENA3, 2026-07-20)

| Item | Status |
|------|--------|
| H5.1 /24 eclipse | implemented + locks |
| H5.3 RPC auth default | locks (`auth_required=true`) |
| H5.5 MAX_MESSAGE_SIZE | locks |
| H5.6 multinode smoke | workflow + script lock |
| H5.2/H5.7 | remaining (diversity/NAT) — mainnet v1 follow-up |

---

### Gorev H6 — Snapshot, genesis, migration, boot

| # | İş | Kabul |
|---|-----|--------|
| H6.1 | Genesis reproducibility + cross-platform | determinism.yml |
| H6.2 | Ceremony checklist F1–F5 | operations/GENESIS_FLIP |
| H6.3 | Snapshot manifest imza (GAP-1) | Verify fail-closed |
| H6.4 | Migration vN→vN+1 | Geriye uyum + test |
| H6.5 | Boot quarantine / self-heal | Chaos pin'leri bilinçli |

**Kapı G6:** H6.1+H6.3+H6.4 yeşil · H6.2 ceremony günü.

### H6 progress (ARENA3, 2026-07-20)

| Item | Status |
|------|--------|
| H6.1 determinism workflow | present + lock |
| H6.3 GAP-1 RequireSigned | verify_authentic locks |
| H6.4 migration bounds | migration_report locks |
| H6.2 ceremony F1–F5 | checklist present (ceremony-day) |
| H6.5 chaos | snapshot_chaos / chaos suites |

---

### Gorev H7 — Supply chain ve CI sertliği

| # | İş | Kabul |
|---|-----|--------|
| H7.1 | cargo-audit / deny / gitleaks | Fail on high |
| H7.2 | SBOM artifact her main push | CycloneDX |
| H7.3 | Actions SHA-pin | zizmor/actionlint |
| H7.4 | Dependabot: yalnız patch + CI-yeşil (mainnet öncesi freeze) | Politika STATUS'ta |
| H7.5 | Coverage ratchet (azalmaya RED) | baseline bilinçli yükselir |
| H7.6 | Semver-checks / doc -D warnings | Job yeşil |
| H7.7 | Rozet botu | Badge ≠ sahte test sayısı; PAT sağlığı |

**Kapı G7:** H7.1–H7.6 yeşil.

### H7 progress (ARENA3, 2026-07-20)

| Item | Status |
|------|--------|
| H7.1–H7.3 deny/gitleaks/CI pins | structural locks |
| H7.5 coverage ratchet file | numeric baseline lock |
| H7.6 miri/semver/doc | existing workflows |
| H7.4 dependabot freeze | policy in STATUS/mainnet docs |

---

### Gorev H8 — Operasyon, tatbikat, dış denetim, bounty

| # | İş | Kabul |
|---|-----|--------|
| H8.1 | PRODUCTION_RUNBOOK tatbikatı | Tarihli kayıt (MR-9) |
| H8.2 | Backup/restore drill | ops script + log |
| H8.3 | Incident response | SECURITY.md + runbook link |
| H8.4 | Bug bounty | SECURITY ↔ BUG_BOUNTY; tier tablosu (MR-8 hazırlık) |
| H8.5 | Harici audit paket | AUDIT_CHECKLIST dolu + SBOM + threat model |
| H8.6 | Validator onboarding | docs/operations/VALIDATOR_ONBOARDING |
| H8.7 | Monitoring/alerts | metrics + örnek Prometheus |

**Kapı G8:** H8.1+H8.2+H8.4 yeşil · H8.5 audit başlatma kararı (§11 K4).

### H8 progress (ARENA3, 2026-07-20)

| Item | Status |
|------|--------|
| Docs: runbook, bounty, audit checklist, validator onboarding | present + lock |
| H8.1/H8.2 live drills | ceremony/ops day (not auto-claimed) |
| H8.5 external audit kickoff | user decision K4 |

---

### Gorev H9 — Sürekli sertleştirme (asla "bitti" sayılmaz)

Mainnet sonrası da yürür:

| Ritim | İş |
|-------|-----|
| Her PR | Diff threat review (bridge/consensus/crypto = ikinci göz) |
| Her main push | Zorunlu CI seti |
| Haftalık | Fuzz corpus growth raporu; yeni crash triyajı |
| Sprint sonu | Açık 🔴/🟡 sayımı; ratchet coverage |
| Olay sonrası | Postmortem → yeni regresyon kilidi → protokol revizyonu |

---

## 4. Anlık bulgu envanteri (protokol t0 — 2026-07-20)

> Bu tablo **canlıdır**. Her kapanışta STATUS_ONLINE + bu satır güncellenir.
> Kaynak: ARENAS/ARENAX denetimleri + kod teyidi. "Fixed" iddiası CI+test olmadan ✅ olmaz.

### 4.1 🔴 Kritik — H1 hedefi

| ID | Konu | Kod teyidi (t0) | H1 aksiyon |
|----|------|-----------------|------------|
| V89 | Non-escrowed payment remove | **FIXED:** settle-immediate receipt; payment_id consumed | teyit CI |
| V86 | Release/reclaim path | Tx tipleri + executor var — **uçtan uca fund test teyidi** | Teyit + kilitle |
| V24 | Bridge root scope | `bridge.rs` root() transfer alanlarını içeriyor | Teyit testi + kapat |
| V37/V38 | PoS answer / merkle | VerifyMerkle production-gated; interim challenge | K2 karar + MR-3 plan |
| V95 | Reorg state sync | Fix claim var | Regresyon kilidi teyit |
| V106 | sweep refund | Fix claim var | Regresyon kilidi teyit |
| V110 | VerifyInference stub | Disabled/fail path | Teyit + mainnet gate |
| V116 | Proto payment types | Enum+decode fix serisi | Roundtrip test teyit |
| V119 | Sync committee threshold | Threshold sayımı var | Test teyit |

> **2026-07-20 ARENA3 doğrulama turu (kod + regresyon kilidiyle):**
> V89 / V86 / V24 / V95 / V106 / V110 / V116 / V119 — hepsi **✅ FIXED teyit edildi**
> (her biri güvenlik özelliğini iddia eden isimli testle; V24 transfer+replay kapsamı dahil).
> V37/V38 — bilinçli mainnet sınırı (K2 + MR-3, kapatılamaz). Tam kanıt:
> `docs/ARENA3_SECURITY_VERIFICATION_AUDIT_2026-07-20.md`. Bu tur sonrası §4.1'de
> kapatılabilir 🔴 kalmadı; eski STATUS tablolarındaki "V24 🔴 Açık" işaretleri stale'dir.

### 4.2 Bilinçli mainnet sınırları (iddia etme)

| Konu | Durum | İbare yasağı |
|------|--------|--------------|
| VerifyMerkle 64-depth soundness | Production gate kapalı / experimental | "full PoS" / "64-depth ready" |
| BLS/PQ vendor HSM | Mock + PKCS#11 Ed25519 | "HSM production complete" |
| Harici audit | Başlamadı | "audited" |
| EVM receipt full verify | Kısmi / stub riski | "trustless ETH bridge" |

---

## 5. ADIM çalışma birimi şablonu

Her sertleştirme ADIM'ı STATUS_ONLINE'da şu formatta açılır/kapanır:

```markdown
### [TS] ARENAx — HARDEN ADIM-N: <başlık>
**Gorev:** H1..H9
**Kapsam:** <dosya/modül>
**Bulgu ID:** Vxx / yeniyse NEW-...
1. Ne bitti: <davranış>
2. CI kanıtı: SHA + run id
3. Regresyon kilidi: <test adı>
4. Ne bekliyor: ...
5. Kim karar verecek: ...
```

**ADIM bitiş checklist (zorunlu):**

- [ ] `cargo fmt --check`
- [ ] `cargo clippy -D warnings` (core + budzero)
- [ ] İlgili testler + mümkünse full lib
- [ ] Negatif test (saldırı senaryosu)
- [ ] STATUS 4 satır kapanış
- [ ] CI SLEEP yeşil

---

## 6. Regresyon kilidi standardı

Bir 🔴/🟡 kapanışı ancak şu üçlü ile "kapalı" sayılır:

1. **Fix** (minimal, davranış net)
2. **Pozitif test** (happy path)
3. **Negatif test** (saldırı / eski bug repro RED)

İsimlendirme önerisi:

- `v89_non_escrowed_payment_id_not_reusable`
- `v24_forged_transfer_changes_bridge_root`
- `v119_single_pubkey_insufficient_for_sync_aggregate`

Mümkünse `src/tests/regression_lock.rs` veya modül `#[cfg(test)]` altında
`// REGRESSION: Vxx — silme` marker'ı.

---

## 7. Kod review / merge kapıları

| Değişen path | Ek kural |
|--------------|----------|
| `consensus/`, `chain/blockchain.rs`, `execution/` | İkinci ajan veya kullanıcı diff özeti onayı |
| `cross_domain/`, `bridge*` | Replay + root test zorunlu |
| `crypto/`, `budzero/` | Clippy -D + mümkünse miri |
| `rpc/`, `network/` | Auth default ve DoS limiti gözden geçir |
| `.github/workflows/` | actionlint; pipefail; secret yok |
| `proto/` | Encode/decode roundtrip test |

Kendi PR'ını merge eden ajan STATUS'ta gerekçe yazar (Madde 17).

---

## 8. Red team turu (periyodik)

Her H1 ve H2 kapısından önce kısa red-team:

1. **Fund drain:** bridge, escrow, fee, reclaim
2. **Finality forge:** QC, sync-committee, PoW legacy
3. **State lie:** snapshot, root scope, reorg
4. **Auth bypass:** RPC, PoA sızması, relayer
5. **DoS:** msg size, mempool, peer fill
6. **Crypto oracle:** timing, verify stub

Çıktı: yeni V-ID veya "tur temiz" kaydı (SHA + tarih).

---

## 9. Metrikler (haftalık STATUS özeti)

| Metrik | Hedef (sertleştirme bitişi) |
|--------|-----------------------------|
| Açık 🔴 | 0 |
| Açık 🟡 FIX-NOW | 0 |
| CI zorunlu job | %100 yeşil (3 ardışık main) |
| Fuzz nightly crash | 0 (7 gün) |
| Coverage ratchet | düşmez; consensus/cross_domain/crypto → %90 (MR-5) |
| Regresyon kilidi sayısı | her kapanan 🔴 için ≥1 |
| Sahte-yeşil olay | 0 |

---

## 10. ARENA görev sınırları (sertleştirme dönemi)

| Ajan | Birincil | Sertleştirme odağı |
|------|----------|-------------------|
| **ARENA1** | cross_domain, bridge, EVM | H1.B, H5 bridge-facing, light-client |
| **ARENA2** | chain, execution, snapshot, rpc | H1.A/D, H6, V89 |
| **ARENA3** | CI, fuzz, crypto/HSM, budzero | H0, H3, H4, H7, V37/V38/MR-3, protokol bakımı |
| **ARENAX/S** | sürekli denetim | Yeni V-ID, teyit, red-team |

Kesişim: STATUS'ta ilan + sahip onayı.

---

## 11. Kullanıcı karar kapıları (bloklayıcı)

| # | Karar | Varsayılan (karar yoksa) |
|---|--------|---------------------------|
| **K1** | V89: non-escrowed payment yasak mı, yoksa kalıcı settlement kaydı mı? | FIX-NOW: non-escrowed'da registry kaydı silinmez; settled flag |
| **K2** | VerifyMerkle mainnet v1 zorunlu mu? | v1: gate kapalı + interim PoS iddiası yok; economic slashing |
| **K3** | HSM vendor (YubiHSM / Thales / CloudHSM)? | PKCS#11 Ed25519 only; BLS/PQ mock mainnet dışı |
| **K4** | Harici audit firması / zamanı | Audit paketi hazırla; kickoff kullanıcı |
| **K5** | Relayer model teyidi | Permissionless + stake (CLAUDE.md) — whitelist YASAK |
| **K6** | Bug bounty public launch | SECURITY+BUG_BOUNTY metin hazır; launch kullanıcı |

---

## 12. Mühür: "Tam sertleştirilmiş" checklist

Hepsi ✅ olmadan ibare kullanılmaz:

- [ ] **G0** yeşil zemin
- [ ] **G1** açık 🔴 = 0 + kilitler
- [ ] **G2** 🟡 triyaj kapalı
- [ ] **G3** fuzz/chaos
- [ ] **G4** crypto/HSM politikası
- [ ] **G5** network/RPC
- [ ] **G6** snapshot/genesis
- [ ] **G7** supply chain
- [ ] **G8** ops tatbikat + bounty hazır
- [ ] **MR-1..MR-10** (`MAINNET_READINESS.md`) ile hizalı
- [ ] **Ayaz nihai onayı**
- [ ] Son red-team turu temiz (tarihli)

---

## 13. İlk 10 ADIM (hemen uygulanacak sıra)

> Task 11.2 tamam iddiası sonrası pratik kuyruk. ARENA3 önerisi.

| ADIM | Gorev | İş | Çıktı |
|------|-----|-----|--------|
| **S0** | H0 | Main CI yeşil teyit + bu protokolü merge | G0 |
| **S1** | H1 | V89 kararı uygula + regresyon kilidi | 🔴-1 |
| **S2** | H1 | V86 uçtan uca fund conservation testleri | teyit |
| **S3** | H1 | V24/V106/V95/V119/V116/V110 teyit kilitleri | envanter güncelle |
| **S4** | H1 | Executor `current_block` tek kaynak (release/reclaim epoch_index*100 riski) | tutarlı height |
| **S5** | H2 | RPC mutate surface audit + default auth | rapor+fix |
| **S6** | H3 | Fuzz nightly 7 gün izleme + crash triage rutini | H3.2 |
| **S7** | H5 | Eclipse: per-subnet connection bound | test |
| **S8** | H4 | Mainnet disk-key fail-closed negatif test tarama | H4.1 |
| **S9** | H8 | Runbook tatbikat + bounty metin senkron | MR-8/9 hazırlık |
| **S10** | H7/H0 | Coverage modül % raporu; consensus/cross_domain/crypto borcu | MR-5 plan |

---

## 14. Anti-patternler (görülürse incident)

| Anti-pattern | Doğru davranış |
|--------------|----------------|
| "Test geçti, merge" (CI kırmızı) | CI yeşil olmadan üzerine iş yok |
| Stub verify → Ok(()) | Fail-closed veya experimental |
| Bulgu kapatmadan "mainnet ready" | MR + G mühür |
| PoA listesini validator registry ile birleştirme | Ayrı yapı |
| Coverage baseline düşürme | Yalnız bilinçli PR + gerekçe |
| Fuzz crash'i ignore | Corpus + fix |
| STATUS'a kanıtsız "tamam" | SHA + run |
| Aynı anda 3 büyük özellik + fix | Önce 🔴 |

---

## 15. Belge bakımı

- Bu dosya **her gorev kapısında** revize edilir (tarih + SHA).
- Yeni V-ID sınıfları §2 haritasına bağlanır.
- Protokol ihlali STATUS'ta `HARDEN-INCIDENT` olarak işlenir; silinmez.

---

## 16. Referanslar

| Belge | Rol |
|-------|-----|
| `CLAUDE.md` | Permissionless + PoA izolasyon anayasası |
| `docs/mainnet-hazirligi-talimati.md` | 18 maddelik mainnet listesi |
| `docs/MAINNET_READINESS.md` | MR-1..10 |
| `docs/THREAT_MODEL.md` | Tehdit modeli |
| `docs/AUDIT_CHECKLIST.md` | Dış audit paketi |
| `docs/BUDLUM_TASK11.md` | V-bulgu sprint planı |
| `docs/NETWORK_HARDENING_SPEC.md` | Ağ |
| `docs/operations/*` | Runbook, HSM, ceremony |
| `SECURITY.md` / `docs/BUG_BOUNTY.md` | Raporlama / bounty |
| `docs/STATUS_ONLINE.md` | Canlı koordinasyon |

---

*Co-authored-by: ARENA3 <arena3@budlum.xyz>*
