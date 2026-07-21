# Status Online 2 — Aktif iletişim kanalı (AI birliği)

**Amaç:** AI'ların anlık olarak ne yaptığını, ne yapacağını, karar taleplerini ve engelleri burada paylaşması.
**Eski kanal:** `docs/archive/STATUS_ONLINE.md` (189 KB, 2026-07-17'ye kadar) + `docs/archive/STATUS_ONLINE_2026-07-16.md` (272 KB).

**Format:** timestamp'li ve AI-handle imzalı. Eski entry "resolved" notuyla kalır (audit trail).

**Yazan:** ARENA1, ARENA2, ARENA3, ARENAX
**Okuyan:** tüm AI'lar + kullanıcı

---

## [2026-07-19 00:38 UTC+3] ARENA2 — P5 ADIM7 WIP: Security Hardening (B18-B21) + V38 Domain Separation Fix

**Durum:** Commit `e54390c` yerel — merge conflict çözümü + push bekliyor
**Kapsam:** P5 AI Inference derinleştirme — 4 yeni bulgu + 16 yeni test

**ADIM7 Bulgular:**
- **B18:** Equivocation event recording — `(request_id, verifier)` çiftleri on-chain kayıt (`equivocation_events: BTreeSet`). Gelecek slashing hook'ları için temel. Accessor: `has_equivocated()`, `equivocation_count_for_verifier()`
- **B19:** State root domain separation (ARENAX V38 fix) — her map'e unique domain prefix: `BDLM_AI_MODELS/REQUESTS/RESULTS/OUTCOMES/RECLAIMED/EQUIVOCATIONS/CANCELLED`. Root version V1→V2.
- **B20:** Model version auto-increment — `update_model_spec` her çağrıda `version` otomatik artar. On-chain audit trail.
- **B21:** Request cancellation — requester deadline öncesi iptal edebilir. Escrowed `max_fee` iade. İptal edilen request'lere result gönderilemez.

**Yeni transaction tipleri:**
- `AiModelReactivate` (id=25) — deaktive modeli yeniden aktive eder
- `AiRequestCancel` (id=26) — pending request iptal + fee refund

**Yeni RPC:**
- `bud_aiEquivocationStatus(request_id, verifier)` → `has_equivocated`
- `bud_aiCancelStatus(request_id)` → `is_cancelled`

**Yeni ChainActor komutları:** `GetAiEquivocationStatus`, `GetAiCancelStatus`

**Lokal doğrulama:** `cargo check` ✅ | `cargo fmt --check` ✅ | `cargo clippy -D warnings` ✅
**Bekleyen:** origin/main merge (V29 signature_version conflict çözümü) → push → CI SLEEP

**Engel:** ARENA3 V29 signing değişiklikleri Transaction struct'ına `signature_version` eklemiş — proto_conversions.rs'de 9 compile error var. Merge sonrası çözülecek.

Co-authored-by: ARENA2 <arena2@budlum.ai>

---

## [2026-07-19 05:32 UTC+3] ARENA2 — P5 ADIM5-8 PUSHED: AI Settlement Layer Deepening (B14-B24) + origin/main merge

**Durum:** Pushed SHA `4bb0be7`, CI SLEEP (Run 29670336340 CI)
**Kapsam:** P5 AI Inference ADIM5-8 toplu merge — 11 bulgu + 50+ test + origin/main 3 tur conflict resolution

**ADIM5 Bulgular:**
- **B14+B17:** ZKVM fee leak fix — max_fee escrow on submit_request success
- **B16:** Reward distribution remainder — first verifier gets extra unit

**ADIM6:**
- ARENA2-T1 F06 edge-case test matrix (29 tests)

**ADIM7 Bulgular:**
- **B18:** Equivocation event recording (BTreeSet<(AiRequestId, [u8;32])>)
- **B19:** State root domain separation V2 (ARENAX V38)
- **B20:** Model version auto-increment on update_model_spec
- **B21:** Request cancellation (cancel_request + AiRequestCancel tx)

**ADIM8 Bulgular:**
- **B22:** AI outcome settlement root — `ai_root: Option<Hash32>` in GlobalBlockHeader, V3 tag. ConsensusKind::AiInference domain with is_ai() and as_bytes()
- **B23:** Dispute slashing — `slash_equivocator()` + `AiDisputeSlash` tx (id=27) + executor slashing (validator.stake=0, active=false, slashed=true)
- **B24:** Signature verification hook prepared (structural, calculate_signing_hash exists)

**Conflict Resolution (3 tur):**
- Tur 1: aa87b8f → 74a2b3a (V29 signing, poa_isolation, EVM F10.1/F10.2)
- Tur 2: 74a2b3a → 4720f8e (migration v3→v4, module READMEs)
- Tur 3: 4720f8e → 89ea451 → a8df2a9 (V19 fail-loud, F14 grace-period, snapshot_chaos)
- Strateji: origin/main base kabul + ARENA2 AiDisputeSlash eklemeleri

**Lokal doğrulama:** `cargo check` ✅ | `cargo fmt --all` ✅ | `cargo clippy -D warnings` ✅

Co-authored-by: ARENA2 <arena2@budlum.ai>

---

## [2026-07-19 10:46 UTC+3] ARENA2 — P5 ADIM9 CI-PROVEN: Dispute Window (B25) + Verifier Stake (B26)

**Durum:** CI-yeşil — SHA `061ef3e` (ADIM9 commit `ca9e49a` ancestor), CI Run `29672884497` Budlum Core ✅
**Kapsam:** P5 AI Inference ADIM9 — 2 yeni bulgu + 11 yeni test

**ADIM9 Bulgular:**
- **B25:** Dispute window enforcement — `DISPUTE_WINDOW_BLOCKS = 10_080` (≈7 days). Equivocation events expire after window, `slash_equivocator` enforces window, `is_disputable()` + `expire_dispute_window()` added. `equivocation_events` changed from `BTreeSet` to `BTreeMap<(AiRequestId, [u8; 32]), u64>` — value is block number when detected.
- **B26:** AI verifier stake registry — `MIN_VERIFIER_STAKE = 1_000`. `lock_verifier_stake`, `withdraw_verifier_stake` (blocked during pending disputes), `is_staked_verifier`, `verifier_stake`. `slash_equivocator` now returns `(Address, u64)` — seized stake burned. State root V3 with `BDLM_AI_VERIFIER_STAKES` domain.

**CI kanıtı:** SHA `061ef3e` CI Run `29672884497` — Format ✅ Clippy ✅ Test ✅ Doc ✅
- `bef9e04`'teki kırmızılık ARENA3 `snapshot_chaos.rs` dyn Serialize hatası idi, `3d00fe7`'de düzeltildi
- ADIM9 kodumuz temiz — sonraki commit'lerde CI geçti

**Ne bekliyor:** ADIM10 (B27 + B28) — Dispute Resolution RPC + Outcome Callback Execution
**Kim karar verecek:** ARENA2 (devam) / Ayaz (önemli tasarım kararları)

Co-authored-by: ARENA2 <arena2@budlum.ai>

---

## [2026-07-19 11:36 UTC+3] ARENA2 — P5 ADIM10 CI-PROVEN: Dispute Resolution RPC (B27) + Outcome Callback Execution (B28)

**Durum:** CI-yeşil — SHA `a2f8faa`, CI Run `29679216358` Budlum Core ✅
**Kapsam:** P5 AI Inference ADIM10 — 2 yeni bulgu + 9 yeni test + 4 yeni RPC

**ADIM10 Bulgular:**
- **B27:** Dispute Resolution RPC — `bud_aiDisputeSlash` (tx template + pre-validation), `bud_aiSlashingStatus` (comprehensive dispute info), `bud_aiVerifierStake` (stake + equivocation count). `AiDisputeStatusInfo` + `AiVerifierStakeInfo` response types. Dispute slash validates equivocation + dispute window before preparing tx.
- **B28:** Outcome Callback Execution — `callback_queue: BTreeMap<Address, Vec<AiCallbackEvent>>` in AiRegistry. When outcome finalized with non-empty callback, `AiCallbackEvent` queued. `bud_aiCallbackQueue` RPC for off-chain delivery. `consume_callback_events` for ACK-based consumption. State root V3 domain `BDLM_AI_CALLBACK_QUEUE`.

**Yeni RPC endpoint'leri (4):**
- `bud_aiDisputeSlash` — Prepare dispute slash tx with status pre-check
- `bud_aiSlashingStatus` — Query dispute window + equivocation + stake info
- `bud_aiVerifierStake` — Query verifier stake amount + equivocation count
- `bud_aiCallbackQueue` — Query pending callback events for an address

**Yeni ChainActor komutları:** `GetAiDisputeStatus`, `GetAiVerifierStake`, `GetAiCallbackQueue`

**CI kanıtı:** SHA `a2f8faa` CI Run `29679216358` — Format ✅ Clippy ✅ Test ✅ Doc ✅
- İlk push'ta `Result::is_some()` compile hatası vardı, düzeltildi
- İkinci push'ta `multiple_callbacks_same_address` test hatası (aynı request_id çakışması), farklı submitted_at_block ile düzeltildi

**P5 Toplam:** 10 ADIM, 28 bulgu, ~90+ test

**Ne bekliyor:** B15 (ZKVM model_id partial fill — tasarım kararı), AI-specific finality adapter, verifier whitelist
**Kim karar verecek:** Ayaz (B15 tasarım kararı + AI finality adapter)

Co-authored-by: ARENA2 <arena2@budlum.ai>

---

## [2026-07-19 14:03 UTC+3] ARENA2 — P5 ADIM11 CI-PROVEN: AI Execution Proof (B29) + Verifier QoS (B30)

**Durum:** CI-yeşil — SHA `93aae87`, CI Run `29684010494` Budlum Core ✅ (14/14 jobs green, 964 passed, 0 failed, 1 ignored)
**Kapsam:** P5 AI Inference ADIM11 — 2 yeni bulgu + 9 yeni test + 3 yeni RPC + 3 yeni ChainActor command

**ADIM11 Bulgular:**
- **B29: AI Execution Proof** — ZKVM-based verifiable inference primitive. `AiExecutionProof` struct: model_id, input_commitment, output_commitment, program_hash, proof_bytes, steps, gas_used. `commitments_match()` structural verification. `calculate_leaf()` domain-separated hash (BDLM_AI_EXEC_PROOF_V1). `attach_execution_proof()` binds proof to (request, verifier) with commitment validation. `get_execution_proof()`, `has_execution_proof()` query methods. `execution_proofs: BTreeMap<(AiRequestId, [u8; 32]), AiExecutionProof>` in AiRegistry with BDLM_AI_EXEC_PROOFS domain in state root.
- **B30: Verifier QoS** — Quality of Service reputation tracking for Agentic Economy. `AiVerifierQos` struct: total_results_submitted, successful_finalizations, equivocation_count, avg_response_blocks, last_active_block. `record_result()`, `record_finalization()`, `record_equivocation()` metric trackers. `reliability_score()`: finalization_rate × (1 - equivocation_penalty). `calculate_leaf()` domain-separated hash (BDLM_AI_VERIFIER_QOS_V1). QoS recording integrated into submit_result/finalization/equivocation flows. `verifiers_by_reliability()` ranking for QoS-aware verifier selection.

**Yeni RPC endpoint'leri (3):**
- `bud_aiExecutionProof(request_id, verifier)` → proof details + trustless flag
- `bud_aiVerifierQos(verifier)` → QoS metrics + reliability_score + finalization_rate
- `bud_aiVerifierRanking()` → all verifiers ranked by reliability (descending)

**Yeni ChainActor komutları (3):**
- `GetAiExecutionProof { request_id, verifier, response }`
- `GetAiVerifierQos { verifier, response }`
- `GetAiVerifiersByReliability(oneshot)`

**Yeni testler (9):**
- `test_p5_adim11_attach_execution_proof` — happy path proof attachment
- `test_p5_adim11_execution_proof_wrong_commitment_rejected` — output_commitment mismatch
- `test_p5_adim11_execution_proof_no_result_rejected` — no result exists
- `test_p5_adim11_verifier_qos_recorded_on_result` — QoS on result submission
- `test_p5_adim11_verifier_qos_finalization_recorded` — finalization increments
- `test_p5_adim11_verifier_qos_equivocation_recorded` — equivocation penalty
- `test_p5_adim11_verifier_qos_reliability_score` — score calculation
- `test_p5_adim11_execution_proof_changes_state_root` — proof affects state root
- `test_p5_adim11_qos_changes_state_root` — QoS affects state root

**Ek düzeltmeler (V58 regression):**
- `storage_deal.rs`: 4 test `ContentId([0u8; 32])` → `ContentId([1u8; 32])` (V58 zero-hash guard)
- `rpc/tests.rs`: answer_msg signature hash `[0u8; 32]` → `[0xAA; 32]` + `_range_hash` sync

**CI kanıtı:** SHA `93aae87`, CI Run `29684010494` — 14/14 ✅
- İlk push `a25cb54`: E0422 compile error (AiExecutionProof/AiVerifierQos not in pub use) → fix `32fa6c3`
- İkinci push `9fda0c0`: V58 storage_deal test regression (5 FAILED) → fixed ContentId + signature sync
- Üçüncü push `93aae87`: Full green ✅

**P5 Toplam:** 11 ADIM, 30 bulgu, 964 test (CI-kanitli)

**Ne bitti:** B29 ZKVM execution proof type + registry + RPC, B30 Verifier QoS tracking + reliability scoring + ranking RPC, V58 regression fix
**CI kanıtı:** SHA `93aae87` + CI Run `29684010494` (14/14 ✅, 964 passed)
**Ne bekliyor:** B31 Agent-to-Agent Payment primitive, ZKVM ISA AI opcode tasarımı, verifier whitelist
**Kim karar verecek:** Ayaz (B31 tasarım kararı + ZKVM opcode + vizyon hizalaması)

Co-authored-by: ARENA2 <arena2@budlum.ai>

---

## [2026-07-20 21:45 UTC+3] ARENA2 — BudL FieldAccess Type-Aware Correctness Fix (bud-compiler codegen)

**Problem:** codegen `FieldAccess`, struct alanı offset'ini TÜM struct layout'larını tarayıp alan adıyla eşleşen İLK struct'tan alıyordu. İki struct aynı alan adını farklı pozisyonda tanımlıyorsa → yanlış offset + hash-map iteration order belirsizliği → yanlış memory word (sessiz veri bozulması).

**Çözüm:** `VarInfo { reg, struct_type }` — her değişkenin struct tipi `let` binding'lerinde (literal/alias) ve struct tipli parametrelerde kaydedilir (sema'nın `Type::Struct(name)` türetmesinin codegen yansıması). `FieldAccess` artık base ifadenin gerçek layout'unda offset çözer; çözülemeyen base (iç içe `a.b.c`) eski taramaya düşer → doğrulanmış davranış değişmez. Public API (`compile()`) aynı.

**Testler (2 yeni, negatif-doğrulamalı — eski kodda FAIL, yeni kodda PASS):**
- `test_field_access_resolves_correct_layout_on_name_collision` — eski kod `[222,444]`, doğru `[111,444]`
- `test_field_access_on_struct_parameter_uses_param_type` — eski kod `[7,9]`, doğru `[7,10]`

**Yerel doğrulama:** bud-compiler 16/16 ✅ · clippy `-D warnings` temiz ✅ · fmt temiz ✅ · downstream `bud-cli` derleniyor ✅

**Ne bitti:** FieldAccess tip-farkındalıklı offset çözümü + 2 regresyon testi; PR #99 açıldı (base: main)
**CI kanıtı:** PR #99 head `61eea8d` — **22/22 check YEŞİL ✅** (ana CI run `29769236837` + Determinism `29769237051` / Miri `29769236927` / Semver `29769236969` / Benchmark `29769236895` / DockerSmoke `29769236807` tümü success). Kritik: BudZero/BudZKVM ✅, Budlum Core ✅, Miri UB (budzero) ✅, Semver ✅ (public API aynı), Coverage ratchet ✅, Cross-Platform Determinism (mac+ubuntu) ✅, Fuzz ✅
**Ne bekliyor:** PR #99 CI YEŞİL — merge onayı (Ayaz) / main stabil olduğunda merge; follow-up bulgu: StructLiteral alan-sırası/tanım-sırası uyumu
**Kim karar verecek:** Ayaz (merge onayı) / CI (tek yargıç)

Co-authored-by: ARENA2 <arena2@budlum.ai>

---

## [2026-07-20 22:35 UTC+3] ARENA2 — BudL StructLiteral Declared-Offset Fix (PR #99 devamı)

**Problem:** `StructLiteral` codegen'i alanları **literal'deki yazılış sırasıyla** (`i*8`) depoluyordu, `FieldAccess` ise **tanım sırasıyla** okuyordu. Literal alanları tanımdan farklı sırada yazılınca değerler sessizce takas oluyordu (veri bozulması); sema alan sırasını denetlemiyor. Örnek: `Point{y:20,x:10}` → eski kod `p.x=20, p.y=10`.

**Çözüm:** Her alanın **tanım offset'ini** struct layout'undan çöz → oraya depola (literal sırası önemsiz; StructLiteral+FieldAccess aynı doğruluk kaynağı). Heap'i **tanım boyutu** kadar büyüt. Bilinmeyen alan → pozisyonel slot + codegen hatası (derinlik savunması). PR #99'un üzerine stacked; base sonradan `main`'e alındı (CI tetiklensin; #99 merge sonrası diff küçülür).

**Testler (2 yeni, negatif-doğrulamalı — eski kodda FAIL, yeni kodda PASS):**
- `test_struct_literal_field_order_independent_of_declaration` — eski `[20,10]`, doğru `[10,20]`
- `test_struct_literal_reordered_through_function_param` — eski `[1,6]`, doğru `[2,6]`

**Yerel doğrulama:** bud-compiler 18/18 ✅ · clippy `-D warnings` temiz ✅ · fmt temiz ✅ · downstream `bud-cli` derleniyor ✅

**Ne bitti:** StructLiteral tanım-offset'i depolama + 2 regresyon testi; PR #100 açıldı (base: main, #99 üstüne stacked — merge sırası: önce #99)
**CI kanıtı:** PR #100 head `37f8cd7` (yeşil main `0fb0942` merge'lü) — **20+ check YEŞİL ✅, 0 kırmızı** (ana CI run `29781683722`; Budlum Core / docker-smoke / Coverage / Devnet / BudZero / Miri / Determinism / Semver tümü success; Genesis+Fuzz hâlâ koşuyor, kırmızı yok). Not: önceki kırmızılık main'deki duplike `spin` Cargo.lock parse hatasıydı — ARENA3 `709c356 fix(deps): remove duplicate spin lock entry` ile düzeltti; yeşil main merge edilince #100 tam yeşile döndü.
**Ne bekliyor:** PR #99 + #100 CI YEŞİL — merge onayı (Ayaz); merge sırası: önce #99, sonra #100; follow-up: partial-literal (sema eksik alana izin veriyor)
**Kim karar verecek:** Ayaz (merge sırası/onayı) / CI (tek yargıç)

Co-authored-by: ARENA2 <arena2@budlum.ai>

---

## [2026-07-21 00:15 UTC+3] ARENA2 — BudL Partial-Literal Rejection (struct doğruluğu üçlemesi tamam)

**Problem:** sema, struct literal'ının verdiği her alanın struct'ta varlığını denetliyordu ama literal'ın **tüm** tanım alanlarını verdiğini denetlemiyordu. Eksik alanlı literal type-check geçiyordu; codegen tam bloğu ayırıp eksik alanı offset'inden **uninitialized** okuyordu → VM'de belirsiz davranış (sessiz çöp/sıfır okuma).

**Çözüm:** sema artık struct literal'ında **tüm tanım alanlarını zorunlu kılıyor** (fail-fast, Rust'ın exhaustive struct literal'ı gibi; gelecekte `..default` ile gevşetilebilir). Tam literaller (her sırayla) derlenmeye devam ediyor.

**Testler (2 yeni, negatif-doğrulamalı — checksiz kodda partial literal DERLENİYOR/test FAIL, check ile PASS):**
- `test_struct_literal_missing_field_rejected` — `Point{x:10}` (y eksik) → SemanticError "missing field y"
- `test_struct_literal_with_all_fields_compiles` — tam literal derleniyor + çalışıyor (30)

**Güvenlik:** repo'da partial literal kullanan BudL kodu yok (.bud corpus struct'sız; bud-compiler testleri tam literal) → başka bir şey etkilenmiyor.

**Yerel doğrulama:** bud-compiler 20/20 ✅ · clippy `-D warnings` temiz ✅ · fmt temiz ✅ · downstream `bud-cli` derleniyor ✅

**Ne bitti:** Partial-literal reddi (sema) + 2 test; struct-doğruluğu üçlemesi tamam (#99 FieldAccess → #100 sıralama → bu: eksik alan)
**CI kanıtı:** PR #102 head `9870928` — **20+ check YEŞİL ✅, 0 kırmızı** (ana CI run `29783801320`; BudZero/BudZKVM, Budlum Core, docker-smoke, Coverage, Devnet, Miri, Determinism, Semver tümü success; Fuzz+Genesis koşuyor, kırmızı yok)
**Ne bekliyor:** PR #102 CI YEŞİL — merge onayı (Ayaz); olası follow-up: duplike-alan literal denetimi (`A{x:1,x:2}`)
**Kim karar verecek:** Ayaz (merge onayı) / CI (tek yargıç)

Co-authored-by: ARENA2 <arena2@budlum.ai>

---

## [2026-07-21 01:00 UTC+3] ARENA2 — BudL Duplicate-Field Literal Rejection (struct hardening kapanışı)

**Problem:** sema, aynı alanı birden fazla kez başlatan struct literal'ını kabul ediyordu (`Point { x:1, y:2, x:3 }`). codegen her değeri alanın TEK tanım offset'ine depoladığı için duplike yazımlar çakışıyor ve **son değer sessizce kazanıyordu** — gizli, sıraya-bağımlı sonuç (programcı hatası).

**Çözüm:** sema duplike alan başlatıcılarını tespit edip net bir `SemanticError` ("Struct X literal initializes field Y more than once") ile reddediyor. Struct-literal sertleştirmesini tamamlıyor (#100 tanım-offset + #102 eksik-alan + bu: duplike-alan).

**Test (negatif-doğrulamalı — checksiz kodda duplike literal DERLENİYOR/test FAIL, check ile PASS):**
- `test_struct_literal_duplicate_field_rejected` — `Point{x:1,y:2,x:3}` → SemanticError "more than once" (x)

**Yerel doğrulama:** bud-compiler 21/21 ✅ · clippy `-D warnings` temiz ✅ · fmt temiz ✅ · downstream `bud-cli` derleniyor ✅

**Ne bitti:** Duplike-alan literal reddi (sema) + 1 test; struct-literal hardening TAM (#99→#100→#102→bu)
**CI kanıtı:** PR #103 head `38aaaa1` — **19+ check YEŞİL ✅, 0 kırmızı** (BudZero/BudZKVM, Budlum Core, docker-smoke, Devnet, Miri, Determinism tümü success; Coverage/Fuzz/Genesis koşuyor, kırmızı yok). Not: ilk head `0575068`'de Budlum Core *Format*'tan düştü — neden, main'e yeni gelen ARENA4 settlement commit'i (6d2c746) henüz rustfmt'lenmemişti; ARENA4 `16e695c` ile rustfmt'ledi, yeşil main merge edilince Format geçti (benim değişikliğimle ilgisiz).
**Ne bekliyor:** PR #103 CI YEŞİL — merge onayı (Ayaz)
**Kim karar verecek:** Ayaz (merge onayı) / CI (tek yargıç)

Co-authored-by: ARENA2 <arena2@budlum.ai>
