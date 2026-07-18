# Phase 9 — Rapor ↔ Vizyon ↔ Kod Çelişki Denetimi (ARENAX, 2026-07-17)

> **TR Özet:** Bu rapor kullanıcının ARENAX görev tanımının ilk kapanışıdır: raporlar ile Budlum vizyonu kodla çelişiyor mu, boşta/çalışmayan kod var mı, vaad edilen işlemler gerçekleşebiliyor mu. 16 vaat **kanıtlı doğrulandı**; 10 bulgu açık (2 büyük: Hard-Pruning anayasa kuralı kodsuz, MainnetActivation bayrağı ölü kod). `budlumdevnet` deposu 2026-07-11'den beri dokunulmamış (main `6613219a`). Her satır SHA / dosya:satır / CI-job kanıtı taşır; kanıtsız iddia yok.

**Denetçi:** ARENAX (AI birliği üye #4 — bağımsız denetim hattı)
**Baz:** `origin/main` @ `541a772` (CI tam-yeşil baz: `2acef45`, 13/13 ✅)
**Kapsam:** README/STATUS/rapor iddiaları ↔ kod; Constitution ↔ executor; RPC yüzeyi; fail-closed guard'lar; ölü kod taraması; süreç kullanılabilirliği
**Metod:** `git grep` / `git show` statik analiz + GitHub check-runs API + docs.rs crate kaynakları (sandbox'ta `cargo` yok — crates.io kapalı; CI zorunlu kanıt, STATUS.md kuralı)

---

## 1. Verified claims (claim → evidence, all on `541a772`)

| # | Claim (source) | Evidence | Verdict |
|---|---|---|---|
| V1 | `budlumdevnet` base code unchanged | `gh api repos/budlum-xyz/budlumdevnet` → main `6613219a`, last push 2026-07-11 21:11 UTC | ✅ |
| V2 | 7 storage RPC + `bud_storageOpenDeal`/`ActiveOperators`/economics (README) | `src/rpc/api.rs:272-365` trait + `src/rpc/server.rs:1395-1818` impl; CI "B.U.D. E2E Invariants (9/9 isim-kilitli)" ✅ @ `2acef45` | ✅ |
| V3 | Registry/prover RPCs permissionless | `api.rs:176-219` + `server.rs` impl; `src/tests/permissionless.rs` | ✅ |
| V4 | `budlum-core keygen --type ed25519` CLI (Dalga-3 claim) | `src/main.rs:237-296` | ✅ |
| V5 | Genesis JSON == code hash lock | `src/chain/genesis.rs:424` `test_mainnet_genesis_json_matches_code` (hash+state_root+validator_set_hash equality) | ✅ |
| V6 | Mainnet disk `ValidatorKeys` ban + genesis placeholder ban (fail-closed) | `src/crypto/primitives.rs:63,73,420-425`; `src/cli/commands.rs:877-881` (A1/A2 previously sealed, spot-re-verified) | ✅ |
| V7 | VerifyMerkle 1/2/64-depth positive tests active & green | `budzero/bud-proof/src/plonky3_prover.rs:2117,2179,2241` (no `#[ignore]`); BudZero job ✅ @ `2acef45` | ✅ |
| V8 | Faz 5 economics (reward accrual, slashed-bond ledger, events) | `src/chain/blockchain.rs:3419` `accrue_storage_operator_rewards`, `:3535` `finalize_missed_storage_challenges`, `:41-53` `StorageEconomicsEvent` | ✅ |
| V9 | Boost split = 4/16/80 (Constitution §3) | `src/execution/executor.rs:331-335` (4% bud, 16% creator, 80% protocol) — **hesap doğru; dağıtım F4'te** | ✅/⚠️ |
| V10 | Luminance starts at 1 cd; owner-only update | `src/nft/mod.rs:37` (`1000` mcd), `executor.rs:362-377` | ✅ |
| V11 | Fee per post (NftMint) | `executor.rs:288-299` (`balance -= tx.fee`) | ✅ |
| V12 | M4 BNS fee gate / M5 hub fee (Dalga-5 seals) | `executor.rs:222` `bns_insufficient_payment`; `executor.rs:492` `HUB_REGISTER_MIN_FEE=100`; `src/tests/relayer_gates.rs` regression | ✅ |
| V13 | Bootnode guard bypass (`c953049`) reverted | `893ffdc`: `chain_config.rs` back to `203.0.113.x` + `placeholder-seed-*`; guard wiring `src/main.rs:746-764` intact | ✅ (residual F7) |
| V14 | cryptoki 0.12 landed correctly + lock consistent | `6953bb9` (AuthPin/SecretString, `CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)`, `EddsaParams::new(EddsaSignatureScheme::Pure)`, `VendorDefinedMechanism::new::<()>`); `Cargo.lock` = cryptoki 0.12.0 / secrecy 0.10.3; Budlum Core ✅ | ✅ (my 0.6-revert `50b9ffb` superseded — §4 note) |
| V15 | Unjust-liveness-slash consensus bug found & fixed | `920e9fe` (epoch-close participation now looks back `EPOCH_LENGTH-1` producers, not just closing block) — union self-audit worked | ✅ |
| V16 | CI fully green at code HEAD | `2acef45` check-runs: 13/13 ✅ (Budlum Core, BudZero, Deny ×2, SBOM, Fuzz Quick, Timing, Secret, E2E, Coverage, Docker Sec, Repo Lint, Udeps, Geiger) | ✅ |

## 2. Open findings (revised against `541a772`)

| # | Finding | Evidence | Class | Suggested owner |
|---|---|---|---|---|
| F1 | **Constitution "Hard Pruning" not implemented.** `NftBurn` removes the NFT from registry and returns the CID; executor only *logs* `B.U.D. Hard Prune Triggered by NftBurn` — **no code deletes the storage content** (no `StoragePrune` command/worker anywhere: `git grep StoragePrune src/` → 0; no `remove_content`/`delete_content` in `src/storage/`). The log line actively claims a physical deletion that never happens. Constitution §1 ("NFT yakılırsa veri B.U.D. storage'dan fiziksel silinir") ↔ code contradiction. | `executor.rs:314-328` (esp. `:323`); `src/nft/mod.rs:80-95`; grep proofs | 🔴 vision↔code, misleading claim | ARENA1 (impl) + ARENAX (verify) |
| F2 | **`MainnetActivation` is dead code — "staged rollout" unenforced.** `5e8e59e` added the flag (`bud-isa/src/lib.rs:57-81`, `decode_for_mainnet:184-193`) with correct gate logic, but **zero callers** (`git grep MainnetActivation origin/main` outside `bud-isa/src/lib.rs` → 0). VM decodes via `decode_for_profile(Testing)` (tests) / `decode()`→Production (prod) — never `decode_for_mainnet`. Effective state: VerifyMerkle **is executable on mainnet today** (gate open since tests green, V7). Stale comment in `bud-vm/src/lib.rs:27` still says "VerifyMerkle disabled" in Production. Either wire the flag (mainnet config → VM decode) or drop it + write honest docs. | `5e8e59e`; `bud-vm/src/lib.rs:29-39`; grep proofs | 🔴 dead code / unkept promise | ARENA1 or ARENA3 (wire), else ARENAX docs |
| F3 | **Vendor-mechanism CLI surface not wired to signer.** `--pkcs11-bls-mechanism`/`--pkcs11-pq-mechanism` are parsed & merged from config (`src/cli/commands.rs:223-226, 434-436, 687-693`), `Pkcs11Signer::with_vendor_mechanisms` exists — but `src/main.rs:485` constructs the signer with `new()` only; mechanism IDs never reach it. "Vendor mechanism config support (c92125b)" promise is surface-only. Now that cryptoki 0.12 (V14) makes the vendor path real, wiring has become meaningful. | `commands.rs:687-693` vs `main.rs:485-505` | 🟡 dead plumbing | ARENA3 (HSM owner) |
| F4 | **Boost 4% B.U.D. share computed but never distributed.** Executor deducts full `amount` from booster, credits creator 16%; the remaining 84% (80% protocol + 4% B.U.D.) has **no destination** — implicit burn. Constitution §3 says "4% to B.U.D. (Storage Operators)". Either route `bud_share` to the storage-operator reward pool (`accrue_storage_operator_rewards` exists, V8) or document honestly that boost is 16% creator / 84% burn. | `executor.rs:329-359` | 🟡 vision↔code (accounting gap) | ARENA1 |
| F5 | **Genesis persistence errors silently swallowed.** `blockchain.rs:503-504` `let _ = store.insert_block(&genesis_block); let _ = store.save_last_hash(...)` — node boots and runs with an unpersisted genesis, no log. Also `:2843` (`save_last_hash` post-restore) and 267 total `let _ =` in `src/` (many benign; persistence paths deserve `tracing::error!` at minimum). Flagged by ARENA3 2026-07-16 (High) — still open. | `blockchain.rs:503-504, 2843`; `grep -rn "let _ = " src/ \| wc -l` → 267 | 🟡 error-swallowing | ARENAX can fix (small) |
| F6 | **Test-count prose stale.** Badge auto-updated to 538 (`541a772`), but `README.md:114` still says "531 unit/integration tests" and `docs/MAINNET_READINESS.md` §1 banner says 531. Bot refreshes the badge only; prose rots. | `README.md:8` vs `:114`; `MAINNET_READINESS.md:3` | 🟢 docs hygiene | ARENAX (next docs wave) |
| F7 | **Guard test strength regression (residual of V13).** Pre-`c953049` the guard test asserted the *compiled-in* mainnet constants were caught by `first_placeholder_peer`; `893ffdc` restored the constants but kept `c953049`'s weaker test (synthetic dummy lists only). Guard function + wiring are correct today, but a future constant-edit could silently evade the guard again. One-line restore recommended. | `chain_config.rs` `test_placeholder_peer_detection_blocks_dummy_mainnet_entries` | 🟢 test strength | ARENAX (with F5) |
| F8 | **CI design bug: `buf breaking` step fails on any non-main branch.** Step resolves `.git#branch=main` (ci.yml:442); on branch pushes there is no local `main` ref → step exits non-zero → Repo Lint red. Evidence: my branch `50b9ffb` Repo Lint ❌ (job 87812434426) with proto untouched; same step ✅ on main pushes. Fix: `--against '.git#branch=origin/main'`. Needs workflow edit — my token lacks `workflows` permission (push rejected when tried). | `ci.yml:436-446`; job 87812434426 | 🟡 CI | ARENA2 (CI owner) |
| F9 | **Genesis hash constant unasserted.** `config/mainnet.toml:5` documents `9bf07f9f…`; no test asserts the absolute value (only JSON==code equality, V5). `examples/print_genesis_hash.rs` exists — a CI assert or a GENESIS_FLIP_CHECKLIST cross-ref would seal it. Low risk (empty validators/allocations locked by tests). | `mainnet.toml:5`; `genesis.rs:409-421` | 🟢 verification gap | ARENA2 |
| F10 | **`#![allow(warnings)]` at crate root hides `dead_code` visibility.** User-decided (`lib.rs:1` comment); `#![forbid(unsafe_code)]` unaffected. Consequence: dead-code detection cannot rely on compiler warnings — this audit used manual grep instead. Noted as an audit-visibility constraint, not a rule violation. | `src/lib.rs:1-5` | ⚪ note | — |

## 3. Process usability assessment (görev sorusu: "tüm süreç kullanılabilir mi?")

- **Build/test loop:** CI is the only executable arbiter for agents without local Rust (this sandbox included). 13 gates green at `2acef45`; pipeline is usable and now includes canary-protected gates (udeps, geiger, coverage ratchet, zizmor, actionlint, buf, genesis schema, E2E name-lock). **Usable.**
- **Direct-main flow + branch protection:** works; today's red-chain (3 successive Format/Clippy reds: `9be811b`, `749d27f`/`c953049`, `dbc99b0`/`c69e1c0`) shows the recurring root cause is **pushing without local fmt/clippy** — KURAL 3 repairs landed within ~30-60 min each time. Recommendation (process, not code): a `scripts/pre-push-check.sh` (fmt+clippy+test the three commands from AI_BIRLIGI §4.9) referenced in CLAUDE.md for agents with local Rust.
- **Multi-agent coordination:** STATUS_ONLINE protocol worked (Aşama 1-2-3); my push as the 4th agent exposed two env gaps now documented: new-branch push from shallow clone triggers GitHub workflow-permission artifacts (fix: `git fetch --unshallow`), and the F8 branch-only CI bug.
- **Promise-tracking:** the strongest systemic risk found is **claims ahead of code** (F1 misleading log, F2 dead flag, F3 unwired surface, F4 undistributed share) — all four are small to fix but each is a "vaad edilen işlem gerçekleşmiyor" instance. MR-4 (claim-hygiene) should list F1-F4 explicitly.

## 4. Transparency notes (kural 4: hata kabulü)

1. My first push (`58d295a`, fmt-fix on `9be811b`) was rejected: new-branch push from a **shallow** clone packed the graft-root commit which "creates" `.github/workflows/ci.yml` → GitHub workflow-permission refusal. Fixed by `git fetch --unshallow`; STATUS.md §4.2's documented advice confirmed correct.
2. My `50b9ffb` reverted `749d27f` to cryptoki 0.6 (lock-matching, fmt-clean) as the emergency KURAL-3 repair. ARENA2 independently chose the better forward fix (`6953bb9`, real 0.12 port + lock update) ~25 min later. My revert is **superseded** and dropped from this branch; the branch was reset onto `541a772`. CI on `50b9ffb` had validated the revert path too (Budlum Core ✅, 12/13 — only F8 red).
3. Finding B2 of my first entry (`c953049` guard bypass) was independently resolved by ARENA1 (`893ffdc`) before my report landed — recorded as V13 with the F7 residual.

## 5. Questions to the user (karar noktaları)

- **Q-X1 (F1):** Hard Pruning implementasyonu — Phase 9 kapsamında `NodeCommand::StoragePrune` + NftBurn→shard-silme yolu + dürüst log mu yapalım (önerim), yoksa Constitution'a "şimdilik registry-silme, fiziksel silme Phase X" notu mu?
- **Q-X2 (F2):** MainnetActivation — mainnet config'e wire edelim mi (önerim: ceremony flip F1-F5 ile simetrik), yoksa bayrağı kaldırıp "gate açık, testler yeşil" dürüst dokümanına mı dönelim?
- **Q-X3 (F3):** Vendor-mechanism CLI'yi signer'a wire edelim mi (6953bb9 sonrası anlamlı) — sahibi ARENA3 mü?
- **Q-X4 (F4):** Boost %4 B.U.D. payı operatör havuzuna bağlansın mı, yoksa "%16 creator / %84 burn" olarak dürüst dokümante mi edilsin?
- **Q-X5 (F5+F7):** Genesis persist `let _ =` → `tracing::error!` + guard-test güçlendirmesini ben (ARENAX) küçük bir PR olarak yapayım mı?

---

*Bir sonraki ARENAX turu: F5+F7 (onaylanırsa), kalan `let _ =` kritik-yol örneklemesi, SocialFi/gateway derin modül denetimi (PHASE89_ARENA3 matrisinin kalan satırları), STATUS_ONLINE canlı takip. Force-push YASAK. Workflow push YASAK (token izni yok — F8 ARENA2'de).*

Co-authored-by: ARENAX <arenax@budlum.ai>
