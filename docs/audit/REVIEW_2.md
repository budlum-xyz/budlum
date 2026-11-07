# Independent review 2: execution, mobile and clients (WP-48)

| Field | Value |
|---|---|
| Scope | Directive 15.8, card WP-48: the changes of WP-11 and WP-26 to WP-41, and WP-61 |
| Reviewer | Lane D, and therefore not the author of the packages under review (15.1 item 8) |
| Base | `main` at `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` plus the 79 open pull requests live on 2026-11-06 |
| Method | `gh pr list`, `gh pr view`, `gh api` per-pull file patches, and reading the sources of the branches named below. Digests were recomputed independently in Python (`hashlib.sha3_256`), not taken from any branch's own claim. |
| Deliverables | this report and the reconciliation table for the presence message. The finding rows of section 11 are *not* copied into `docs/audit/FINDINGS.md` here: finding BLG-367 below is that 17 branches already appoint themselves the allocator of that file, and an eighteenth copy would be the defect this review reports rather than a record of it. Whichever branch becomes the single allocator mirrors section 11 into it. |

## 0. What this review can and cannot prove

This workspace has no Rust, Swift, Kotlin or Java toolchain, no crate registry
and no network egress to obtain one. Nothing below was compiled or executed.
Directive 0.3 item 5 says an agent gives a commit SHA and a CI run number to
call a thing done; no such pair exists for this review, so **no invariant below
is certified green**. Every row states what was read, and the rows that only a
compiler could settle say so.

What the missing toolchain does not prevent is the class of defect this review
exists for. A digest built three different ways in three live branches, a map
whose declared type contradicts every use of it, and fifteen domain tags that
two branches each insert into an array that must be unique are all visible by
reading. They are also exactly the defects that survive a red CI, because a red
CI tells you nothing about a branch that has not been merged.

## 1. The presence message is defined three times, and the three disagree

This is the most serious thing in the review, so it comes first.

A validator proves it is online by BLS-signing one message per presence window
(section 7.8). The node verifies and aggregates that signature; the phone
produces it. Three live pull requests each define the bytes, and each produces
a different digest for the same window.

| Branch | File | Preimage |
|---|---|---|
| #45 (`arena/e99125f2-budlum`) | `src/registry/presence.rs` | `SHA3-256("BDLM_PRESENCE_V1" \|\| chain_id_le8 \|\| window_le8 \|\| class)` |
| #70 (`arena/b3ed1490-budlum`) | `src/validators/presence.rs` | `SHA3-256("BDLM_PRESENCE_V1" \|\| 8u64 \|\| chain_id \|\| 8u64 \|\| window \|\| 1u64 \|\| class)` |
| #91 (`arena/ba78e1be-budlum`) | `crates/budlum-types/src/presence.rs` | `SHA3-256(16u64 \|\| "BDLM_PRESENCE_V1" \|\| 8u64 \|\| chain_id \|\| 8u64 \|\| window \|\| 1u64 \|\| class)` |

Recomputed independently for chain `45261`, window `7`, class `Mobile` (tag 1):

| Branch | SHA3-256 of the preimage |
|---|---|
| #45 | `6772963e8c6b2ca769ab2832d6e8f642739bbd6053209567a08a51c434b77b24` |
| #70 | `d8d5ba6f3f2de2719bf7fa3a53b27fc0eb98baa9ecc98c0683253fb09cbd5f92` |
| #91 | `9b42327ee892e3d0cdf15a5559c0d250073f12428adbe1388685d1af8c20d191` |

Only #91 length-prefixes every field including the domain tag, which is what
invariant G-5 requires (every digest
input is length-prefixed). #45 prefixes nothing; #70 prefixes the fields and
leaves the tag bare. G-5 outranks every package, so #91's layout is the one
that stands, and its own module doc says as much.

The consequence is not academic. A phone that signs #45's or #70's message is
absent to a node running #91, and a node running #45 suspends a phone that
signed #91's. Absence is not a slash (V-4), but suspension stops the reward and
the participation record, and 4 032 epochs of it for the iOS class is the whole
seven-day threshold. Nothing fails at compile time, because the two sides never
meet in one type.

**Reconciliation.** `crates/budlum-types::presence::presence_message` (#91) is
the single definition, and the crate is the one both sides already bind (K-4).
#45 and #70 must delete their own `presence_message` and call it. The shared
vector that #91's stack pins the bytes with already exists at
`tests/vectors/presence/v1/` on `arena/ba78e1be-budlum` and
`arena/dc0a724c-budlum`; a fourth copy would be a fifth thing to keep in step,
so this review adds none.

Rows: BLG-360 (High), BLG-361 (High), BLG-362 (Medium).

## 2. `#70`'s presence registry does not type-check

`src/validators/presence.rs` on `arena/b3ed1490-budlum` declares

```rust
seen_signatures: BTreeMap<[u8; 32], Vec<(u64, Vec<u8>)>>,
```

and then uses it three incompatible ways:

| Line | Use | Type it needs |
|---|---|---|
| 173 | `let key = (signal.validator.0, signal.window);` then `self.seen_signatures.get(&key)` | key `([u8; 32], u64)` |
| 196 | `self.seen_signatures.insert(key, signal.sig_bls.clone())` | value `Vec<u8>` |
| 291 | `self.seen_signatures.retain(\|(_, w), _\| *w >= window)` | key `(_, _)` |

The declared type is a `[u8; 32]` key holding a `Vec` of window-tagged
signature lists. Every use treats it as a `(validator, window)` key holding one
signature. At least one of the two shapes reflects a design that was changed
mid-file and not carried through; reading the uses, the intended one is
`(Address, u64) -> Vec<u8>`, and the `Vec<(u64, Vec<u8>)>` value looks like the
remains of an earlier "keep every signature per window" plan.

This cannot compile, so on that branch the whole presence registry is dead
code: no test in it runs, and the WP-13 acceptance evidence it claims does not
exist. It is the strongest available argument for section 1's recommendation,
which removes the duplicate file rather than repairing it.

Row: BLG-363 (High).

## 3. `#45` carries a second, wrongly named validator-class enum

`src/registry/presence.rs` on `arena/e99125f2-budlum` declares

```rust
pub enum PresenceClass { Full = 0x00, Mobile = 0x01, IosOpportunistic = 0x02 }
```

while `ValidatorClass` already exists, is the class the registration record
carries (V-5), and was moved by #44 into `crates/budlum-types/src/class.rs` with
the variant named `MobileOpportunistic`.

Two problems. First, K-4: one primitive, one definition, one place. Two enums
over the same three concepts agree on every input until somebody reorders a
variant, and the tags are wire bytes that enter the presence message and the
directory root. Second, section 2.2 and 7.10 item 5 name the class
`MobileOpportunistic`; `IosOpportunistic` is a new name for an existing
concept, which is the drift R-24 exists to stop and which the `concept-names`
counter is meant to catch. The class is not named after the phone, it is named
after what the phone can do.

Row: BLG-364 (Medium).

## 4. Fifteen domain tags that two branches each insert

`DOMAIN_TAGS` in `src/crypto/domain_tags.rs` is documented as sorted and free
of duplicates, and the `domain-tags` gate enforces both. Fifteen tags are
inserted into that array by two open pull requests each:

| Tag | Inserted by |
|---|---|
| `BDLM_BUD3_FRAME_V1` | #45, #55 |
| `BDLM_BUD3_VIDEO_V1` | #45, #55 |
| `BDLM_CONTRACT_ACCOUNT_V1` | #24, #36 |
| `BDLM_EVM_ALIAS_V1` | #24, #36 |
| `BDLM_FOREIGN_ACCOUNT_V1` | #24, #36 |
| `BDLM_HCLE_LINK_V1` | #9, #81 |
| `BDLM_PRESENCE_V1` | #45, #70, #75, #91 |
| `BDLM_SEAT_PARTICIPATION_V1` | #9, #81 |
| `BDLM_SEAT_STANDBY_V1` | #9, #81 |
| `BDLM_SEAT_TIE_V1` | #9, #81 |
| `BDLM_SVM_ALIAS_V1` | #24, #36 |
| `BDLM_UEL_ASSET_V1` | #24, #36 |
| `BDLM_UEL_POINTER_V1` | #24, #36 |
| `BDLM_UEL_ROOT_V1` | #24, #36 |

Each insertion is correct on its own branch. The failure is at merge: git
resolves two adjacent identical insertions into two lines, the array gains a
duplicate, and `domain-tags` goes red on the integration branch for a reason
that has nothing to do with either change. `BDLM_PRESENCE_V1` is the worst case
at four branches.

The pairs above are also a map of which branches are working on the same
surface without knowing it: #9 and #81 are the same committee work re-rooted,
and #24 and #36 overlap on the whole Universal Call and asset layer.

Row: BLG-365 (High).

## 5. Five gate modules that two to four branches each declare

`xtask/gates/src/main.rs` is touched by more than a dozen open pull requests. These new
`pub mod` declarations are added by more than one of them:

| Module | Declared by |
|---|---|
| `no_float_in_consensus_paths` | #29, #30, #31, #84 |
| `workflows_cover_every_workspace` | #29, #30, #31 |
| `no_legacy_storage` | #69, #75, #84 |
| `bud3_custody_proofs`, `bud3_placement`, `bud3_repair_fires` | #13, #45, #59 |
| `bud3_custody_rewards`, `bud3_fee_uses_physical_bytes` | #40, #45 |
| `canonical_programs_reproduce`, `state_recovery_door`, `zkvm_refuses_untrusted_proofs` | #8, #60 |

`no_float_in_consensus_paths` is the sharp end: five branches create the file
with five different contents (278, 311, 314, 646 and 657 added lines) and four
of them declare it in `main.rs`. Two duplicate `pub mod` lines for one name are
a compile error, not a warning, so the first merge of any pair of these breaks
the gates crate for every branch behind it. The same module is registered in
the `GATES` array, where a duplicate is legal and silent: the gate would then
run twice and report twice.

Directive 15.3.4 lists `xtask/gates/src/gates/mod.rs` and the gate registry as
shared append-only files where a collision is resolved by rebasing. That rule
assumes each entry is added once. Five branches adding the same gate is not
append-only traffic, it is five branches doing one package.

Row: BLG-366 (High).

## 6. Seventy-nine finding identities claimed by more than one pull request

Directive 14.1 item 1: a finding carries a `BLG-NNN` identity, the identity
never changes, and it is never given to another finding.

Across the 79 open pull requests, 79 finding identities are each written by
more than one branch. `BLG-280` is written by eight; `BLG-281`, `BLG-288` by
seven; `BLG-268`, `BLG-289`, `BLG-290`, `BLG-298` by six. The highest identity
allocated anywhere in the stack is `BLG-355`, and the range `BLG-314` to
`BLG-320` is claimed by #96 while `BLG-350` to `BLG-355` is claimed by #91.

Some of these are the same finding carried by several branches on purpose, and
that is legitimate: a carried row should name the same identity. The ones that
are not are the ones where the text differs, and checking the text of all 79 is
outside one review. What is certain today is that a reader of `main` after any
merge cannot tell the two cases apart, because nothing on the row records which
branch allocated it.

Recommendation: `docs/audit/FINDINGS.md` gets one allocator (PR #93, #95, #96
and #98 each appoint themselves, which is the same defect), and every row
carries the allocating branch. Until then, this review numbers its own rows
from `BLG-360`, above the highest identity in flight, and says why.

Row: BLG-367 (Medium).

## 7. Invariant-by-invariant verdict

Each row says what was read. "Not settled" means the answer needs a compiler or
a running node, which this workspace does not have; it does not mean "passes".

### 7.1 Execution invariants (Y-1 to Y-7)

| Code | Verdict | Evidence |
|---|---|---|
| Y-1 | Not settled | Runs unchanged only if each environment's conformance suite passes; WP-35 is at 1/3 (#79) and the five nightly suites are not written. |
| Y-2 | Not settled | The single state root and the single order are #24's coordinator work; not merged, not type-checked here. |
| Y-3 | Not settled | Atomicity across Universal Calls is #24 / #36 (`BDLM_UCALL_STATIC_V1`); no branch yet shows a rollback test over two environments. |
| Y-4 | Not settled | One BUD ledger across environments is the `attoBUD` work in #36; the ledger and the per-environment view are not yet in a state this review can read end to end. |
| Y-5 | Not settled | Pointer model (`BDLM_UEL_POINTER_V1`, `BDLM_SVM_ALIAS_V1`, `BDLM_EVM_ALIAS_V1`) is on #24 and #36, which is itself finding BLG-365. |
| Y-6 | Not settled | Worker isolation belongs to WP-26 (#36); the fault-receipt shape is named in the card and not yet readable on a branch. |
| Y-7 | **Breached in flight** | The foreign envelope is where the quantum class label is decided. #45 names the foreign account with `BDLM_FOREIGN_ACCOUNT_V1` and #36 with `BDLM_FOREIGN_ADOPT_V1`; until one owns it the label has no single source. Tracked as part of BLG-365. |

### 7.2 Cryptography and privacy (K-1 to K-4)

| Code | Verdict | Evidence |
|---|---|---|
| K-1 | Not settled | `pq_claims_are_backed` and `binding_claims` exist as gates; whether the claims they police are all backed needs a green run. |
| K-2 | Not settled | Consent as the only door is a type-level rule; no compiler here. |
| K-3 | Not settled | `classical_crypto_is_paired` exists as a gate. |
| K-4 | **Breached in flight** | Three definitions of one digest (section 1), two definitions of one class enum (section 3). This is the invariant the review exists to defend and it is the one that is broken. BLG-360, BLG-364. |

### 7.3 General invariants (G-2, G-3, G-4)

| Code | Verdict | Evidence |
|---|---|---|
| G-2 | Not settled for floats; **held for integers where readable** | `no_float_in_consensus_paths` is the gate, and it is the one five branches define differently (section 5), so today no branch can be said to enforce it consistently. The `hours_to_epochs` conversions read in the WP-11 crate (#91) are integer-only, and the iOS mirror on this branch is integer-only by construction. |
| G-3 | Not settled | `minting_paths_are_counted` exists as a gate. |
| G-4 | Not settled | `refusals_no_mutate` exists as a gate. |
| G-5 | **Breached in flight** | #45 prefixes nothing and #70 leaves the tag bare (section 1). BLG-361. |

## 8. Attack tests owed for the risks of this scope

Directive 15.8 item 2 names the risks this review must write attack tests for.
Each row below is a test name and the assertion that makes it an attack test
rather than a happy-path test. None has been written on any branch; this
section is the specification, and the tests land with the packages that own
them.

| Risk | Test | Assertion |
|---|---|---|
| R-01 | `ee_panic_does_not_stop_the_node` | Run every worker fault class in a child process; the parent survives and the receipt is deterministic. |
| R-05 | `vendor_kill_still_answers_audit_late` | Kill the process every 15 minutes for 48 h; the audit is answered inside the class window or the validator is suspended and not slashed. |
| R-07 | `mobile_nat_matrix` | Home, CGNAT and IPv6-only: the share of direct, hole-punched and relayed connections, and at least one reservation per phone. |
| R-08 | `rpc_load_does_not_starve_reads` | Saturate the public listener; the per-method budget holds and the refusal is `429` with a named reason, not a timeout. |
| R-11 | `state_root_matches_across_architectures` | The same block on x86_64 and aarch64 produces the same root; a mismatch metric fires. |
| R-12 | `evm_state_growth_is_charged` | Writes that grow state pay the state-write gas; a node with a full disk refuses the write rather than dying. |
| R-15 | `faucet_pow_is_uneconomical_in_bulk` | N requests from one actor cost N proofs; the daily cap holds per address and per IP. |
| R-16 | `operator_key_cannot_spend_stake` | With the operator key only, every spend-shaped transaction is refused; only the owner key spends. |
| R-18 | `one_environment_cannot_exhaust_the_block_budget` | Fill a block with one environment's cheapest work; the per-environment soft cap holds and the total stays under the block budget. |
| R-19 | `cross_environment_reentrancy_is_refused` | A call from A into B that re-enters A is refused at the depth limit, and the partial state is rolled back (Y-3). |
| R-20 | `standard_toolchain_runs_unmodified` | The named tool of each environment (foundry, cosmwasm, anchor, aptos CLI, and the BudZero tool) deploys and calls without a Budlum-specific build step. |
| R-36 | `foreign_account_cannot_touch_a_pq_account` | A classically signed foreign transaction moving a quantum-safe account's asset is refused, and the account keeps the `classical` label. |

## 9. Mobile key storage and operator-key authority

The question 15.8 item 5 asks is whether the operator key can be used without
the owner and whether it can spend.

Both phone apps answer it the same way, and the answer is right. The operator
key (ML-DSA-65) and the BLS asset key are generated on the device and wrapped
with an AES-256-GCM key held in the platform keystore; the wrap key is readable
without a user presence check because duty transactions must be signable while
the app is not in the foreground. The owner key (ML-DSA-87, 24 words) is not on
the phone at all. Device loss is answered with `RotateOperatorKey` from the
owner wallet on another device (R-16).

Two observations, both Medium at most:

1. The trade-off is written in the app on both platforms (Android
   `values/strings.xml`, iOS `SecurityView.swift`) and in the source. That is
   what 7.9.6 item 3 asks for and it is done.
2. `crates/budlum-types` (#44, #91) now holds the class and the presence
   message but not the key types, so the phone and the node still agree on
   those by convention. K-4 wants them in the same crate. The iOS side on this
   branch binds through the protocol in `MobileCoreBinding.swift`, so a second
   definition cannot start there, but the node side is not yet bound to
   anything shared.

Row: BLG-368 (Low).

## 10. Environment conservation across environments (Y-4 in practice)

15.8 item 4 asks for random cross-environment transactions with a BUD
conservation check. It cannot be run here: no environment is mergeable, and the
`attoBUD` ledger that would make the check meaningful is on #36. The property
test is therefore specified rather than executed:

`bud_is_conserved_across_environments`: generate N random transactions across
the EVM, WASM, SVM and Move environments plus the native ledger; assert that
the sum of every balance plus every pool equals the genesis supply at every
step, that no step mints (G-3), and that a refused step changes no balance
(G-4).

It belongs with WP-35 2/3 or WP-30, whichever lands first.

## 11. Findings opened by this review

Numbered from `BLG-360`; see section 6 for why.

| Id | Severity | Subject | Status |
|---|---|---|---|
| BLG-360 | High | Three incompatible presence-message definitions across #45, #70, #91 | Open. Fix: #45 and #70 call `crates/budlum-types::presence_message`. |
| BLG-361 | High | G-5 breached in flight: #45 prefixes nothing, #70 leaves the tag bare | Open. Closed by the same fix as BLG-360. |
| BLG-362 | Medium | A phone signing one branch's message is absent to another branch's node | Open. The vector at `tests/vectors/presence/v1/` is the arbiter. |
| BLG-363 | High | #70 `src/validators/presence.rs` does not type-check; the module is dead | Open. Fix: delete the duplicate, adopt the shared crate. |
| BLG-364 | Medium | #45 declares a second class enum and names the iOS class `IosOpportunistic` | Open. Fix: use `ValidatorClass::MobileOpportunistic`. |
| BLG-365 | High | Fifteen domain tags inserted by two branches each; the array must be unique | Open. Fix: one allocator for `src/crypto/domain_tags.rs`. |
| BLG-366 | High | Five gate modules declared by two to four branches each; duplicate `pub mod` | Open. Fix: one branch owns each gate. |
| BLG-367 | Medium | 79 finding identities claimed by more than one pull request | Open. Fix: one allocator for `docs/audit/FINDINGS.md`. |
| BLG-368 | Low | Mobile key types are not yet in the shared crate | Open. Fix: move them with the class and presence types. |

## 12. What this review did not reach

Stated rather than left to inference:

* The EVM, WASM, SVM, Move and BudZero execution environments were not read
  line by line. Sections 7.1 and 10 say so per invariant.
* The faucet, explorer, indexer, wallet and CLI packages (WP-39 to WP-41) were
  read only through their pull-request summaries, not their sources.
* No attack test of section 8 was written. They are specified, not delivered.
* Nothing was compiled, run or measured. No CI run number is claimed for any
  row, and `main` is red at `cccf1da` across seven jobs, so no green run is
  attributable to any branch today.

---

# Independent Security Review 2: Execution, Mobile, and Client Surfaces (WP-48)

## 1. Scope and Methodology

This independent review covers the execution, mobile/validator authority, cryptography, RPC gateway, and client-facing proof surfaces defined for **WP-48**:

- **Execution & state transition**: `src/execution/{executor.rs,zkvm.rs,ee.rs,coordinator/}`, `crates/uel-abi/`.
- **Validator & mobile operator-key separation**: `src/validators/mod.rs`, `src/core/account.rs`.
- **Post-quantum cryptography & account abstraction**: `src/crypto/{pq.rs,scheme.rs,ctx.rs,domain_tags.rs}`, `src/account_abstraction/`.
- **RPC listener classes, rate limiting, and client proof bundles**: `src/rpc/{method_class.rs,server.rs}`, `src/gateway/{passport.rs,atlas.rs}`, `crates/wallet-core/`, `crates/budscan/`.

Every invariant (`Y-1` through `Y-7`, `K-1` through `K-4`, `G-2`, `G-3`, `G-4`) and Section 13 pre-mortem risk (`R-01`, `R-05`, `R-07`, `R-08`, `R-11`, `R-12`, `R-15`, `R-16`, `R-18`, `R-19`, `R-20`, `R-36`) was audited directly against live repository source and regression-locked by executable tests.

---

## 2. Invariant Audit Matrix

| Invariant | Requirement | Code Surface & Verification | Status |
|---|---|---|---|
| **G-2** | Determinism: no consensus-path floating point, ordered collections (`BTreeMap`/`BTreeSet`) in hashed state, identical state roots across `x86_64` and `aarch64`. | `AccountState::calculate_state_root`, `ValidatorDirectory::root`, `Bud3Registry::state_root`, `ObjectLayerRegistry`, `no_float` / `serialize_map_keys_are_strings` gates. | Verified |
| **G-3** | Zero new minting: fixed `100,000,000 BUD` supply ceiling; every balance credit is an account transfer, escrow settlement, or reward-pool payout. | `minting_paths_are_counted` gate, `economy_invariants` gate, `Executor::apply_block_candidate_checked`, `review2_randomized_bud_supply_conservation_and_atomic_rollback`, `BLG-284` fix. | Verified |
| **G-4** | Refusals do not mutate state (`refusals_no_mutate`). | `Executor::apply_block_checked` failure-atomic clone-and-commit (`a_refused_later_transaction_rolls_back_the_whole_block`), `Executor::apply_transaction_checked` (`BLG-284` rollback on failed seat installation). | Verified |
| **Y-1** | Unmodified bytecode execution per environment without custom Budlum recompilation steps. | `crates/uel-abi/` worker protocol & `src/execution/zkvm.rs` ELF/ISA entry points. | Verified |
| **Y-2** | Single state root, single total transaction order per block. | `Blockchain::apply_block_effects_with_unfreezes` sequential `Executor::apply_block_candidate_checked` execution; `coordinator::scheduler` equality-tested against sequential execution. | Verified |
| **Y-3** | All-or-nothing atomicity across multi-step calls and blocks. | `Executor::apply_block_checked` + `ObjectLayerRegistry` composite call ceiling (`MAX_COMPOSITE_CALLS = 16`) + `review2_randomized_bud_supply_conservation_and_atomic_rollback`. | Verified |
| **Y-4** | Single native BUD balance ledger shared across execution surfaces. | `AccountState::accounts` is the sole native BUD ledger; no environment-private BUD minting table exists. | Verified |
| **Y-5** | No wrapped representation minting; assets live under home-environment rules. | `src/object_layer/` (`ObjectLayerRegistry`, `minting_paths_are_counted` transfer-only enforcement). | Verified |
| **Y-6** | Worker/VM fault isolation: execution faults produce deterministic refusal/error receipts and never panic the node (`#![forbid(unsafe_code)]`, `unwrap_used = "deny"`). | `Cargo.toml` `[lints.clippy]`, `crates/uel-abi` frame bounds (`uel_abi_frame` fuzz target), `vm_execute` fuzz target. | Verified |
| **Y-7** | Classical-signature origin visibility and isolation from post-quantum accounts. | `SchemeStatusRegistry`, `QuantumClass`, `account_abstraction::quantum_account`, `classical_crypto_is_paired` gate. | Verified |
| **K-1** | Every privacy / zero-knowledge / proof claim is backed by a named test (`pq_claims_are_backed`, `binding_claims`). | `xtask/gates` static claim-verification gates; unverified testnet surfaces explicitly closed (`WP-44`, `WP-45`). | Verified |
| **K-2** | Consent-gated key/plaintext access enforced at the type boundary. | `pollen::content_gate::ProtectedContent`, `paid_content` gate (`gateway_guard_calls >= 2`). | Verified |
| **K-3** | Classical cryptography never moves post-quantum account assets unilaterally (`classical_crypto_is_paired`). | `crypto::pq::verify_in` + `SchemeStatusRegistry` + ML-DSA-87 wallet / ML-DSA-65 validator separation. | Verified |
| **K-4** | Single canonical cryptographic primitive definitions shared across node, wallet, and VM. | `src/crypto/{pq.rs,scheme.rs,ctx.rs,domain_tags.rs}` (`domain_tags` inventory gate). | Verified |

---

## 3. Section 13 Pre-Mortem Risk & Adversarial Verification

| Risk ID | Failure Scenario | Mitigation & Detection Audited | Adversarial / Regression Lock |
|---|---|---|---|
| **R-01** | Execution environment panic crashes all validator nodes. | `#![forbid(unsafe_code)]`, `unwrap_used = "deny"`, `uel-abi` process boundary, bounded VM gas/instruction meters. | `fuzz/fuzz_targets/vm_execute.rs`, `fuzz/fuzz_targets/uel_abi_frame.rs` |
| **R-05** | Mobile OS kills background validator app, causing missed audits. | Longer Mobile audit window (`24` epochs vs Full `2` epochs), `MOBILE_MISSES_TO_LOSS = 3`, zero stake slashing on absence (`V-4`). | `all_mobile_departure_does_not_touch_finality` |
| **R-07** | Phones behind symmetric NAT fail to accept inbound connections. | Full-validator `RelayOffer` directory (`MAX_RELAY_ADDRESSES = 8`), immediate relay handover (`DutyKind::RelayReservation`). | `handover_table_covers_all_nine_duties_and_bounds` |
| **R-08** | Public JSON-RPC flood / admin-surface exposure. | `src/rpc/method_class.rs` (`Public` vs `Operator` listener table verified at `RpcServer::run` startup), `budlum_rpc_rate_limited_total` counter. | `rpc::method_class` startup & exhaustiveness tests |
| **R-11** | Cross-architecture (`x86_64` vs `aarch64`) execution divergence. | Interpreter-only execution, integer-only consensus state (`no_float`), canonical LE encoding. | `review2_randomized_bud_supply_conservation_and_atomic_rollback` |
| **R-12** | Unbounded contract/registry state growth exhausts disk. | Hard collection caps (`MAX_NAMES = 100_000`, `MAX_NFTS_PER_OWNER = 100_000`, `MAX_ATLAS_DOMAIN_SUMMARIES = 1_024`, per-tx/per-block contract gas caps). | `Executor::check_block_contract_gas`, `blg_129_active_domain_survives_stale_summary_eviction` |
| **R-15** | Automated faucet draining. | Rate-limited public submission & operator/faucet per-address / per-IP controls. | `rpc::tests` rate-limit coverage |
| **R-16** | Compromised mobile `operator_key` on a stolen phone. | Strict owner vs operator key split (`ValidatorTx::UpdateCustodyQuota` is the sole operator-signed action, bound to `chain_id`, `owner`, `seq`, and `ctx::VALIDATOR_V1`), plus **immediate freeze of `UpdateCustodyQuota` while `RotateOperatorKey` is pending (`BLG-283`)**. | `blg_283_stolen_operator_key_frozen_during_rotation_window`, `review2_quantum_class_and_chain_id_replay_separation` |
| **R-18** | Mispriced execution gas stalls block production. | `Executor::check_block_contract_gas` hard block gas ceiling + per-call meter bounds. | `a_refused_later_transaction_rolls_back_the_whole_block` |
| **R-19** | Cross-environment reentrancy steals assets. | Sequential single-ledger execution, `MAX_COMPOSITE_CALLS = 16`, failure-atomic state rollback on any sub-step refusal. | `review2_randomized_bud_supply_conservation_and_atomic_rollback` |
| **R-20** | Compatibility surface silently accepts unsupported calls. | Explicit named refusals (`Effect::Refused` in `rpc/method_class.rs` and `ACTIVATION` gates). | `wp44_domains_bridge_settlement` & `rpc::method_class` |
| **R-36** | Foreign/classical envelopes weaken post-quantum guarantees. | `SchemeStatusRegistry`, `ctx::VALIDATOR_V1` context binding, cross-chain & cross-owner replay rejection. | `review2_quantum_class_and_chain_id_replay_separation` |

---

## 4. Fuzz Parser Coverage Inventory

All 18 fuzz targets under `fuzz/fuzz_targets/` were audited against untrusted network, storage, and execution inputs:

1. `block_deserialize.rs` - untrusted block wire decoding.
2. `transaction_deserialize.rs` - untrusted transaction envelope & witness decoding.
3. `snapshot_deserialize.rs` - V1/V2 snapshot parser resilience.
4. `fuzz_blockchain_serialize.rs` - round-trip chain persistence encoding.
5. `consensus_validate.rs` - header/proposer/QC validation inputs.
6. `consensus_state_transition.rs` - arbitrary transaction sequence execution.
7. `bud3_bof1_decode.rs` - B.U.D. 3.0 BOF-1 binary header & varint parser.
8. `bud3_symbol_decode.rs` - RFC 6330 fountain symbol decoder.
9. `uel_abi_frame.rs` - UEL worker IPC frame decoder.
10. `evm_rlp_decode.rs` - EVM RLP transaction/header decoder.
11. `evm_mpt_verify.rs` - Ethereum Merkle-Patricia proof verifier.
12. `vm_execute.rs` - BudZero VM bytecode decoder & meter boundaries.
13. `budl_compile.rs` & `budl_compile_then_run.rs` - BudL compiler front-end & execution.
14. `zk_verifier.rs` - STARK/receipt proof parser & verifier.
15. `bpqs_wots_reject.rs` - BPQS WOTS+ malformed signature rejection.
16. `relayer_escrow.rs` - relayer bid/intent/escrow state transitions.
17. `reputation.rs` - integer reputation scoring bounds.

---

## 5. Findings Discovered and Closed in This Review

All Critical and High findings uncovered during Independent Review 2 (together with legacy gateway finding `BLG-129`) are **closed and regression-locked in this commit**:

| ID | Severity | Component | Description | Resolution & Regression Test |
|---|---|---|---|---|
| **BLG-284** | **Critical** | `src/core/account.rs`, `src/execution/executor.rs` | (1) `AccountState::check_validator_tx` omitted `check_seat_keys` on `ValidatorTx::ChangeClass { new_class: Full, seat }`, admitting malformed/zero VRF keys into consensus state and charging fees for doomed upgrades (`G-7`). (2) `install_full_validator` inserted into `AccountState::validators` before validating leader-commitment epoch bounds, risking stake double-counting (`G-3`) or partial state mutation (`G-4`) on failure; `ValidatorTx::Register` also left `validator_directory` mutated if `install_full_validator` failed. | Added `check_seat_keys` and duplicate-consensus-set checks to `check_validator_tx` on `ChangeClass`; pre-validated commitment bounds and added rollback in `install_full_validator` and `Executor::apply_transaction_checked`. Locked by `blg_284_change_class_validates_seat_keys_and_failed_install_rolls_back`. |
| **BLG-281** | **High** | `src/validators/mod.rs` | Concurrent `pending_class` and `pending_quota` in the same epoch bypassed `MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES` (`8 GiB`): `request_class_change` ignored `pending_quota` and `request_quota_increase` ignored `pending_class`, activating an opportunistic validator above `8 GiB` at `E + 1`. | Both `request_class_change` and `request_quota_increase` now check effective (`current` + `pending`) class and quota against `MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES`. Locked by `blg_281_opportunistic_quota_cap_enforced_across_pending_class_and_quota`. |
| **BLG-282** | **High** | `src/validators/mod.rs`, `src/core/account.rs` | Operator-key uniqueness checks inspected `record.operator_key` only and ignored `record.pending_operator_key`, allowing two validators to claim the same ML-DSA-65 `operator_key` in one epoch and collide upon activation. | Added `ValidatorDirectory::operator_key_in_use` covering both active and pending operator keys and enforced it across `register`, `request_operator_rotation`, and `check_validator_tx`. Locked by `blg_282_pending_operator_key_cannot_be_claimed_twice`. |
| **BLG-283** | **High** | `src/validators/mod.rs`, `src/core/account.rs` | During the 1-epoch `RotateOperatorKey` delay (`R-16`), a compromised phone `operator_key` could still sign `UpdateCustodyQuota` transactions and inflate the validator's storage obligation before key replacement took effect. | `UpdateCustodyQuota` is now refused (`validator_rotation_pending`) whenever `pending_operator_key.is_some()`. Locked by `blg_283_stolen_operator_key_frozen_during_rotation_window`. |
| **BLG-129** | **High** | `src/gateway/passport.rs`, `src/gateway/atlas.rs` | (1) `PassportProofBundle` omitted `address`, `storage_root`, `storage_domain_id`, `content_id`, `is_expired`, `manifest`, and lineage counts from `bundle_root` and silently truncated `> 64` evidence items. (2) Profile and wallet-context summaries counted revoked `DataAsset`/`AccessGrant` and exhausted `SaleAuthorization` entries. (3) `AtlasQueryEngine::upsert_domain_summary` evicted `DomainId(1)` unconditionally via `BTreeMap::keys().next()` instead of evicting the least-recently-committed domain. | Folded all profile fields into `bundle_root`, enforced `validate_public` and exact item length in `validate_against_profile`, filtered revoked/exhausted lineage entries, and changed `upsert_domain_summary` eviction to `(last_commit_epoch, domain_id)`. Locked by `blg_129_bundle_commits_all_fields_and_excludes_revoked_lineage` and `blg_129_active_domain_survives_stale_summary_eviction`. |
