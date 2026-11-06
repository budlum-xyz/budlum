# Unified findings ledger - repository record

Directive §15.5 item 8 keeps the rows a package closes here, each carrying the
commit SHA and the CI run that validated it. This file is a shared append-only
file under §15.3 item 4: a package appends its own rows and never renumbers or
re-states another package's. Identities, severities and titles come from the
directive's §14 ledger.

A finding with a foot in two lanes is closed by two packages, and each package
closes only its own foot. "Closed by testnet closure" means the unsafe path is
unreachable on the testnet chain id and refuses with a named code (G-7); the
code is kept, not deleted, and the underlying proof work stays open under the
package that owns it.

## Closed rows

| Identity | Severity | Status | Foot this PR closes | Evidence | Test | Closing package |
|---|---|---|---|---|---|---|
| BLG-063 | Critical | Closed (Kapalı) | `privacy_transfers_enabled` admitted testnet (`45261`), so the unproven private-note mint/spend path was reachable there. The allowlist is now devnet-only; testnet refuses with `privacy_testnet_closed`. Mainnet keeps its historical `privacy_mainnet_disabled` code and message. | `src/execution/executor.rs` `privacy_transfers_enabled`, `privacy_closed_refusal` | `blg_063_privacy_allowlist_excludes_testnet`, `private_transfer_is_closed_on_testnet`, `note_registry_is_closed_on_testnet` | WP-45 (1/3) |
| BLG-225 | High | Closed by testnet closure | Ownership, conservation and membership proofs are still unbound on the private-transfer path. That path is now unreachable on testnet and mainnet and runs on devnet only. **The proof binding itself is not built** and stays open under İP-56. | same guard as BLG-063 | `private_transfer_is_closed_on_testnet`, `note_registry_is_closed_on_testnet` | WP-45 (testnet foot); İP-56 keeps the proof foot |
| BLG-228 | High | Closed by testnet closure | `AiAttachExecutionProof` ran with `FULL_AI_STARK_VERIFICATION_LIVE = false`. It refuses on testnet with `ai_layer_testnet_closed`, as do 9 other entry doors; the 7 settle-or-unwind doors stay open so value taken while the layer was ungated can still leave and a proven equivocation can still be slashed (`is_ai_layer_exit`). **Full STARK verification is not built** and stays open under İP-57. | `src/execution/executor.rs` `ai_layer_enabled`, `is_ai_layer_transaction`, `is_ai_layer_exit` | `ai_execution_proof_is_closed_on_testnet`, `ai_layer_is_closed_on_testnet` | WP-45 (testnet foot); İP-57 keeps the verification foot |
| BLG-229 | High | VL-1 leg: closed decision | The card lets the AI layer open at VL-1 only with BLG-059..062 closed **and** both VL-1 conditions built. Per-request lottery and commit-reveal are absent from the tree, so the layer does not open. The decision is recorded in the `ai_layer_enabled` doc comment. **The lottery/commit-reveal itself is not built.** | `src/execution/executor.rs` `ai_layer_enabled` doc comment | `ai_layer_is_closed_on_testnet` (10 entry doors, three chain ids, byte-identical state), `a_bond_taken_before_the_closure_can_still_leave_testnet` (the exits stay open), `a_dispute_survives_the_closure_on_testnet` (the dispute window cannot be waited out) | WP-45 (VL-1 decision); İP-57 keeps the build |
| BLG-240 | Low | Closed (Kapalı) | Verifier/agent ranking ordered on `f64`. Sort keys are now integer permyriad with an address tie-break - a total order, no `partial_cmp`. `agents_by_trust_score_permille` returns the integer instead of re-quantizing a float at the boundary that existed to stay float-free. The `f64` columns remain as display only. | `src/ai/types.rs` `reliability_score_permyriad`, `trust_score_permyriad`; `src/ai/registry.rs` `verifiers_by_reliability`, `agents_by_trust_score` | `ai_ranking_uses_integers`, `ai_ranking_breaks_ties_by_address`, `ai_ranking_saturates_instead_of_overflowing`, `ai_ranking_integer_matches_display_within_one_basis_point`, `reliability_permyriad_is_exact_and_bounded`, `trust_permyriad_weights_are_forty_sixty`, `permyriad_scores_are_total_over_extreme_counters`, `a_ratio_above_one_caps_at_the_basis` | WP-45 (1/3) |

### Evidence commits and CI status

Closing commit for every row above: `2f03e59673386737bd61f3c781de42505af50b7f`
(WP-45 slice 1, PR #44). Test-first commit: `69dbd8021f65ae2b7f86e8b8bf484c096760b2fe`
- tests only, red by construction, since the functions they call do not exist
at that commit.

**CI run: not yet available, and none is claimed.** This sandbox has no Rust
toolchain and `static.rust-lang.org` is outside the allowed egress, so no local
`cargo test` log exists. Per S-1, CI is the sole validator. Every run on this
branch so far is either `cancelled` or still pending: the workflow sets
`cancel-in-progress` on non-main refs, so each push cancels the previous run.
The failure-filtered list (`failure`, `timed_out`, `action_required`) is empty.
Exact counts are deliberately not recorded here — they change with every push
and a stale count reads as evidence when it is not. **No row above is validated
by a completed run, green or red**, and this ledger must be amended with the run
number when one completes. Self-report is not evidence (§0.3 item 5).

## Open rows these packages touch but do not close

| Identity | Severity | Why it stays open |
|---|---|---|
| BLG-059 | Critical | Execution-proof STARK binding and host-guest divergence: `FULL_AI_STARK_VERIFICATION_LIVE` is still `false`. WP-45 slice 2/3, now blocked by #43's locks on `src/ai_inference/` and `crates/ai-inference/`. |
| BLG-060 | Critical | Requester pre-auth landed on `main` earlier; the permanent escrow-fee loss on delayed `AiAttachExecutionProof` finalisation is not closed as a finding. |
| BLG-061 | High | Ghost `verifier_stakes`, effort-tier bypass and payment gaps are untouched. |
| BLG-062 | High | The state root still omits execution fields. Only the QoS ranking arithmetic leg is addressed, under BLG-240. |
| BLG-151 | High | Assigned to **İP-17**, with three feet: the NUL-separated wire-framing collision and dropped V4-V6 transaction / PoS-BFT header fields in `core::encoding`, the `address.rs` parse contract, and the AI system-prompt production-refusal gate bypass. **#43 is closing the `address.rs` foot**, not WP-11: #44 moved the definition verbatim and deliberately pins no input contract. That foot's body now lives at `crates/budlum-types/src/lib.rs`; the `encoding.rs` and `system_prompt.rs` feet are untouched here. |
| BLG-022 | Medium | `LightClient::next_checkpoint_height` overflow. WP-11 job 3, blocked: `src/light_client/` is held by #9. |
| BLG-257 | High | No mobile application exists; the mobile profile is still only a node CLI flag. WP-11 jobs 2-9 and İP-36. |
| BLG-259 | Medium | Checkpoint certificate size and the undocumented trust model. WP-11 job 3, blocked by #9. |

## New rows

| Identity | Severity | Row | Owner | Status |
|---|---|---|---|---|
| BLG-279 | Medium | A second `Address` definition survives in the VM workspace: `budzero/verifier-registry/src/address.rs:9` derives `Serialize`/`Deserialize` over `pub struct Address(pub [u8; 32])`, so it encodes as a 32-element byte array, while `core::address::Address` hand-writes a bare hex string. K-4 says wallet, chain and VM call one definition. `SlashingReport` (`evidence.rs:65`) and `Registration` (`registry.rs:106`) derive serde over that field, so the two workspaces already disagree on the JSON shape of the same concept. | İP-33 (owns the crate), coordinate with İP-11 job 1 | **Open — recorded, not closed here.** |
| BLG-291 | High | The concept-name gate is red on `main` itself, independently of any PR. Four concepts measure above the committed baseline: `Budscan` 34/272 vs 33/268, `Tarif` 52/1444 vs 51/1442, `PUL` 14/100 vs 13/99, `Gövde` 2/2 vs 1/1. Each is exactly **+1 file**, and the deltas are the gate's own detection literals: `xtask/gates/src/gates/geiger.rs` (Budscan 4), `bud3_forbidden_phrases.rs` (Tarif 2, Gövde 1) and `module_coverage.rs` (PUL 1). `xtask` is in `SCAN_ROOTS`, so a detector is counted as a use of the name it detects. `compare()` fails on any inequality and `check(root, write=true)` refuses to write a raised count, so the documented `BUDLUM_CONCEPT_NAMES_WRITE=1` escape cannot clear it. **#50 already carries the fix for three of the four**; only `PUL` is unowned. | naming-policy owner; #50 covers Budscan/Tarif/Gövde, `PUL` in `module_coverage.rs` has no open owner | **Open — recorded, not closed here.** |
| BLG-292 | High | #68 replaces the working 531-line concept-name gate with a 99-line stub: `ConceptNamesGate::new` returns `entries: Vec::new()` and `baseline: HashMap::new()` (both parsers are `// Parse from ...` comments), `run()` only calls a `self_test()` whose body is two comments and `Ok(())`, and all three unit tests are `assert!(true)`. Independently it does not compile against its own caller: `xtask/gates/src/main.rs` :964/:967 take `gates::concept_names::run` and `::self_test` as `fn(&Path) -> Result<String, String>`, but the stub defines those names only as methods on `ConceptNamesGate`, so both paths are unresolved (E0425). The gate it replaces exports exactly those two free functions. | #68 owner (İP-05); to be reported on the PR | **Open — another PR's branch; this PR cannot push to it.** |

Numbering: `BLG-288` was free when this row was written but has since been taken
by #77/#86/#88, so the row is renumbered to `BLG-291` and the #68 row takes
`BLG-292`. Both were re-verified free across all 69 open PR bodies and all 12 open
`FINDINGS.md` patches; `BLG-279` is unchanged.

BLG-291 is not fixed here, and it is smaller than first recorded: #50 already adds
`xtask/gates/src/gates/geiger.rs` to `Budscan`'s `allow_paths` and
`bud3_forbidden_phrases.rs` to `global_allow_paths`, which clears the Budscan, Tarif
and Gövde deltas. Only `PUL` in `module_coverage.rs` is still unowned by any open PR.
This PR's own measured delta stays **0 matches / 0 files**.

One limit on that row. It was measured with a faithful replication of
`measure()` and `compare()` — same `SCAN_ROOTS`, `SKIP_DIRS`, `MAX_FILE_BYTES`,
`global_allow_paths`, per-concept scoping and per-line counting — not with the
Rust gate, which cannot run here (S-1). An earlier revision of this row also
claimed the `PUL`/`Tarif` `\b` patterns were inert because TOML literal strings
do not process escapes. **That was wrong and is retracted**: the literal string
passes `\b` through to the regex engine, which reads a word boundary. Both
spellings compile identically and match `PUL` while refusing `XPULX`.

Why this PR does not fix it: nothing depends on `verifier-registry` today (it is
a leaf member of the `budzero` workspace), so no wire crosses yet and there is
no live bug. Swapping in the shared type would change that crate's encoded form
from an array to a string — a wire change, which §15.5 requires to be declared
and reviewed on its own, not smuggled into a K-4 move. The crate is also partially
held by #24 (`params.rs`, `tests/regression.rs`).

What is closed here is the drift hazard on the node side:
`address_json_is_a_hex_string_not_a_byte_array` in `src/core/address.rs` pins the
hex-string form and asserts the array form stays refused, so a future dedup that
substitutes the derived encoding fails a test instead of the database.

BLG-292 was found while looking for the owner of BLG-291, so the two are related:
#50 carries the correct fix for three of the four drifting concepts while #68
rewrites the same gate, and whichever lands second must not undo the other. The
compile break is read directly from the two files at #68's head `cecf85a1`; its CI
was still queued, so no run result is claimed either way (S-1).

## Package status

`docs/work/PACKAGES.md` is deliberately not written here: §15.5 item 7 assigns
it to a package's **last** PR. WP-45 is 1/3 and WP-11 is 1/N, so neither is last.
