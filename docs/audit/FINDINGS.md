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
| BLG-228 | High | Closed by testnet closure | `AiAttachExecutionProof` ran with `FULL_AI_STARK_VERIFICATION_LIVE = false`. All 17 AI doors now refuse on testnet with `ai_layer_testnet_closed`. **Full STARK verification is not built** and stays open under İP-57. | `src/execution/executor.rs` `ai_layer_enabled`, `is_ai_layer_transaction` | `ai_execution_proof_is_closed_on_testnet`, `ai_layer_is_closed_on_testnet` | WP-45 (testnet foot); İP-57 keeps the verification foot |
| BLG-229 | High | VL-1 leg: closed decision | The card lets the AI layer open at VL-1 only with BLG-059..062 closed **and** both VL-1 conditions built. Per-request lottery and commit-reveal are absent from the tree, so the layer does not open. The decision is recorded in the `ai_layer_enabled` doc comment. **The lottery/commit-reveal itself is not built.** | `src/execution/executor.rs` `ai_layer_enabled` doc comment | `ai_layer_is_closed_on_testnet` (17 doors, three chain ids, byte-identical state) | WP-45 (VL-1 decision); İP-57 keeps the build |
| BLG-240 | Low | Closed (Kapalı) | Verifier/agent ranking ordered on `f64`. Sort keys are now integer permyriad with an address tie-break - a total order, no `partial_cmp`. `agents_by_trust_score_permille` returns the integer instead of re-quantizing a float at the boundary that existed to stay float-free. The `f64` columns remain as display only. | `src/ai/types.rs` `reliability_score_permyriad`, `trust_score_permyriad`; `src/ai/registry.rs` `verifiers_by_reliability`, `agents_by_trust_score` | `ai_ranking_uses_integers`, `ai_ranking_breaks_ties_by_address`, `ai_ranking_saturates_instead_of_overflowing`, `ai_ranking_integer_matches_display_within_one_basis_point`, `reliability_permyriad_is_exact_and_bounded`, `trust_permyriad_weights_are_forty_sixty`, `permyriad_scores_are_total_over_extreme_counters`, `a_ratio_above_one_caps_at_the_basis` | WP-45 (1/3) |

### Evidence commits and CI status

Closing commit for every row above: `2f03e59673386737bd61f3c781de42505af50b7f`
(WP-45 slice 1, PR #44). Test-first commit: `69dbd8021f65ae2b7f86e8b8bf484c096760b2fe`
- tests only, red by construction, since the functions they call do not exist
at that commit.

**CI run: not yet available, and none is claimed.** This sandbox has no Rust
toolchain and `static.rust-lang.org` is outside the allowed egress, so no local
`cargo test` log exists. Per S-1, CI is the sole validator. The branch's runs
are currently 56 `cancelled` (the workflow sets `cancel-in-progress` on non-main
refs, so each push cancels the previous run) and 24 still pending; the
failure-filtered list is empty. **No row above is validated by a completed green
run yet**, and this ledger must be amended with the run number when one
completes. Self-report is not evidence (§0.3 item 5).

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

None. Neither package found anything the §14 ledger did not already carry, so
the `BLG-268` new-finding counter is untouched.

## Package status

`docs/work/PACKAGES.md` is deliberately not written here: §15.5 item 7 assigns
it to a package's **last** PR. WP-45 is 1/3 and WP-11 is 1/N, so neither is last.
