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

Numbering: `BLG-268` is taken by #24, #13 claims `BLG-268`–`BLG-275`, and
`BLG-276`–`BLG-278` are claimed by #36/#50/#68, so this row takes the next free
id, `BLG-279`.

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

## Package status

`docs/work/PACKAGES.md` is deliberately not written here: §15.5 item 7 assigns
it to a package's **last** PR. WP-45 is 1/3 and WP-11 is 1/N, so neither is last.
# WP-11 mobile continuation findings

Append-only WP-11 continuation records from PR #88. Earlier ledger sections
proposed by other open PRs must be retained at integration. No finding below
is closed: local evidence is not a substitute for the pinned-toolchain CI run
required by the closing protocol.

A live scan of open PR bodies and changed audit documents found BLG-297 as
the highest allocated identifier before this slice reserved BLG-298 through
BLG-301 in PR #88. Existing open PRs reuse some earlier identifiers for
unrelated findings; references to those records include their originating PR.

| Finding | Severity | State | Evidence and correction |
|---|---|---|---|
| BLG-298 | Medium | Open; locally corrected, CI evidence pending | `quota::fits` used saturating addition, so `fits(u64::MAX, 1, u64::MAX)` incorrectly succeeded. `mobile_quota_overflow_is_a_refusal` executed red after `224deb93d27634c28a7d53f79f72378ee12c4702`. Checked addition in `0886af28034319c96b63659b97a069e0b2af6e1e` makes it green. Policy's 64 GiB limit bounds the normal caller; the public quota helper and store still must reject arithmetic overflow. |
| BLG-299 | Medium | Open; locally corrected, CI evidence pending | Replaying one assignment allocated another local id and stored another copy. The replay regression executed red after `cf15d20726dd094eeae0fc4a339b6636fa697f7b`: expected a refusal, got `ShareRecord { id: ShareId(1), ... }`. `0886af28034319c96b63659b97a069e0b2af6e1e` refuses an existing `(object, segment, position)` or `(object, segment, ESI)` before mutation. Controls prove refusal preserves free space, quota, records and pending duties, while distinct symbols of one segment remain usable. |
| BLG-300 | Low | Open; locally corrected, CI evidence pending | `next_id.saturating_add(1)` could reuse the final local id and overwrite a record after exhaustion. `mobile_share_id_exhaustion_does_not_overwrite_a_record` executed red at `320adcfcc1877bd71fe2f6080466c4c30c30064c`. `0886af28034319c96b63659b97a069e0b2af6e1e` checks the increment before mutation and refuses exhaustion. The final control also preserves an existing record and the counter. This is a local-store boundary, not a chain share identifier. |
| BLG-301 | Medium | Open; locally corrected, CI evidence pending | The inherited mobile suite did not compile on stable Rust 1.99.0: `sig.as_slice()` on an existing byte slice triggered E0658. `cf15d20726dd094eeae0fc4a339b6636fa697f7b` removes the extra call. All-target Clippy also reported `manual_range_contains` in `Policy::set_quota`; `b041519678e16914823df3e3395d85f2537a6a1e` uses the equivalent inclusive-range check without a lint exemption. The local suite and strict Clippy now pass; Rust 1.97.1 and CI remain unverified. |

## Existing compatibility findings, not renumbered

- **PR #77 / BLG-289:** PR #85 scopes audit selection to the named object.
  `ef5b471cdb78300dfbd55ff2e6b1eaa6ce6a2935` retains that object in every
  returned `(object, proof)` pair. A two-object, identical-symbol regression
  executed red before the latter correction and is green afterward. This
  fixes the local selection/retention legs only. Shared types, signed wire
  round trips and node integration evidence remain outstanding.
- **PR #77 / BLG-288:** the mobile and PR #70 node presence preimages still
  differ. The G-5 vector is locked in `tests/vectors/presence/v1/` and checked
  by `presence_preimage_matches_shared_golden_vector`. No node source is
  silently changed to conceal the unresolved incompatibility.
- **PR #77 / BLG-290:** mobile release duties still carry process-local ids,
  while PR #45 proposes an object/optional-segment/quota-delta payload. The
  directive requires chain share identities and a new quota. These contracts
  must be reconciled before a valid mobile release transaction can be built.

Detailed red/green output, source/toolchain caveats, scope constraints and the
remaining integration blockers are in `MOBILE_CORE_REVIEW.md`. No performance
measurement, package completion or testnet readiness is claimed.
