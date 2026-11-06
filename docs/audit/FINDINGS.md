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
| BLG-063 | Critical | Closed | `privacy_transfers_enabled` admitted testnet (`45261`), so the unproven private-note mint/spend path was reachable there. The allowlist is now devnet-only; testnet refuses with `privacy_testnet_closed`. Mainnet keeps its historical `privacy_mainnet_disabled` code and message. | `src/execution/executor.rs` `privacy_transfers_enabled`, `privacy_closed_refusal` | `blg_063_privacy_allowlist_excludes_testnet`, `private_transfer_is_closed_on_testnet`, `note_registry_is_closed_on_testnet` | WP-45 (1/3) |
| BLG-225 | High | Closed by testnet closure | Ownership, conservation and membership proofs are still unbound on the private-transfer path. That path is now unreachable on testnet and mainnet and runs on devnet only. **The proof binding itself is not built** and stays open under WP-56. | same guard as BLG-063 | `private_transfer_is_closed_on_testnet`, `note_registry_is_closed_on_testnet` | WP-45 (testnet foot); WP-56 keeps the proof foot |
| BLG-228 | High | Closed by testnet closure | `AiAttachExecutionProof` ran with `FULL_AI_STARK_VERIFICATION_LIVE = false`. All 17 AI doors now refuse on testnet with `ai_layer_testnet_closed`. **Full STARK verification is not built** and stays open under WP-57. | `src/execution/executor.rs` `ai_layer_enabled`, `is_ai_layer_transaction` | `ai_execution_proof_is_closed_on_testnet`, `ai_layer_is_closed_on_testnet` | WP-45 (testnet foot); WP-57 keeps the verification foot |
| BLG-229 | High | VL-1 leg: closed decision | The card lets the AI layer open at VL-1 only with BLG-059..062 closed **and** both VL-1 conditions built. Per-request lottery and commit-reveal are absent from the tree, so the layer does not open. The decision is recorded in the `ai_layer_enabled` doc comment. **The lottery/commit-reveal itself is not built.** | `src/execution/executor.rs` `ai_layer_enabled` doc comment | `ai_layer_is_closed_on_testnet` (17 doors, three chain ids, byte-identical state) | WP-45 (VL-1 decision); WP-57 keeps the build |
| BLG-240 | Low | Closed | Verifier/agent ranking ordered on `f64`. Sort keys are now integer permyriad with an address tie-break - a total order, no `partial_cmp`. `agents_by_trust_score_permille` returns the integer instead of re-quantizing a float at the boundary that existed to stay float-free. The `f64` columns remain as display only. | `src/ai/types.rs` `reliability_score_permyriad`, `trust_score_permyriad`; `src/ai/registry.rs` `verifiers_by_reliability`, `agents_by_trust_score` | `ai_ranking_uses_integers`, `ai_ranking_breaks_ties_by_address`, `ai_ranking_saturates_instead_of_overflowing`, `ai_ranking_integer_matches_display_within_one_basis_point`, `reliability_permyriad_is_exact_and_bounded`, `trust_permyriad_weights_are_forty_sixty`, `permyriad_scores_are_total_over_extreme_counters`, `a_ratio_above_one_caps_at_the_basis` | WP-45 (1/3) |

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
Exact counts are deliberately not recorded here: they change with every push
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
| BLG-151 | High | Assigned to **WP-17**, with three feet: the NUL-separated wire-framing collision and dropped V4-V6 transaction / PoS-BFT header fields in `core::encoding`, the `address.rs` parse contract, and the AI system-prompt production-refusal gate bypass. **#43 is closing the `address.rs` foot**, not WP-11: #44 moved the definition verbatim and deliberately pins no input contract. That foot's body now lives at `crates/budlum-types/src/lib.rs`; the `encoding.rs` and `system_prompt.rs` feet are untouched here. |
| BLG-022 | Medium | `LightClient::next_checkpoint_height` overflow. WP-11 job 3, blocked: `src/light_client/` is held by #9. |
| BLG-257 | High | No mobile application exists; the mobile profile is still only a node CLI flag. WP-11 jobs 2-9 and WP-36. |
| BLG-259 | Medium | Checkpoint certificate size and the undocumented trust model. WP-11 job 3, blocked by #9. |

## New rows

| Identity | Severity | Row | Owner | Status |
|---|---|---|---|---|
| BLG-279 | Medium | A second `Address` definition survives in the VM workspace: `budzero/verifier-registry/src/address.rs:9` derives `Serialize`/`Deserialize` over `pub struct Address(pub [u8; 32])`, so it encodes as a 32-element byte array, while `core::address::Address` hand-writes a bare hex string. K-4 says wallet, chain and VM call one definition. `SlashingReport` (`evidence.rs:65`) and `Registration` (`registry.rs:106`) derive serde over that field, so the two workspaces already disagree on the JSON shape of the same concept. | WP-33 (owns the crate), coordinate with WP-11 job 1 | **Open: recorded, not closed here.** |

Numbering: `BLG-268` is taken by #24, #13 claims `BLG-268` to `BLG-275`, and
`BLG-276` to `BLG-278` are claimed by #36/#50/#68, so this row takes the next free
id, `BLG-279`.

Why this PR does not fix it: nothing depends on `verifier-registry` today (it is
a leaf member of the `budzero` workspace), so no wire crosses yet and there is
no live bug. Swapping in the shared type would change that crate's encoded form
from an array to a string, a wire change, which §15.5 requires to be declared
and reviewed on its own, not smuggled into a K-4 move. The crate is also partially
held by #24 (`params.rs`, `tests/regression.rs`).

What is closed here is the drift hazard on the node side:
`address_json_is_a_hex_string_not_a_byte_array` in `src/core/address.rs` pins the
hex-string form and asserts the array form stays refused, so a future dedup that
substitutes the derived encoding fails a test instead of the database.

## Package status

`docs/work/PACKAGES.md` is deliberately not written here: §15.5 item 7 assigns
it to a package's **last** PR. WP-45 is 1/3 and WP-11 is 1/N, so neither is last.

## WP-11 (2/N): budlum-types carries the class and the presence message

### Closed rows

| Identity | Severity | Status | Foot this PR closes | Evidence | Test | Closing package |
|---|---|---|---|---|---|---|
| BLG-022 | Medium | Previously fixed | The infinite loop at `u64::MAX` and the O(interval) walk are gone on `main` already: `LightClient::next_checkpoint_height` is one division (`start % interval`) with `checked_add`, and returns `None` instead of wrapping. The open row above (written by WP-11 1/N) said job 3 was blocked by #9; no change to `src/light_client/` is needed to close it. | `src/light_client/mod.rs` `next_checkpoint_height`, present at `cccf1da` | `next_checkpoint_height_is_closed_form` (calls it with `u64::MAX` interval and target, and from a `u64::MAX` anchor), `sync_plan_targets_the_next_checkpoint` | WP-11 (2/N) |

### New rows

| Identity | Severity | Row | Owner | Status |
|---|---|---|---|---|
| BLG-301 | High | Two open PRs define the presence message (section 7.8 item 2) with different bytes. #70 (`src/validators/presence.rs:75`, head `d611e8aa`) length-prefixes every field as G-5 requires: `tag \|\| 8u64 \|\| chain_id \|\| 8u64 \|\| window \|\| 1u64 \|\| class`. #45 (`src/registry/presence.rs:103-106`, head `3fdcf11d`) hashes `tag \|\| chain_id \|\| window \|\| class` with no prefixes and carries its own `PresenceClass` enum (line 47) beside `ValidatorClass` (K-4, V-5). For chain 45261, window 7, class Mobile the digests are `d8d5ba6f...` and `6772963e...`: a phone signing one layout is absent to a node verifying the other, and is suspended after 72 hours. | WP-13 (node side), WP-11 (definition) | **Definition closed here, call sites open.** `budlum-types::presence::presence_message` is now the single definition, byte-compatible with #70's layout and pinned by vectors computed outside the code (`presence_message_matches_independent_vectors`, `the_unprefixed_layout_is_not_the_presence_message`). The node side closes when `src/validators/presence.rs` calls it instead of its own copy. |
| BLG-302 | High | #70's `src/validators/presence.rs` does not compile at head `d611e8aa`: `seen_signatures` is declared `BTreeMap<[u8; 32], Vec<(u64, Vec<u8>)>>` (line 135), but is read with a `([u8; 32], u64)` key and compared with a `Vec<u8>` (line 175), written with that key and a `Vec<u8>` value (line 196), and retained with a tuple-key pattern (line 291). `[u8; 32]` does not implement `Borrow<([u8; 32], u64)>`, so `get` and `insert` fail type checking. | WP-13 (#70) | **Open, recorded, not fixed here**: the file is outside this package's lock paths. The type the rest of the file assumes is `BTreeMap<([u8; 32], u64), Vec<u8>>`. |

| BLG-303 | Medium | #44 (WP-11 1/N and WP-45 1/3, the base of this PR) wrote Turkish characters and typographic dashes into the tree: the Turkish word for "closed" spelled with U+0131 (dotless i) and the work package abbreviation spelled with U+0130 (dotted capital I) in `docs/audit/FINDINGS.md`, a new file that is not on `.github/turkish-baseline.txt`; the same abbreviation in `src/execution/executor.rs:4458`; and U+2013 and U+2014 dashes in the same ledger. `tree_is_english` fails on a Turkish character in an unlisted file and `no_unicode_dashes` fails on any of its 13 dashes, so both gates go red on #44. | WP-11 | **Closed here.** The status words are English (`Closed`, `Previously fixed`), work packages are written `WP-NN`, and the dashes are ASCII. Checked by scanning every file this branch changes for the twelve characters `tree_is_english` lists and the 13 code points `no_unicode_dashes` lists: none left. |
| BLG-304 | Medium | `tree_is_english` cannot pass on `main` (`cccf1da`): `THE_BUDLUM_DIREKTIF.md` (6044 lines of Turkish) and `arena_claude.py` carry Turkish and are neither in `ALLOWED_FILES` nor on the baseline. Directive section 0.1 item 5 says the directive does not enter the repository. #36 and #45 delete the file; adding it to the allow list or the baseline would be a gate weakening (S-2). | Repository owner | **Open, recorded.** This PR keeps the file: the owner placed it in the tree and points agents at it, so removing it is the owner's call, not a work package's. |

Numbering: `BLG-268`-`BLG-279` are already claimed by parallel PRs (#13, #24,
#36, #44, #50, #68), some of them twice. This package takes the block from
`BLG-301` so that a later parallel claim of `BLG-280`+ cannot collide with it.

Not fixed in this slice and still open: BLG-257 (no mobile application) and
BLG-259 (certificate size and the undocumented light-client trust model). Both
belong to the later slices of this package that add `mobile/core` and
`docs/LIGHT_CLIENT.md`.
