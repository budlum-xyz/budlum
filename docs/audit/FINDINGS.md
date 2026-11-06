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

## WP-11 (budlum-types line, #91): the class, the presence message and the signal

### Closed rows

| Identity | Severity | Status | Foot this PR closes | Evidence | Test | Closing package |
|---|---|---|---|---|---|---|
| BLG-022 | Medium | Previously fixed | The infinite loop at `u64::MAX` and the O(interval) walk are gone on `main` already: `LightClient::next_checkpoint_height` is one division (`start % interval`) with `checked_add`, and returns `None` instead of wrapping. The open row above (written by WP-11 1/N) said job 3 was blocked by #9; no change to `src/light_client/` is needed to close it. | `src/light_client/mod.rs` `next_checkpoint_height`, present at `cccf1da` | `next_checkpoint_height_is_closed_form` (calls it with `u64::MAX` interval and target, and from a `u64::MAX` anchor), `sync_plan_targets_the_next_checkpoint` | WP-11 (2/N) |

### New rows

This PR takes identifiers from `BLG-350`. A live scan of open PR bodies and
branches when it was stacked on #88 found `BLG-280` to `BLG-301` allocated,
some twice (#88's `BLG-298` to `BLG-301` among them), so a block well above the
highest one keeps a parallel claim from colliding with these rows.

| Identity | Severity | Row | Owner | Status |
|---|---|---|---|---|
| BLG-350 | High | Three open PRs hash the presence message (section 7.8 item 2) three ways. The mobile core (#82, #88, `tests/vectors/presence/v1/`) length-prefixes all four fields, the domain tag included, as G-5 says ("every hash input is length-prefixed"). #70 (`src/validators/presence.rs:75`, head `d611e8aa`) leaves the tag unprefixed. #45 (`src/registry/presence.rs:103-106`, head `3fdcf11d`) prefixes nothing and adds a second class enum, `PresenceClass` (line 47), beside `ValidatorClass` (K-4, V-5). For chain 45261, window 11, class Mobile the digests are `26a5bec8...` (mobile), `f14a3db5...` (#70) and `209eb03a...` (#45): a phone is absent to either node and is suspended after 72 hours. The mobile core also carried its own `ValidatorClass` and preimage beside the node's (K-4). #77 records the mobile-versus-#70 leg as BLG-288; this row adds #45's layout and the duplicate definitions. | WP-11 (definition), WP-13 (node call sites) | **Definition and mobile side closed here; node side open.** `budlum-types::presence` is the single definition of the preimage, the message, the signal and the network hint, in the mobile layout, and reads the shared vector files in its tests (`presence_message_matches_the_shared_vector`, `presence_message_matches_independent_vectors`, `the_other_layouts_are_not_the_presence_message`). `mobile/core` now re-exports it and its own copies are gone. #70 and #45 close the row by calling `budlum_types::presence::presence_message` instead of their own copy. |
| BLG-351 | High | #70's `src/validators/presence.rs` does not compile at head `d611e8aa`: `seen_signatures` is declared `BTreeMap<[u8; 32], Vec<(u64, Vec<u8>)>>` (line 135), but is read with a `([u8; 32], u64)` key and compared with a `Vec<u8>` (line 175), written with that key and a `Vec<u8>` value (line 196), and retained with a tuple-key pattern (line 291). `[u8; 32]` does not implement `Borrow<([u8; 32], u64)>`, so `get` and `insert` fail type checking. | WP-13 (#70) | **Open, recorded, not fixed here**: the file is outside this package's lock paths. The type the rest of the file assumes is `BTreeMap<([u8; 32], u64), Vec<u8>>`. |
| BLG-352 | Medium | #44 (WP-11 1/N and WP-45 1/3) wrote Turkish characters and typographic dashes into the tree: the Turkish word for "closed" spelled with U+0131 (dotless i) and the work package abbreviation spelled with U+0130 (dotted capital I) in this file, which is new and not on `.github/turkish-baseline.txt`; the same abbreviation in `src/execution/executor.rs:4458`; and U+2013 and U+2014 dashes in this file. `tree_is_english` fails on a Turkish character in an unlisted file and `no_unicode_dashes` fails on any of its 13 dashes, so both gates go red on #44. | WP-11 | **Closed here.** The status words are English (`Closed`, `Previously fixed`), work packages are written `WP-NN`, and the dashes are ASCII. Checked by scanning every file this branch changes for the twelve characters `tree_is_english` lists and the 13 code points `no_unicode_dashes` lists: none left. |
| BLG-353 | Medium | `tree_is_english` cannot pass on `main` (`cccf1da`): `THE_BUDLUM_DIREKTIF.md` (6044 lines of Turkish) and `arena_claude.py` carry Turkish and are neither in `ALLOWED_FILES` nor on the baseline. Directive section 0.1 item 5 says the directive does not enter the repository. #36, #45, #78 and #87 delete the file; adding it to the allow list or the baseline would be a gate weakening (S-2). | Repository owner | **Open, recorded.** This PR keeps the file: the owner placed it in the tree and points agents at it, so removing it is the owner's call, not a work package's. |
| BLG-354 | Medium | The `domain_tags` gate scanned `src`, `budzero`, `crates` and `bud`, so the mobile core under `mobile/` was outside it. It carried `BDLM_PRESENCE_V1` and `BDLM_PRESENCE_HINT_V1`, neither in the inventory (G-5: every tag is in the inventory), and the gate stayed green. | WP-11 | **Closed here.** The gate scans `mobile` too, with a self-test canary that plants an unlisted tag under `mobile/core/src` and must be caught. Both presence tags are in `src/crypto/domain_tags.rs`, and their one definition is in `budlum-types`. |
| BLG-355 | Low | `mobile/core/src/lib.rs` opened with `#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]`, a new suppression (S-2). The root `clippy.toml` already allows both lints inside `#[test]` bodies and `#[cfg(test)]` modules, which is where the crate's tests live, so the attribute only widened the exemption. | WP-11 | **Closed here**: the attribute is removed. The integration tests in `mobile/core/tests/` call `expect` only inside `#[test]` functions. |

| BLG-356 | Medium | `MobileCore::set_policy` (#82, `mobile/core/src/duty.rs`) checked only the 1 GiB to 64 GiB user range, so an opportunistic (iOS) core accepted a quota up to 64 GiB. Section 7.2 caps that class at 8 GiB and the node refuses a larger registration (`MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES`): the phone would hold and advertise custody it cannot register. | WP-11 | **Closed here, not executed.** `set_policy` refuses a quota above `ValidatorClass::max_custody_quota_bytes()` with `mobile_quota_above_class_cap`, before any share is released. Test first: `mobile_opportunistic_quota_is_capped_at_8_gib` (`1819dc7b`), fix in the next commit. |

Not fixed in this PR and still open: BLG-257 (no mobile application), which
belongs to the bindings and to WP-36 and WP-38, and BLG-259. BLG-259 has two
legs. The trust-model leg is answered by `docs/LIGHT_CLIENT.md` (BLS at every
checkpoint, ML-DSA-65 at every set change, the post-quantum half required on
mainnet, sizes computed from the signature sizes). The size leg (about 420 KB
per post-quantum certificate at 128 seats) stays open with WP-12, which owns
the certificate format, so the row is not closed.

## WP-11 (#82, #85, #88): mobile core duty engine, carried intact

The rows below are PR #88's ledger section, carried verbatim when this PR
was stacked on #88 (only the heading levels changed, so the section nests
under this file's title). The identifiers are #88's.

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

### Existing compatibility findings, not renumbered

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
