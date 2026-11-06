# Findings ledger

The single findings ledger of the directive (section 14). The register of
BLG-001 to BLG-267 is written in the directive itself; this file carries the
findings found after it, from BLG-268 on, and the closure record of every finding
whose fix has merged.

## Rules

1. An identity (`BLG-NNN`) is never reused and never renumbered.
2. Severity is Critical, High, Medium or Low.
3. Status is `open`, `confirmed` (open and reproduced), `closed` (the fix merged),
   `closed by removal` (the code is gone) or `invalid` (the condition no longer
   exists, with evidence).
4. Live verification of BLG-001 to BLG-267 belongs to WP-01 to WP-04, and its
   output is `docs/audit/LIVE_STATUS.md`.
5. Closure protocol: the required test is written first, the fix makes it green,
   the pull request carries both, and the row then names the merge commit and the
   CI run number. A row without those two references is a claim, not a closure.
6. A new finding is written here with the next free identity, and the row names
   the package that closes it.

## Closure record

WP-61 (lane D, RPC and crypto hardening) locks the thirteen findings of its card.
Nine were already fixed in the analysed snapshot, so directive section 14.1 item 7
applies: the finding is closed by the test that stays in the tree, and the note
says `pre-fixed`. The state below is written against `origin/main`
`cccf1da1f4bcfe97503a3a00cfba24b172b49b31`. Closure takes effect when the pull
request merges; the merge commit and the CI run number are written into these rows
by that merge, and no row below claims one.

The branch carrying these rows is `arena/e55d486b-budlum`, pull request #41, head
commit recorded in `docs/work/PACKAGES.md`.

| Identity | Severity | Status | Lock | Note |
|---|---|---|---|---|
| BLG-004 | Medium | pre-fixed, locked here | `blg_004_validator_key_save_resets_a_wide_mode` (`src/crypto/primitives.rs`) | `write_key_file` creates a sibling with `create_new` and mode `0o600`, syncs, then renames, so the mode of the replaced file is never kept. The snapshot held the rule for `KeyPair`; the validator key file, which also carries the BLS and PQ secrets, is now driven by the same assertion. |
| BLG-009 | Medium | pre-fixed, locked here | `blg_009_an_unregistered_context_or_scheme_is_refused_before_the_keys` (`src/crypto/pq.rs`) | `check_context` refuses an empty, an over-long and an unregistered context, and `verify` takes the scheme identifier as an argument instead of inferring it from a key length. |
| BLG-010 | Medium | pre-fixed, locked here | `blg_010_a_slot_with_more_than_one_key_is_refused_not_guessed` (`src/crypto/pkcs11.rs`) | `connect` binds `key_label` before the key is read, and `require_single_key` refuses a slot holding more than one Ed25519 key. |
| BLG-029 | High | pre-fixed, locked here | `blg_029_a_forged_forwarded_for_entry_buys_no_fresh_quota` (`src/rpc/server.rs`) | `extract_client_ip` answers with the rightmost `X-Forwarded-For` entry, the one the trusted proxy appended, and the quota table is keyed on it, so a forged left entry neither escalates privileges nor resets the window. |
| BLG-030 | Critical | pre-fixed for the grant rows, locked here | `blg_030_view_grant_writes_refuse_and_name_their_transaction_door` (`src/rpc/tests.rs`) | The chain actor answers `IssueViewGrant`, `RevokeViewGrant` and `SocialDelete` with the transaction door and mutates nothing; the read side still answers, so a refusal is not an outage. The faucet half belongs to WP-41. |
| BLG-032 | Medium | pre-fixed, already locked | `prepare_templates_carry_valid_nonce_and_fee` (`src/rpc/server.rs`) | `finish_template` overwrites the nonce with the sender's next nonce and the fee with `required_fee`, and sets `max_fee` to the same value, for every `Prepare` template. |
| BLG-099 | High | pre-fixed, locked here | `blg_099_the_api_key_compare_never_early_returns_on_length` (`src/rpc/server.rs`) | The compare walks the expected key, folds the length difference into the accumulator and clamps the candidate index, so a length mismatch costs the same work as a byte mismatch and no same-buffer self-comparison remains. |
| BLG-150 | Critical | signer feet pre-fixed, locked here; the nullifier feet are open | `blg_150_block_prevote_and_precommit_signatures_are_not_interchangeable` (`src/crypto/signer.rs`) | `sign_prevote` and `sign_precommit` hash their own `BDLM_*_ED25519_V1` tag and each verifies over its own domain. The `nullifier == 0` feet live in `src/privacy/` and `src/relayer/`, which are outside the WP-61 lock set, so they stay open for their owning packages. |
| BLG-192 | High | pre-fixed, locked here | `blg_192_estimate_gas_carries_the_proportional_cut` (`src/rpc/tests.rs`) | `estimate_gas` answers `tx.fee.max(required_fee)`, and `required_fee` adds the proportional cut of `required_transfer_fee` to the floor. |
| BLG-200 | Critical | key material half pre-fixed, locked here; the aggregator and RLP feet are open | `blg_200_zero_and_identity_bls_material_is_refused` (`src/crypto/primitives.rs`) | `from_seed` refuses a seed that reduces to the zero scalar; `from_bytes` demands an exact length, refuses a zero secret and re-derives the public half, so the identity encoding is refused by the pairing check and not by a failed decode. The `FinalityAggregator` foot is in `src/chain/finality.rs`, held by WP-12, and the depth-unbounded RLP foot is in `src/cross_domain/evm/rlp.rs`, held by WP-44. |
| BULGU-011 | Medium | pre-fixed, already locked | `cors_wildcard_does_not_reflect_headers` (`src/rpc/server.rs`) | A `*` configuration answers with the literal `*`; the caller's `Origin` is never echoed, and no credentials grant is sent. |
| BULGU-012 | Low | pre-fixed, already locked | `rpc_serialization_error_is_explicit` (`src/rpc/server.rs`) | A value that cannot be encoded is a `-32603` error naming the field, not a `null` that reads as absent. |
| TEST-GAP-07 | High | ratchet delivered, gap recorded | `rpc_every_method_has_success_and_refusal_test` and `rpc_method_coverage_catches_an_injected_gap` (`src/rpc/method_class.rs`), `.github/rpc-method-coverage-baseline.txt` | 183 rows in the method table; 31 rows have the answer test and the refusal test the rule can see, 152 rows carry 264 gap lines. The file only shrinks, so the gap cannot grow and every delivery that adds RPC tests lowers it. Closing TEST-GAP-07 needs the remaining rows covered, in later WP-61 pull requests. |

## New findings

None. WP-61 found no new defect in this range. BLG-268 to BLG-275 are recorded by
WP-20 in its own pull request and stay open there.
