# Lane A live audit: initial observations

This is a partial audit, not a completed WP-01 or a finding closure. The
observations below are from source inspection of main at
`20140e87061efc9d8d4076e04305c1318705e348`. The other lane A findings have not
yet been audited. No red reproduction, green regression run, or live network
measurement is claimed here.

| Finding | Source observation | Existing or added test | Closing package | Severity in directive | Evidence still needed |
| --- | --- | --- | --- | --- | --- |
| BLG-001 | `src/consensus/pos.rs` derives and checks leader rounds using `affordable_leader_round` and a cap. | `src/tests/consensus_rounds.rs`: `pos_seed_binds_the_round`, `pos_validate_rejects_round_above_the_cap` | WP-12 | Critical | Run the regression and verify progress after an empty height. |
| BLG-006 | `Blockchain::apply_epoch_reward_pool` calls `reward_pool::pay_epoch`; the transition calls `apply_epoch_reward_pool`. | `src/tokenomics/reward_pool.rs`: `an_epoch_moves_its_budget_from_the_pool_to_the_validators_by_stake` | WP-16 | Medium | Verify end-to-end epoch payment in a passing CI run and the expanded pool policy. |
| BLG-019 | `Executor::apply_transaction_checked` rejects `TransactionType::StateUpdate` with `state_update_retired`. | `audit_lane_a_blg_019_retired_state_update_preserves_accounts` covers testnet and devnet, multiple nonce targets, and account balances; existing `state_update_from_a_non_committer_is_refused` covers a victim. | WP-17 | Critical | Run both tests in CI; review admission and replay boundaries before assigning a final live status. |
| BLG-246 | `ValidatorSetSnapshot::quorum_count` counts all validators; `check_prevote_quorum` and `check_precommit_quorum` require both count and stake quorum. Certificate verification also checks count. | No red reproduction run. | WP-12 | Critical | Reproduce with an offline mobile majority on a separate non-merging audit branch and record the CI run. |
| BLG-251 | `LivenessTracker::record_epoch` constructs `SlashingReport::consensus_liveness` after consecutive missed epochs. | `src/registry/liveness.rs` contains liveness tests; no red reproduction run. | WP-13 | High | Trace report enforcement and reproduce the mobile-absence policy violation. |
| BLG-264 | The exact string `WIRING:` occurs 14 times in `src/consensus/filiz.rs` and 7 times in `src/consensus/handoff.rs` at the audited commit. Markers alone do not establish whether individual paths are live. | No red reproduction run. | WP-12 | High | Trace each production caller and run the required network test. |

BLG-018 needs a four-node finalized-height experiment; no such experiment was
run. The complete lane inventory, external finding-ledger evidence, status
classification, reproduction branch and CI run numbers remain outstanding.
