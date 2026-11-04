# Lane A live verification (WP-01): consensus, economics, P2P core, state, config

Scope: every ledger row (directive sections 14.3, 14.4, 14.5, 14.6) whose closing package is WP-08, WP-12, WP-13, WP-14, WP-15, WP-16 or WP-17 (90 rows).
Live branch: `main` at `14d9a18` plus the WP-01..04 working branch `wp/01-04-live-verification`. Line numbers are deliberately not recorded; code was located by content.
Status vocabulary: see `baseline.md`. Severity suggestions use the ledger scale (Critical, High, Medium, Low). Archive rows map S2 to High and S3 to Medium.
Closing packages are written as `WP-NN` (the directive writes `İP-NN`).

Method limits: the machine has two cores and a cold build cache. Where a row says `Verified (static)` the evidence is code reading and a red repro on `audit/repro-a` is still owed. No test is claimed red unless its failure was observed (the observed output is quoted in the notes column).

Rows are written in severity order (Critical, High, Medium, Low). Special audits follow the table.

| ID | Live status | Test name | Evidence (file + function) | Closing package | Severity suggestion | English title | Notes |
|---|---|---|---|---|---|---|---|
| BLG-001 | Previously fixed | audit_lane_a_blg_001_leader_round_rerolls_seed_and_ladder_is_capped | src/consensus/pos.rs::PoSEngine::calculate_seed_with_chain (round in seed), src/consensus/mod.rs::affordable_leader_round, MAX_LEADER_ROUNDS=16, PoSEngine::validate_block round cap | WP-12 | Critical | PoS leader election cannot skip an empty height, permanent production lock | Matches ledger snapshot note (fix trace present). Round re-rolls the VRF seed (threshold is deliberately round independent). Residual: round pricing reads the verifier wall clock, see BULGU-001. Also covered by src/tests/consensus_rounds.rs and p01_consensus_rounds.rs. |
| BLG-017 | Previously fixed | audit_lane_a_blg_017_no_utf8_byte_slice_of_peer_strings_in_vote_handlers | src/network/node.rs::log_prefix used by the Prevote, Precommit and FinalityCert arms of the gossip handler | WP-15 | Critical | UTF-8 byte slicing of peer strings in unauthenticated Prevote/Precommit/FinalityCert handlers panics the node | All three arms log through char-based log_prefix; no byte slice of checkpoint_hash remains. Regression test is a source scan; behavioural lock exists in-file (network::node::tests::log_prefix_survives_multibyte_input). |
| BLG-019 | Previously fixed | audit_lane_a_blg_019_state_update_is_retired_for_every_sender | src/execution/executor.rs::Executor::apply_transaction (StateUpdate arm returns state_update_retired); src/core/account.rs validate_transaction refuses StateUpdate | WP-17 | Critical | StateUpdate lets any account write arbitrary nonces without authority or commitment | Matches ledger snapshot note. Tag stays decodable for old blocks; no new block may carry one. Also covered by byzantine_settlement::state_update_from_a_non_committer_is_refused. |
