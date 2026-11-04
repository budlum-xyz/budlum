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
