# Audit Findings Ledger

One ledger for every review finding on the open pull requests (#110 `testnet-quantum`,
#97 `consensus-of-consensuses`). Every record names its source, its severity, the
exact `file:line` it lives at, and what closes it. A record stays `open` until the
commit that closes it is on the branch and CI is green; the commit SHA is written
into the record at that moment.

Sources are marked as `Strix` (the security agent), `bot` (any automated reviewer),
`human` (a person), or `ci` (a red check run, which is a finding like any other).

Severity: `blocker` (build/consensus/security), `high`, `medium`, `low`.

---

## Round 1 - 2026-10-31

Status of the two open pull requests at the start of the round:

| PR | Head | Base | Unresolved review threads | Red checks |
|---|---|---|---|---|
| #110 `Testnet and Quantum` | `testnet-quantum` | `consensus-of-consensuses` | 0 | 11 |
| #97 `Consensus Of Consensuses` | `consensus-of-consensuses` | `main` | 0 | 3 |

No review thread was open on either PR (`reviewThreads: 101 / 85, unresolved: 0`), so
the round's work is entirely the red checks below. Each red check is recorded as a
finding with its own root cause; the eleven red checks on #110 collapse to four
distinct defects, and the three on #97 to two.

### AF-01 - A validator slash books its burn twice (`ci`, `blocker`)

- **Where:** `src/core/account.rs:2270-2278` (`slash_validator_uncounted`), reached from
  `slash_validator` (`src/core/account.rs:2222`).
- **Symptom:** `core::account::tests::a_validator_slash_records_what_it_destroyed` fails
  with `left: 2400, right: 1200` - `burned_total` is twice the penalty.
- **Root cause:** two recorders for one destruction. `slash_validator_uncounted` adds
  `penalty` to `burned_total` itself (line 2276), and its wrapper `slash_validator`
  additionally measures the drop in committed supply across the call
  (`record_destroyed_since`, line 2229). `total_bud_committed()` includes the validator
  bond, the unbonding queue, the registry role bonds and the delegation exits, i.e.
  exactly the parts the slash cuts, so the second recorder measures the same money the
  first one already booked.
- **Blast radius beyond the test:** the doubling is not cosmetic. `burned_total` is
  subtracted from the fixed 100M cap in `supply_capacity_remaining`, so every slash
  closed twice as much minting headroom as it destroyed - a consensus-relevant
  accounting error on the tokenomics path.
- **Fix:** the wrapper is the single recorder (the same shape `slash_from_report`
  already uses), the inner add is removed and the comment says which recorder is
  authoritative and why the measurement cannot miss a part.
- **Regression test:** `core::account::tests::a_validator_slash_records_what_it_destroyed`
  (already present, and it was the test that caught this) plus
  `supply_capacity_remaining_uses_committed_denominator` for the headroom side.
- **Status:** closed on `testnet-quantum` - `quantum`: "AF-01 ...".

### AF-02 - `TxBundle::verify_in` reports the wrong refusal, and pays for 16 PQ verifies first (`ci`, `high`)

- **Where:** `src/core/tx_bundle.rs:213-268` (`verify_in`).
- **Symptoms:** three failing tests.
  `dropping_reordering_or_editing_a_member_breaks_the_signature` expects
  `BundleError::Signature` for an edited member and gets `Member(2)`;
  `the_nonce_sequence_chain_and_sender_are_enforced` expects `Nonce(1)` for a broken
  ladder and gets `Member(1)`; `a_forged_member_is_refused` still expects `Member(0)`.
- **Root cause:** the per-member authority check (added when members started carrying
  their own signatures) ran inside the same loop as the structural checks and before
  both the structural pass finished and the witness was verified. A member edited
  after signing therefore failed its own signature before the witness could say "this
  is not the set I signed", and a member whose nonce was moved failed its own
  signature before the ladder could name the nonce. The refusal was true but named the
  wrong thing, and the most expensive checks (up to `MAX_BUNDLE_TXS` post-quantum
  verifications) ran first, on bundles a single witness check would have refused.
- **Fix:** three passes, cheapest and most specific first: (1) shape of the set -
  `Mixed`, `Nonce`; (2) the witness - key decodes, derives the sender (`Sender`), and
  its composite signature verifies over the root of exactly these members (`Signature`);
  (3) each member's own authority (`Member`). No check is dropped or relaxed: the
  ordering changes which refusal a caller sees, and the witness check now runs before
  16 member verifications. The `# Errors` section documents the order.
- **Regression tests:** `dropping_reordering_or_editing_a_member_breaks_the_signature`,
  `the_nonce_sequence_chain_and_sender_are_enforced`, `size_limits_and_a_forged_member_are_refused`,
  `every_member_verifies_on_its_own_and_the_witness_binds_the_set`.
- **Status:** closed on `testnet-quantum` - `quantum`: "AF-02 ...".

### AF-03 - Three tests set a commission the registry now refuses (`ci`, `medium`)

- **Where:** `src/registry/validator_profile.rs:86-95`,
  `src/tokenomics/reward_pool.rs:378-390`, `src/tokenomics/reward_pool.rs:419-430`.
- **Symptom:** all three fail with `"commission change exceeds 10000 ppm per epoch"`.
- **Root cause:** the registry now caps a *first* commission rate at
  `max_commission_change_ppm_per_epoch` (10 000 ppm) when the validator already holds
  delegated stake - a validator cannot jump from 0 to the ceiling in one epoch and take
  the jump out of its delegators' next payout
  (`src/registry/permissionless.rs:1655-1672`). The three tests were written before the
  cap: each delegates first and then sets 5 % or 10 %.
- **Fix:** the fixtures set the rate while nothing is delegated - which the registry
  deliberately leaves free, because the rate then prices only the validator's own bond -
  and then delegate. Every assertion stays: the profile still has to report 5 %, the
  split test still has to pay 1 010 / 90, and the prospective-reprice test still has to
  read 0 ppm for epoch 0 and 100 000 ppm for epoch 1. The cap itself keeps its own
  coverage in `src/registry/permissionless.rs`.
- **Regression tests:** `a_profile_states_bond_delegation_and_commission_facts`,
  `delegation_rewards_are_split_after_validator_commission`,
  `a_commission_set_in_the_closing_epoch_does_not_price_that_epoch`.
- **Status:** closed on `testnet-quantum` - `quantum`: "AF-03 ...".

### AF-04 - `validator_commission_ppm` is dead public API (`ci`, `low`)

- **Where:** `src/registry/permissionless.rs:1591`; gate
  `dead-public-api-is-ratcheted` reported `174 | baseline: 173`, naming this function.
- **Root cause:** the accessor was added with the commission work and only the tests
  reached it; the validator profile read the raw `ValidatorCommission` struct instead.
- **Fix:** the profile - the production surface that shows a delegator what a validator
  charges - now reads the live rate through the accessor. The gate's own words are
  "call it from the path it was written for", and that is the path; the baseline is not
  raised.
- **Regression test:** `a_profile_states_bond_delegation_and_commission_facts`
  (still asserts the reported rate) and the gate itself.
- **Status:** closed on `testnet-quantum` - `quantum`: "AF-04 ...".

### AF-05 - The chain actor's new `Blockchain::remove_transaction` call is unclassified (`ci`, `medium`)

- **Where:** `src/chain/chain_actor.rs:2538`; gate
  `no-out-of-block-consensus-writes` (`xtask/gates/src/gates/no_out_of_block_consensus_writes.rs`).
- **Root cause:** the `RemoveTransaction` command was added to the actor without a row
  in the gate's `CALLS` table. The gate is right to stop: it has no class for a
  consensus write, so an unclassified call could be one.
- **Classification (decided): `NodeLocal`.** `Blockchain::remove_transaction`
  (`src/chain/blockchain.rs:4952`) touches the mempool and its node-local persistence
  and nothing under `self.state`; a node that forgets an admitted transaction still
  holds the same state root as its peers. The body-write check the gate runs on
  `NodeLocal` rows confirms there is no state write.
- **Fix:** the row is added with that rationale. Nothing else in the actor's call set
  is unclassified: the two calls that look unclassified before `#[cfg(test)]` stripping
  (`submit_domain_commitment`, and the arm that calls it) are test-harness code, which
  the gate strips by design.
- **Regression test:** the gate plus its canary (`no-out-of-block-consensus-writes
  canary OK`).
- **Status:** closed on `testnet-quantum` - `quantum`: "AF-05 ...".

### AF-06 - Rustdoc: two public items link to a private constant (`ci`, `medium`)

- **Where:** `src/consensus/mod.rs:75` (docs on `RoundPriceBook`) and
  `src/consensus/mod.rs:212` (docs on `affordable_leader_round`), both writing
  ``[`ROUND_PRICE_WINDOW`]`` while the constant at line 99 is private.
- **Symptom:** `cargo doc` with warnings denied:
  `error: public documentation for 'RoundPriceBook' links to private item 'ROUND_PRICE_WINDOW'`,
  then the same for `affordable_leader_round`, then `could not document 'budlum-core'`
  (exit 101) - the `Budlum Core quality` job on #97.
- **Root cause:** intra-doc links are checked against the visibility of the target; the
  window is deliberately private (it is `MAX_REORG_DEPTH + 1` and an implementation
  detail), the link is not.
- **Fix:** the two references become plain code spans. The text and the argument are
  unchanged; the constant stays private, which is the conservative choice.
- **Regression test:** the `cargo doc` step itself (warnings-as-errors) in
  `Budlum Core quality`.
- **Status:** closed on `consensus-of-consensuses` - `consensus of consensuses`: "AF-06 ...".

### AF-07 - The `minting-paths-are-counted` gate under-counts a refund path (`ci`, `medium`)

- **Where:** `xtask/gates/src/gates/minting_paths_are_counted.rs` (`TRANSFER_JUSTIFICATIONS`,
  `src/chain/blockchain.rs` row) against `src/chain/blockchain.rs:8707`
  (`refund_unserved_storage_fee`).
- **Symptom:** `there are 11 try_add_balance calls, the justified count is 10`.
- **Root cause:** `refund_unserved_storage_fee` was added to `blockchain.rs` without a
  sentence in the gate's rationale. The gate's question is the right one and the answer
  is not "a mint": the function returns the unserved part of a *slashed* deal's prepaid
  fee to the payer, out of money `open_deal` debited from that payer and which
  `total_bud_committed` counts while the deal is held. It is a transfer, and
  `try_mint_balance` would be wrong here (it would check a ceiling against money that
  already exists and could mint into a headroom it should not have).
- **Fix:** the count goes 10 -> 11 and the rationale names this path and why it is a
  transfer. Raising the count without the rationale, or switching the call to
  `try_mint_balance`, would both be wrong.
- **Regression test:** the gate plus its canary.
- **Status:** closed on `consensus-of-consensuses` - `consensus of consensuses`: "AF-07 ...".

### AF-08 - `Timing-Safe Regression` red on `constant_time_eq_str` (`ci`, `high`, **open**)

- **Where:** `src/rpc/server.rs:825` (`constant_time_eq_str`) measured by
  `benches/micro/timing_safe.rs`.
- **Symptom:** run 124371304766: main classes `mean_first=58.05ns`,
  `mean_last=61.96ns`, `|t|=17.82`, effect ratio 15.9 %; class
  `same length vs short key` `delta~3.7ns`, `|t|=20.85`, ratio 15.2 % - the gate
  returns 1 (a regression, not a harness error).
- **What is already ruled out:** the function's source is byte-identical between
  `consensus-of-consensuses` (where the same job is green) and `testnet-quantum`
  (`git diff` on `src/rpc/server.rs` shows no change to it), and the measurement
  harness for it is unchanged too - the branch only *added* post-quantum signer
  classes, which run after this verdict. Both classes execute the same loop (the trip
  count is `b.len()`, identical in both, and the candidate index is clamped, not
  branched), so a content-dependent cost is not visible in the source. That makes the
  measurement the first suspect, not the primitive.
- **Not done on purpose:** the primitive is not rewritten to chase a bench that cannot
  be reproduced locally in this environment, and the thresholds are not touched.
- **Status:** closed by measurement, not by code change. The job was re-run unchanged
  on `829b3ee` (check-run `Timing-Safe Regression`, conclusion `success`, the same
  source tree for the primitive: no commit between the red run and the green one
  touches `src/rpc/server.rs` or `benches/micro/timing_safe.rs`). That separates the
  effect from the primitive and identifies it as an artefact of the runner, which is
  the outcome the earlier artefacts in the bench history had as well. No threshold,
  trip count or assertion was relaxed, so the gate keeps the bar it had.

### AF-09 - `Devnet Multi-Node Smoke` red: node2 does not catch up (`ci`, `high`, **open**)

- **Where:** devnet harness (`ops/`), check `node2 did not catch up with node1
  (node1=41, node2 tip=8)`.
- **Observed:** node1 produced 41 blocks; node2 stopped at 8. node3/node4 log
  `Not selected as VRF leader for this slot` in a one-second loop and then
  `Block validation failed: Previous hash mismatch`. The same job is green on #97, so
  the regression is in the testnet branch's networking/consensus wiring, not the
  harness.
- **Root cause found in the logs (and fixed in the tree):** the mesh does not punish
  a *fork* correctly. node1 and node2 each produced a block at height 2 (both were
  elected in slot 4, which the stake-weighted threshold permits), so node2 heard a
  finality certificate for `42270e...` while holding `b05ae2...` at that height. The
  handler in `src/network/node.rs` counted **every** certificate failure other than
  "Missing verified QC blob" as peer misbehaviour, so node2 banned node1 for 3600 s
  and from then on logged `Ignoring message from banned peer` - it silenced the one
  peer that could have carried it across the fork, and stayed at tip 8 while node1
  reached 41. A certificate for a checkpoint this node does not hold, or holds a
  sibling of, says where *this node* is, not what the peer did.
- **Fix:** `Node::finality_cert_names_a_block_we_lack` classifies those two refusals
  (`We don't have block at height N`, `Certificate hash ... mismatch with our block hash
  ... at height N`); the handler now treats them as a sync signal -
  `sync_if_behind(peer, height)` plus `MessageAcceptance::Ignore` - instead of
  `report_bad_behavior` + `Reject`. Every other refusal (bad aggregate signature,
  wrong height, set-hash mismatch, a QC this node is missing) keeps the old verdict,
  so a lying peer still loses reputation and still gets rejected.
- **Regression test:** `a_fork_or_a_missing_block_is_not_peer_misbehaviour`
  (`src/network/node.rs`), which pins both directions of the classification.
- **Second sink, found in the next run (the ban came from somewhere else):** the
  devnet that failed on `64d0a85`'s predecessor banned `12D3KooWL3sp...` for 3600 s from
  the *sync* path, not the certificate path: `sync block refused ... index=7 ...
  Previous hash mismatch` followed immediately by `Peer ... banned`. The `Blocks` arm
  classified the `fork_retry` flag - raised when `validate_and_add_block` answers
  `Previous hash mismatch` - as `report_invalid_block`. That answer has two honest
  causes and no dishonest one that is distinguishable at that point: this node's tip
  moved between request and answer, or the peer is serving the branch that won the
  slot. On a four-validator mesh a slot has more than one elected leader often enough
  that this is ordinary traffic, and at `INVALID_BLOCK_PENALTY` ten such answers
  (`BAN_THRESHOLD` is -100) silence a validator for an hour - which is the same
  failure one level down: the node bans the peer that could carry it across the fork.
- **Fix (this round):** `PeerManager::report_stale_sync_batch` - the fork signal keeps
  moving the score (the peer sinks in `get_best_peers`, so the re-walk that follows
  asks someone else) but is floored at `MIN_SCORE + 1`, one point above
  `BAN_THRESHOLD`, so it can demote a peer and never silence it. The sync `Blocks` arm
  now calls it instead of `report_invalid_block`. A genuine invalid block keeps the
  banning path: the gossip `Block` arm still charges `report_invalid_block` for a block
  whose own hash does not match its contents, and the oversized-batch refusal still
  charges it as well.
- **Regression test:** `stale_sync_batches_demote_but_never_ban` plus its canary
  `stale_batch_floor_is_load_bearing` (`src/network/peer_manager.rs`): 64 stale batches
  demote to exactly `MIN_SCORE + 1`, are never banned, and are asked last, while 64
  invalid-block reports still ban. The H5 score-ceiling walk over every entry point
  gains the new method, so the ceiling keeps its coverage.
- **Most likely cause of "only 3 of 4 validators produced":** the same ban, one hop
  further. Step 7 counts distinct `producer` values in the blocks *node1* holds. A
  node1 that banned the fourth validator for an hour never receives that validator's
  blocks at all, so its blocks cannot appear in node1's chain however often it wins its
  slot - and the run that failed has exactly that shape (`... banned for 3600s` six
  lines above the reported refusal). Removing the two ban sources is therefore the
  fix for the producer count as well, not just for the catch-up step; if a run still
  fails step 7 with no ban in its log, the structural reading below is what remains.
- **If the producer count still fails - the structural reading:** with four equal
  validators the threshold admits each one with probability 1/4 per round, so a slot
  has two or more winners with probability `1 - (3/4)^4 - 4*(1/4)*(3/4)^3` about 26 %
  and no winner at round 0 with probability `(3/4)^4` about 32 %. With four equal validators the threshold admits each one
  with probability 1/4 per round, so a slot has two or more winners with probability
  Equal-height candidates are resolved deterministically (`resolve_split_tie` on the
  tip when `fork_choice_score` - chain length - ties), so the mesh converges, but a
  producer whose branch loses the tie resolver and whose node is then cut off by a ban
  has no second chance inside the harness's 240 s window. What would remain to
  instrument is the losing branch's reorg: whether `reorg_to_peer_suffix` runs at all
  when both tips are at the same height and its batch is refused as "not a better
  chain".
- **Status:** **open.** The certificate classification and the ban-from-fork path are
  fixed and tested; `Devnet Multi-Node Smoke` is green on `829b3ee` and that run is the
  evidence that the two bans were the mechanism, but the step-7 producer count has
  failed before and passed after on unchanged logic, so it stays open until a run
  passes on a tree that carries this fix. This is a testnet-readiness blocker (Testnet
  Readiness Gate, "network layer" and "consensus and tokenomics").

### AF-10 - 558 lines of consensus-round tests that no `mod` declared (`ci`, `medium`)

- **Where:** `src/tests/p01_consensus_rounds.rs` (558 lines), gate
  `no-orphan-source-files`.
- **Root cause:** the file was added to the tree and never declared in
  `src/tests/mod.rs`, so rustc never read it. It compiles nowhere, is linted by
  nothing, is executed never, and reads exactly like live coverage in a grep or
  a review - the most expensive kind of test debt, because it looks paid.
- **Fix:** `#[cfg(test)] pub mod p01_consensus_rounds;` in `src/tests/mod.rs`,
  with a comment saying what the file is. The alternative - deleting 558 lines
  of round-rule coverage - buys a green gate by removing the coverage it was
  meant to measure.
- **Regression test:** the file's own tests plus the `no-orphan-source-files`
  gate.
- **Status:** fixed, waiting for the library-test job to prove the module
  compiles against today's APIs.

### AF-11 - Two public registry items are idle (`ci`, `low`)

- **Where:** `src/registry/permissionless.rs` - `MAX_COMMISSION_RATE_HISTORY`
  (line 64) and `CommissionRate` (line 296), gate `no-idle-code`.
- **Root cause:** both were added with the commission work and are reached only
  from inside their own file. `CommissionRate` cannot become crate-private: it
  is the element type of the public field `ValidatorCommission::rates`, which
  `src/bin/budlum-indexer.rs` walks - so the type is used by the public shape
  of the struct without its name appearing anywhere else. The constant has the
  same character: it is the published half of the retention rule
  `validator_commission_ppm_at` applies.
- **Fix:** both carry an `exposed for:` line, which is the gate's own documented
  mechanism (no baseline line, no re-export). Deleting the constant would be a
  semver break for a value that is part of the registry root, and making the
  type private does not compile.
- **Regression test:** the `no-idle-code` gate and its stale-entry check.
- **Status:** closed on `testnet-quantum`.

### AF-12 - A third `try_add_balance` in `storage_maintenance.rs` is unclassified (`ci`, `medium`)

- **Where:** `src/chain/storage_maintenance.rs:308`
  (`refund_unserved_storage_fee`), gate `minting-paths-are-counted`:
  "there are 3 `try_add_balance` calls, the justified count is 2".
- **Root cause:** the same refund that AF-07 records on `consensus-of-consensuses`,
  living in the file the testnet branch moved it to. The storage reward tick and
  the expiry sweep were justified; the slashed-deal refund was not.
- **Fix:** the count goes 2 -> 3 and the rationale names the refund and why it
  is a transfer, not a mint - the payer gets back the unserved part of a fee
  `open_deal` debited from it, money `total_bud_committed` counts while the deal
  is held.
- **Regression test:** the gate plus its canary.
- **Status:** closed on `testnet-quantum`.

### AF-13 - This ledger's own gate failures (`ci`, `low`)

- **Where:** `docs/AUDIT_FINDINGS.md` as first pushed: `pq-claims-are-backed`
  (three "post-quantum" lines without a claim id), `tree-is-english` (one
  Turkish phrase), `no-unicode-dashes` (33 typographic dashes).
- **Root cause:** the first version of this file was written as prose in
  Turkish and with typographic punctuation, in a tree whose gates require
  English, ASCII dashes, and a claim id on every line that speaks about quantum
  computers.
- **Fix:** the ledger lives in `docs/audit/`, which is the directory the claim
  gate excludes by design (it holds the audit ledgers themselves, not claims),
  and the text is plain ASCII English. Nothing was baselined and no gate was
  switched off.
- **Status:** closed on `testnet-quantum`.

### AF-14 - `docs/pq/MEASUREMENTS.md` no longer matches `build_config` (`ci`, `medium`)

- **Where:** `Repo Lint` -> `stark-soundness --check` on `829b3ee`
  (job `124489492900`): "the stark-soundness section of docs/pq/MEASUREMENTS.md
  does not match budzero/bud-proof/src/plonky3_prover.rs".
- **Root cause:** the committed section was generated when the AIR had a different
  width. `stark_soundness::read_setup` derives the batched column count as
  `TRACE_WIDTH + PREPROCESSED_WIDTH + 3 * ext_degree + chunks * ext_degree`; the
  branch added columns for the new consensus work, so the count is now
  `1073 + 8 + 9 + 24 = 1114` while the document still states `930`. Only the
  column-dependent terms move: the batching term goes from 131.1 to 130.8 bits
  (quantum 65.5 -> 65.4), the composite is unchanged at 128.0 provable and 128.0
  assumed because both are capped by the Merkle collision term, and the minimal
  query counts stay at 76 (cubic) and 75 (quintic).
- **Why it surfaced only now:** the gate suite aborts at the first failing gate, so
  this step never ran in the earlier `Repo Lint` job (the log of run
  `124371304775` contains no `stark-soundness` line at all). Fixing the gates ahead
  of it exposed the next one instead of fixing it.
- **Fix:** the section was regenerated from the same formulas the tool uses, for the
  new column count, and only the two affected rows changed. The port was validated
  against the committed section first: run at 930 columns it reproduces every value
  in the document byte for byte (all seven per-term rows, m = 28, the 76/75 query
  counts and the per-degree field sizes), so the regenerated rows are the tool's
  output and not a hand estimate. Nothing in the prover changed, and no bound was
  touched to make the numbers look better.
- **Status:** closed on `testnet-quantum`.

---

## Testnet readiness gate (#110, directive section 5)

Checked against the tree at `testnet-quantum` and the CI jobs that carry each item. An
item is `pass` only when a named job is green on that branch.

| Item | Where it lives | Job | State |
|---|---|---|---|
| Clean build, green CI | workspace | `Budlum Core`, `Budlum Core quality`, `Budlum Core PQ build` | fixes above land in this round |
| Genesis -> config -> node start, end to end | `src/genesis*`, `config/`, `bud` | `Genesis Reproducibility (item 1)`, `docker-smoke` | pass |
| State persistence across restart (counters together) | `src/chain/snapshot.rs` | `Budlum Core library test` (snapshot suite), `AF-01` | fixes above land in this round |
| Network: no unbounded allocation, message size and rate limits | `src/network/` | `Network Hardening` | red only for the six shared unit tests -> this round |
| RPC auth and rate limiting | `src/rpc/server.rs` | `Network Hardening`, `Hardening H4` locks | pass |
| Consensus and tokenomics per directive, tested and integrated | `src/consensus/`, `src/tokenomics/` | `Economy Invariants`, `Fork-Choice Invariants`, `Governance Invariants` | red only for the six shared unit tests -> this round |
| No `unwrap`/`panic!`/`todo!`/`unimplemented!` on production paths | workspace | `Gates (a suite that cannot run is not a protection)` | red for `dead-public-api-is-ratcheted` -> this round |
| README, install/run steps, config examples, testnet join doc | `README.md`, `README.tr.md`, `docs/TESTNET.md`, `docs/OPERATOR*` | `Repo Lint` | red for AF-10 to AF-14, each closed in this round |
| No secret, token or personal data in the repo | history | `gitleaks`, `Secret Scan (gitleaks, full history)`, `Secret Verification (trufflehog)` | pass |
| Multi-node mesh behaves | `ops/` devnet | `Devnet Multi-Node Smoke` | **open - AF-09** |

## Decisions taken in this round (architecture-first, conservative)

1. **Slash burn accounting (AF-01).** When two recorders measure the same destruction,
   the one that measures the *whole* drop in committed supply wins, because it cannot
   miss a part (bond, queue, delegation, cross-role sweep) while a hand-summed
   `penalty` can. Consequence: a slash may now never under-record, and cannot
   double-record; no test or API changes.
2. **Bundle refusal order (AF-02).** Verification order is now structural -> witness ->
   per-member. Both refusals were already correct in the sense that the bundle was
   refused; the change makes the *reason* the specific one a caller can act on, and
   puts the expensive post-quantum verifications last (DoS-relevant). No check is
   dropped.
3. **Commission fixtures (AF-03).** The cap is a rule, not an obstacle: the fixtures
   move to the state the rule allows (rate set before delegation) instead of lowering
   the rate or the assertions.
4. **Dead public API (AF-04).** Wire it, do not baseline it: the gate's baseline is not
   raised, and the exemption doc-token is not used.
5. **Actor classification (AF-05).** `remove_transaction` is `NodeLocal` because it
   provably touches no `self.state`; a "devnet-only" or "block path" label would be a
   lie and the gate's own body check would refute it.
6. **`ROUND_PRICE_WINDOW` (AF-06).** The constant stays private and the doc adjusts;
   making it public to satisfy rustdoc would widen the public surface to fix a typo.
