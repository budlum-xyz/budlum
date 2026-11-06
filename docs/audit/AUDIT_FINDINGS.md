# Audit Findings Ledger

One ledger for every review finding on the open pull requests (#110 `testnet-quantum`,
#97 `consensus-of-consensuses`). Every record names its source, its severity, the
exact `file:line` it lives at, and what closes it. A record stays `open` until the
commit that closes it is on the branch and CI is green; the commit SHA is written
into the record at that moment.

Sources are marked as `Strix` (the security agent), `bot` (any automated reviewer),
`human` (a person), or `ci` (a red check run, which is a finding like any other).

Severity: `blocker` (build/consensus/security), `high`, `medium`, `low`.

The directive traceability matrix is next to this file: `docs/audit/TESTNET_TRACEABILITY.md` maps every #110 directive line to its code,
its test and the job that runs it. A line with no code is unfinished work, and a
line with no test is unverified work, so both files are read together.

---

## Round 2 - 2026-10-31 (continuation)

Round 1 closed the review threads and the first wave of red checks. Round 2 is what the
remaining red checks were hiding: a gate suite aborts at its first failing gate, and a
workflow cancels the run of a branch when a newer commit arrives, so each round peels
one layer and shows the next. This round also re-read the devnet logs end to end.

| Commit | What it closes | Evidence |
|---|---|---|
| `64d0a85` | AF-09 part 1: a certificate for a block this node lacks, or holds a sibling of, is a sync signal, not peer misbehaviour. | classifier test in `src/network/node.rs` |
| `829b3ee` | AF-10 (orphan test file), AF-11 (idle registry items), AF-12 (third `try_add_balance`), AF-13 (this ledger's own gate failures) | `Repo Lint` gates |
| `380cd9e` | AF-14: the STARK soundness section no longer matched `build_config` (batched columns 930 against a trace of 1073) | `stark-soundness --check`; the regenerated rows were validated by reproducing the committed section byte for byte at the old column count |
| `5c5c178` | AF-09 part 2: a sync batch that does not join this chain is a fork signal, not an invalid block | `report_unjoined_block` and its floor test |
| `95a9ffa` | the #110 traceability matrix (`docs/audit/TESTNET_TRACEABILITY.md`) | every directive line mapped to code, test and job |
| `f85145d` | AF-09 part 3: the same classification on the gossip `Block` arm, and the report renamed to `report_unjoined_block` because it is no longer a sync-only signal | the arm branches on the refusal string; `Ignore` instead of `Reject` for that one case |
| `9e50669` | AF-15: a doc line in the new test tripped `clippy::doc_lazy_continuation` on the next-stable toolchain | `Clippy drift (next stable toolchain)` |
| `aef7b57`, `0c4d0ad` | the AF-09 mechanism, and AF-15's record | this file |
| `60b5e36` | the source lock `a_block_that_does_not_join_the_chain_is_not_a_forgery`, the panic-bar reading (per-site, module computed), and the recorded resource-table gap | `Budlum Core library test`, this file |

AF-08 (the timing-side-channel measurement) closed by re-measurement, not by a code
change, and the record says so. Nothing was closed as a false positive, and no gate was
weakened: no test deleted, no `#[ignore]`, no baseline raised, no lint downgraded.

### AF-01 to AF-15 status at the end of round 2

`AF-08` closed by re-measurement with the job green on a tree that does not touch the
primitive. `AF-01` to `AF-07`, `AF-10` to `AF-15` closed by code. `AF-09` is the only
record still open, and it stays open until `Devnet Multi-Node Smoke` passes on a tree
that carries all three of its fixes - its step 7 has failed and passed on unchanged
logic before, so one green run is the bar.

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
  devnet that failed on the run before `64d0a85` banned `12D3KooWL3sp...` for 3600 s
  from the *sync* path, not the certificate path: `sync block refused ... index=7 ...
  Previous hash mismatch` followed immediately by `Peer ... banned`. The `Blocks` arm
  classified the `fork_retry` flag - raised when `validate_and_add_block` answers
  `Previous hash mismatch` - as `report_invalid_block`. That answer has two honest
  causes and no dishonest one that is distinguishable at that point: this node's tip
  moved between request and answer, or the peer is serving the branch that won the
  slot. On a four-validator mesh a slot has more than one elected leader often enough
  that this is ordinary traffic, and at `INVALID_BLOCK_PENALTY` ten such answers
  (`BAN_THRESHOLD` is -100) silence a validator for an hour.
- **Third sink, found while fixing the first two:** the gossip `Block` arm had the
  same shape. `validate_and_add_block` runs after the cheap checks, so a block at
  `height + 1` that fails with `Previous hash mismatch` because the tip moved in the
  meantime was charged as a forged block. Same penalty, same ban, and it needs one
  message per slot rather than one batch per second to reach it.
- **Fix (this round):** `PeerManager::report_unjoined_block` - the fork signal keeps
  moving the score (the peer sinks in `get_best_peers`, so the next re-walk asks
  someone else) but is floored at `MIN_SCORE + 1`, one point above `BAN_THRESHOLD`, so
  it can demote a peer and never silence it. Both the sync `Blocks` arm and the gossip
  `Block` arm call it for that one refusal string; the gossip arm also answers
  `MessageAcceptance::Ignore` for it instead of `Reject`, because there is nothing
  wrong with the message. A genuine invalid block keeps the banning path: a block
  whose own hash does not match its contents, an oversized batch, an oversized
  message, a forged vote and an invalid handshake all keep their own penalties.
- **Regression test:** `unjoined_blocks_demote_but_never_ban` plus its canary
  `unjoined_block_floor_is_load_bearing` (`src/network/peer_manager.rs`): 64 unjoined
  reports demote to exactly `MIN_SCORE + 1`, are never banned, and are asked last,
  while 64 invalid-block reports still ban. The H5 score-ceiling walk over every entry
  point gains the new method, so the ceiling keeps its coverage.
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
  Equal-height candidates are resolved deterministically by `resolve_split_tie`
  (`src/consensus/split_resolver.rs`), whose order is `(weight, height, block_hash,
  proposer)` and whose last field is identical for the same block, so two nodes holding
  the same pair of branches always agree. What they do not necessarily get is a
  *stable* preference: `pos.rs::is_better_chain` passes `SplitCandidate::from_chain_tip`,
  so the comparison is made on the two tips, and two branches growing at the same rate
  hand the decision back and forth (branch A can lead at height 10 and lose at height 11
  without either branch changing). A tie-break that is a function of the fork point -
  the first index where the two chains differ - instead of the tip would make the
  preference monotone under extension, which is what stops a two-branch mesh from
  reorging on every slot. That change is not in this round: it is a consensus rule, the
  current run has to show whether it is still needed, and shipping a rule change on a
  suspicion is worse than shipping it with a failing log that names it.
- **Status:** **closed on `testnet-quantum`.** `Devnet Multi-Node Smoke` (check-run
  `124505840033`) ran to `success` on `2530221` for 17 minutes, and that tree carries all
  three fixes: the certificate classification (`64d0a85`), the sync `Blocks` arm
  (`5c5c178`) and the gossip `Block` arm (`f85145d`). The two earlier runs that were
  green on a tree carrying only the first fix are what kept this record open, because
  the ban was still reachable from the other two arms. The step-7 producer count, the
  step-6 catch-up and the step-10 restart are one harness run, so the green run is the
  pass the record was waiting for. The fork-point tie-break above stays recorded as a
  design note and not as open work: nothing in this run asks for it.

### AF-16 - A fork was refused as a clock error, so the node could not reorg (`devnet`, `blocker`)

- **Where:** `src/consensus/mod.rs:373` (`full_validate`), reached from
  `Blockchain::validate_and_add_block`. Job `124539476950`, `Devnet Multi-Node Smoke`
  on `3fb7381`: `FAIL: only 3 of 4 validators produced in blocks 1..=89`.
- **Observed:** node4 logged `sync block refused peer=... index=2 error=Consensus
  validation failed: Consensus error: Block timestamp not monotonic. Prev:
  1793453778952, Current: 1793453776952` twenty-two times, the same peer and the same
  index every time, and never logged `Added block` at all: it stayed at height 1 while
  the rest of the mesh reached 89. The producer the harness never saw was node4's, so
  step 7 counted 3 of 4.
- **Root cause:** `full_validate` priced the block's timestamp against `chain.last()` -
  which is *this node's* tip - before any check that the block names that tip as its
  parent. node4 held its own block #1 (stamped two seconds later than the sibling that
  won the slot), so every block #2 of the winning branch was compared with a block it
  does not descend from, and because its stamp was lower the refusal read "Block
  timestamp not monotonic". That string is not `Previous hash mismatch`, which is the
  one string the sync `Blocks` arm treats as a fork signal: `fork_retry` stayed false,
  the locator was never re-walked, no reorg was attempted, and the node re-asked the
  same peer for the same index every second until the harness gave up. The ordering of
  two cheap checks turned a recoverable fork into a permanent one.
- **Fix:** `full_validate` compares `block.previous_hash` with the tip's hash *before*
  the timestamp is priced, and refuses an unjoined block with the same
  `Previous hash mismatch` message the engines already produce for that condition. For
  a block that does name our tip as its parent nothing changes: the timestamp is still
  priced against the same `prev_block` on the next line. The sibling's block is then
  classified correctly - fork signal in the sync loop (locator re-walk, reorg by fork
  choice) and an unjoined block, not an invalid one, in the peer's score (AF-09).
- **Regression test:** `a_fork_is_named_a_fork_and_not_a_clock_error`
  (`src/tests/consensus_expanded.rs`): a block on a sibling of our tip must be refused
  with `Previous hash mismatch` and must not mention the clock, and the canary in the
  same test re-parents the identical timestamp on our own tip and asserts the
  monotonicity rule still fires. The two tests that reach the timestamp guard by hand
  (`adversarial_p2p`, `wall_clock_locks`) already parent their blocks on the tip under
  test, which is what the new ordering requires and what they always meant.
- **Status:** fix pushed; `Devnet Multi-Node Smoke` has to confirm it, so the record
  stays open until a run passes on a tree that carries it. Reopens AF-09's root cause
  at the layer below the three ban paths: those removed the punishment for a fork, this
  removes the reason the fork could not heal.

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
- **Fix, part 1 (the numbers):** the section was regenerated from the same formulas the
  tool uses, for the new column count, and only the two affected rows changed. The port
  was validated against the committed section first: run at 930 columns it reproduces
  every value in the document byte for byte (all seven per-term rows, m = 28, the 76/75
  query counts and the per-degree field sizes), so the regenerated rows are the tool's
  output and not a hand estimate. Nothing in the prover changed, and no bound was
  touched to make the numbers look better.
- **Root cause, part 2 (the reason the gate stayed red after part 1):** the generator's
  own text had a typo. `render_section` wrote `"Thetarget is {..} bits provable"` while
  the document says `"The target is 128 bits provable: met."`, so `--check` refused the
  whole section no matter what the numbers said. The document was right and the
  generator was wrong, so the fix is in the generator: the format string now reads
  `"The target is {TARGET_BITS:.0} bits provable: {}."`. Hand-editing the document to
  match the typo would have made the gate pass by making the output worse, and no other
  caller or test pins that string (it appears once in the tree).
- **Why part 2 took a second run to see:** `stark-soundness` is one step near the end of
  the `Repo Lint` suite, which stops at the first failing step, and a branch push cancels
  the previous run. Part 1 fixed the numbers and the run reported the same one-line
  summary - which reads identically for "the numbers are wrong" and "the prose is
  wrong", because the tool checks the block as one string.
- **Status:** closed on `testnet-quantum`.

### AF-15 - `Clippy drift (next stable toolchain)` red on a doc line in the new test (`ci`, `low`)

- **Where:** `src/network/peer_manager.rs:841`, the doc comment of
  `unjoined_blocks_demote_but_never_ban`, job `124501936025`.
- **Root cause:** a paragraph in that doc comment had a line starting with `- `, so
  `clippy::doc_lazy_continuation` read the rest of the paragraph as a list item and
  refused the unindented continuation below it. The stable-toolchain clippy of
  `Budlum Core quality` does not have the lint yet; the next-stable job is what
  catches it, which is the job's purpose.
- **Fix:** the paragraph is reflowed so no line begins with a bullet marker. No
  `#[allow]` and no lint configuration was touched.
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
| Multi-node mesh behaves | `ops/` devnet | `Devnet Multi-Node Smoke` | pass on `2530221` (AF-09 closed) |

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

### AF-17 - The locator never named genesis, so a fork at block 1 could not heal (`devnet`, `blocker`)

- **Where:** `src/chain/chain_actor.rs` (`ChainCommand::GetLocator`, now
  `Blockchain::get_locator`), and the sync `Blocks` arm of `src/network/node.rs` (the
  fork re-walk). Job `124556422112`, `Devnet Multi-Node Smoke` on `5a21b91` (the AF-16
  fix): `FAIL: node2 did not catch up with node1 (node1=44, node2 tip=16)`.
- **Observed:** node2 produced its own block #1 at `14:36:04.29` while node1 adopted a
  sibling #1; from `14:36:05.43` node2 logged `Block #3 is ahead of our chain
  (height=1), requesting sync` and then, for thirty milliseconds, a refusal every
  0.2-1 ms: `sync block refused peer=... index=2 error=Consensus validation failed:
  Consensus error: Previous hash mismatch. Expected: 9415301f..., Got: f269267b...`.
  Each refusal was answered by an immediate header request of its own
  (`Requesting headers from ... (limit 500)`), roughly two hundred of them, until
  node1's own limiter cut node2 off: `Rejected sync request from banned/rate-limited
  peer 12D3KooWPbV...` plus `Inbound sync failure ... ResponseOmission`. node2's sync
  round then stayed open, the stuck-round sweep cleared it 119 s later
  (`Sync state stuck for 119s (timeout=60s), resetting to 0`), and by then node1 was
  forty blocks ahead. node2 crawled 1 -> 4 -> 16 while node1 reached 44.
- **Root cause:** two defects, one cause and one amplifier. **Cause:** `GetLocator`
  built its list with `while current > 0`, so it pushed the tip and then every
  power-of-two ancestor down to index 1 - it never pushed index 0, genesis. A follower
  whose only shared block is genesis therefore named no ancestor at all: node1's
  `find_common_height` found nothing, `start_idx` fell back to 0, and the answer began
  at the follower's own height 0. The follower skipped every block it already held
  (the apply loop only takes `index == height + 1`), refused the first block above its
  tip for a parent it does not have, and could never reach the branch that recognises
  a fork by hash and reorgs - so the same range was asked for and refused forever.
  **Amplifier:** the fork re-walk was issued inside the same event-loop iteration as
  the refusal, so "asked again" meant "asked two hundred times a second" until the
  peer's rate limiter - correctly, as a DoS surface - stopped answering at all.
- **Fix:** `get_locator` walks down to and including genesis (and stays inside the
  protocol's locator ceiling), so the peer names the real common ancestor and the
  follower receives the fork block itself, recognises it by hash at its own height and
  reorgs. The re-walk is now spaced by `ForkRewalkGate`
  (`src/network/fork_rewalk.rs`): the first walk after a fork signal is immediate, the
  following ones wait 1, 2, 4 and then 8 seconds, and a joined batch clears the count.
  A batch that starts *above* our next block is treated as a gap and walks the locator
  instead of being silently skipped. `find_common_height` moved next to the locator so
  both sides of the protocol read the same definition.
- **Also in this commit (not a code defect):** `Repo Lint` job `124559879332` failed at
  `build.rs:37: Failed to compile Protobuf schemas: Could not find protoc`. That step
  (`pq-measure --timings`) builds `examples/pq_measure.rs`, which links the node
  library; every other job that builds the library installs `protobuf-compiler` and
  this job had no run reach the step before, so it had never needed it. The workflow
  installs it, exactly as the other jobs do. No gate was relaxed.
- **Regression tests:** `a_fork_at_the_first_block_still_names_genesis_in_the_locator`
  (two chains that both produce block 1 from genesis: the locator's last entry is the
  shared genesis and `find_common_height` returns `Some(0)`, so the served range starts
  at the fork block), `the_locator_is_newest_first_within_the_protocol_ceiling`, and
  four `ForkRewalkGate` tests - including the one that pins the observed defect: a
  second fork signal in the same second must not walk again.
- **Gate bookkeeping:** moving the locator and the common-ancestor lookup onto
  `Blockchain` turned two calls into `Blockchain::` calls that the chain actor makes,
  and `no-out-of-block-consensus-writes` refuses an unclassified one by design. Both
  are `Read` (neither touches `self.state`); they are classified in the gate's `CALLS`
  table, not exempted from it.
- **Status:** confirmed by `Devnet Multi-Node Smoke` on `477e26b` - the 4x PoS mesh
  passes all ten steps on the tree that carries the locator fix, where `5a21b91` failed
  step 6. The ledger entry stays open only until the gate bookkeeping above is green in
  the same job that carries it.

### AF-18 - A finality vote that arrived before the round opened was lost for good (`devnet`, `blocker`)

- **Where:** the gossip arms for `Prevote` and `Precommit` in
  `src/network/node.rs` (`refusal_is_round_scope`), and the vote beat in the same
  file. Job `124634428303`, `Devnet Multi-Node Smoke` on `68a0a83`:
  `FAIL: finality did not advance (first finalized height seen: Some(6))`.
- **Observed:** the log holds 498 `Cannot precommit before prevote quorum` refusals and
  repeats `No active finality aggregator`. Node5's vote witness shows every vote it
  ever counted arriving through node1 (`propagation_source = JDzf`): four voters at
  heights 2, 4 and 6, and at height 8 only node1's own prevote, which it refused with
  `No active finality aggregator` because its round was not open yet. node1 collected
  three of the four prevotes at height 8 and precommitted, then re-published that
  precommit every beat for the rest of the run: `the round has no precommit quorum
  yet`. No follower ever precommitted, so node1 never reached a precommit quorum and
  the height could not finalize. The same tree had passed the same job on `7535554`
  an hour earlier.
- **Root cause:** two facts that are harmless apart and fatal together. First, the
  devnet mesh is a star - `ops/docker-compose.yml` gives every follower
  `--dial=/dns4/node1/tcp/4001` and nothing else, and no two followers are connected -
  so a follower sees another follower's vote only when node1 relays it. Second, a vote
  is published exactly once and cannot be retransmitted: the payload is signed over
  its own content, so a retry is byte-identical, and gossipsub answers byte-identical
  with `Duplicate` and sends nothing (`Failed to gossip a finality vote: Duplicate;
  height 8 stays unvoted and is retried`, node4, 498 times). This node spent that
  single delivery on nothing whenever the vote landed before its aggregator held that
  epoch and height: the arm refused it as round-scope, answered `Ignore`, and dropped
  it. The author cannot send it again, and the receiver has nothing to ask for. Every
  node then waits for a vote that has already been delivered and thrown away.
- **Fix:** `DeferredVotes` (`src/network/deferred_votes.rs`) holds a round-scope
  refused vote by its `(epoch, height)` in a bounded queue (64 entries, oldest
  dropped), and the vote beat replays the held votes for the round its aggregator
  holds, at the moment that round opens. A held vote is not counted early: it goes
  through the same `handle_prevote` / `handle_precommit` checks, so nothing is
  admitted that the round would have refused, and the safety rule "no precommit
  before the node's own prevote quorum" is untouched. A replayed precommit that
  completes the quorum publishes the resulting `FinalityCert` exactly as the gossip
  arm does. The aggregator state is read again after the replay so the same beat
  signs its own vote rather than acting one beat late.
- **Regression tests:** three tests in `src/network/deferred_votes.rs` - a vote held
  for height 8 comes back once its round opens and is not replayed twice, a vote held
  for another round stays held, another epoch is a different round, and the queue
  drops the oldest past the cap.
- **Open part, recorded rather than hidden:** the vote path still depends on the
  star's hub relaying between followers. The deferral removes the *loss* - a dropped
  delivery no longer costs the round - but not the relay dependency itself, and the
  durable fix is a point-to-point vote exchange over the `/sync` protocol, which is a
  protocol addition and is tracked in `docs/MAINNET_READINESS.md` rather than being
  half-landed here.
- **Status:** confirmed by CI. `Devnet Multi-Node Smoke` is green on `d95f66d`, the
  tree that carries the fix, and has stayed green since: finality advances and the
  height the run reported as stuck (8) finalizes. Closed.

## Round 3 - 2026-11-02 (the Strix review threads of `d95f66d`)

Round 3 works through the review threads the Strix Security Review opened on `d95f66d`
(nine findings on #110, one on #97). Each finding was read in the code before it was
touched; each fix carries a regression test that fails on the tree before it, and the
thread is answered with the fixing commit. Nothing was closed as a false positive, and
no test, gate or lint was weakened.

### AF-19 - A bundle's rollback deleted transactions its own members evicted (`rpc`, `medium`)

- **Where:** `RpcServer::send_tx_bundle` (`src/rpc/server.rs`). The witness and the
  members were checked, then each member went into the pool one at a time; a member the
  pool refused was answered by `remove_transaction` over the members already admitted.
- **Observed:** admission is not side-effect free. A full pool evicts a cheaper
  transaction to make room, and a replacement drops the transaction it replaces. The
  rollback removed the admitted members and left those deletions behind, so a bundle
  whose *last* member was refused cost its sender nothing and permanently removed the
  cheaper transactions its earlier members had evicted - a free deletion primitive, and
  a bundle could be built to aim it.
- **Fix:** the pool admits a bundle as a unit. `Mempool::add_transaction_bundle`
  journals every entry removal it performs while the bundle is being admitted
  (`journal` is `None` outside bundle admission, so ordinary admission pays nothing),
  and on a refusal takes the admitted members back out and restores the journal in
  reverse order. `Blockchain::add_transaction_bundle` runs the chain-level refusals over
  every member first, admits them in one chain-actor turn (`ChainCommand::
  AddTransactionBundle`), and persists them last, so a restart never re-admits a member
  the node does not hold. The RPC layer calls it and no longer rolls anything back
  itself.
- **Regression tests:** `a_bundle_refused_at_its_last_member_restores_the_evicted_victim`,
  `a_bundle_refused_at_its_last_member_restores_the_replaced_transaction`,
  `an_admissible_bundle_admits_every_member` (`src/mempool/pool.rs`).

### AF-20 - `bud_subscribe` had no node-wide bound on subscription work (`rpc`, `medium`)

- **Where:** `RpcServer::subscribe` (`src/rpc/server.rs`).
- **Observed:** each accepted subscription spawns a feed that polls the chain actor once
  a second and serializes a whole block, hex-encoding every ML-DSA signature in it, for
  its own subscriber. Nothing bounded how many a client could start: the per-IP limiter
  sees the HTTP upgrade and jsonrpsee's own cap is per connection.
- **Fix:** a process-wide pool of 128 feed slots (`MAX_SUBSCRIPTION_FEEDS`). The slot is
  taken with the subscription and released when the feed ends, so the ceiling is on live
  feeds whatever the connection count; a client past it is refused with `-32005`
  (`subscription limit reached; retry later`) instead of being given a task.
- **Regression test:** `subscription_feeds_are_capped_node_wide` (`src/rpc/server.rs`)
  exhausts the pool, asserts the refusal, and asserts a released slot is reusable.

### AF-21 - A wrong-answer storage slash stranded the payer's prepaid fee (`storage`, `medium`)

- **Where:** `answer_challenge` (`src/domain/storage_tx.rs`), `Mismatched` arm.
- **Observed:** that arm started the operator cooldown and added the confiscated bond to
  `burned_total`, and settled nothing else, while the missed-deadline arm routed the same
  event through `apply_bond_slash`. The slash takes the deal out of `Active`, and
  `total_storage_escrowed_supply` counts only the unserved part of a *live* deal's
  prepaid fee, so the fee of the epochs the deal would never serve stopped being counted
  by anything: not refunded, not burned, and the supply cap gained exactly that much
  minting headroom while the payer lost it. Any operator could trigger it on its own deal
  by answering with an empty proof.
- **Fix:** both outcomes settle through `apply_bond_slash` - cooldown on the block clock,
  the bond burned and recorded in the storage economics ledger, and the unserved fee
  returned to the recorded payer with a `PayerRefund` event. One routine, so the paths
  cannot diverge again.
- **Regression test:** `a_wrong_answer_slash_returns_the_unserved_fee_to_the_payer`
  (`src/domain/storage_tx.rs`): the payer's balance rises by exactly the unserved fee,
  the ledger holds the refund, the bond is still burned, and the committed supply falls
  by the bond alone.

### AF-22 - The light client verified PQ signatures under genesis statuses (`light-client`, `medium`)

- **Where:** `LightClient::verify_hybrid_checkpoint` and `verify_pq_checkpoint`
  (`src/light_client/mod.rs`).
- **Observed:** the hybrid path passed a fresh `SchemeStatusRegistry::genesis()` to
  `verify_pq_quorum`, and the PQ-only path called `verify_against_snapshot`, which does
  the same. Consensus state demotes a broken lattice family to `Disabled` when the Frost
  Alarm accepts a proof, and every node then refuses signatures under it in that block;
  a client verifying under genesis statuses kept accepting them, printed
  `CHECKPOINT VERIFIED`, and advanced its trust anchor on a checkpoint the network
  rejects.
- **Fix:** the client holds the registry it verifies under (`registry`, genesis by
  default, pinned with `with_scheme_registry`) and uses it on both paths. The registry is
  not on the wire, so pinning it is out-of-band work like pinning the trust anchor, and
  the field's documentation says so.
- **Regression test:** `a_pinned_registry_decides_whether_the_pq_half_verifies` - the
  same honest blob verifies under genesis statuses and is refused once the pinned
  registry disables `ML_DSA_65`.
- **Decision note:** the alternative - carrying the registry in the export - changes the
  wire format and the checkpoint semantics of every existing client, and the client
  already takes its anchor out of band; pinning is the conservative shape.

### AF-23 - Mikoriza credited restaked weight to a key the validator never registered (`settlement`, `medium`)

- **Where:** `apply_restaked_weights` (`src/settlement/shared_security.rs`).
- **Observed:** the `Observe` door compares an allocation's BLS key with the validator's
  registered key only when the validator already exists, and the Ethereum registrar lets
  an operator bind any key to any validator address. An operator-set member could emit an
  allocation naming an arbitrary validator with its own key before that validator
  registered, and the row was stored live; the weight pass then credited the units to the
  validator's voting weight with no second look. The operator gained restaked weight
  towards a validator it does not run, and the ETH behind it was never slashable, because
  the slasher checks double votes against the operator's bound key.
- **Fix:** the weight pass requires the validator's registered key to equal the row's.
  `Observe` keeps its early refusal for a validator that exists; this is the gate where
  the registered key is known, and it covers the rows claimed before it was.
- **Regression tests:** `restaked_weight_needs_the_validators_own_bls_key` (a validator
  registered under another key is credited nothing) and
  `a_move_retires_the_validator_the_operator_left`, whose fixture now registers the key
  its allocation names instead of relying on the lax rule.

### AF-24 - The PUL batch verifier accepted statements nothing had proven (`proof`, `low`)

- **Where:** `verify_batch` (`budzero/bud-pul/src/pul_air.rs`), module note, tests.
- **Observed:** the chip AIR exposes no public inputs and the trace is the whole proof, so
  verification said only "some batch of permutations was run" and nothing tied it to
  `proof.statements`: a proof of unrelated inputs, or a replayed one, verified beside any
  statement list, and the module note claimed a recomputation that did not exist. On a
  stamp-verification path that is a forged stamp.
- **Fix:** `verify_batch` refuses every batch with `KeccakChipError::UnboundProof` after
  the chip proof verifies. Fail-closed until the AIR binds the sponge inputs: a verifier
  that says yes to whatever it is handed is worse than one that says nothing. The module
  note and the doc comment now say exactly that, and the refusal is lifted with the
  binding.
- **Regression tests:** `a_batch_proves_but_the_unbound_proof_is_refused` and
  `a_proof_from_another_batch_does_not_verify_these_statements` (the honest batch is
  refused too, so the refusal is not a statement check).
- **Decision note:** the real binding is a public-values constraint in the Keccak AIR.
  That is a proof-system change: it needs its own soundness measurement and its own
  round. Refusing is the conservative shape until then, and the crate is unwired, so
  nothing that ships depends on the permissive answer.

### AF-25 - Two explorer callers at the documented rate denied every current-state read (`explorer-api`, `low`)

- **Where:** `ClientRates` and `route` (`src/bin/budlum-indexer.rs`).
- **Observed:** every node-backed route spent one unit of a single shared budget of 120
  node calls per minute, while each client address could make 60 requests per minute on
  its own. Two addresses at their ceiling spent the whole budget and every other caller
  got `429 public node budget exhausted` for as long as they kept going - anonymously, at
  the sanctioned rate, against a service published on the internet.
- **Fix:** each client has its own share of the node budget
  (`CLIENT_NODE_CALLS_PER_MINUTE` = 120/8 = 15), charged before the node is touched and
  only on the paths that answer from the node (`node_backed`). Eight callers at their own
  ceiling fill the shared budget exactly; two no longer exhaust it. `/health` stays exempt
  from both limits. Index-backed history routes keep answering throughout.
- **Regression tests:** `a_caller_cannot_spend_the_whole_shared_node_budget` and
  `the_node_budget_is_charged_only_to_node_backed_paths`.

### AF-26 - The explorer and the faucet returned upstream diagnostics to anonymous callers (`explorer-api`, `low`)

- **Where:** `public_error` (`src/bin/budlum-indexer.rs`) and the grant path
  (`src/bin/budlum-faucet.rs`).
- **Observed:** a 502 body was built from the node's raw failure text, which carries the
  request URL - the operator's internal JSON-RPC endpoint, host and port - and the node's
  own diagnostics; JSON-RPC error objects were echoed the same way, under
  `Access-Control-Allow-Origin: *`. Anyone could poll a node-backed route during a
  restart and read it, and the body did not match the documented error schema.
- **Fix:** the detail goes to the service log and the caller gets the generic, documented
  object ("the node could not answer this request"); the faucet's submission failure
  message keeps its meaning ("the allowance is reserved") without the upstream text.
- **Regression tests:** none - the change is a message construction with no branch to
  assert beyond the existing handler tests, and inventing a test that asserts a string
  constant would lock the wording rather than the property. The property (no upstream
  text in a client body) is visible in the two functions and is why they exist.

### AF-27 - Anyone could spend an awarded Graft solver's fulfilment slot (`contracts`, `medium`)

- **Where:** `GraftExecutor.fulfilled` and `execute` (`contracts/graft/GraftExecutor.sol`).
- **Observed:** `registerSolverKey` is permissionless and proves nothing, and the
  per-intent guard was keyed on that claimable solver key. Any account could bind the
  awarded solver's Budlum address, `execute` the intent with its own harmless target, and
  spend that solver's slot; the awarded solver then reverted `AlreadyFulfilled` forever
  and could never emit the event the settlement door requires, so the deadline arrived
  and anyone collected the liveness slash of its bond. Permissionless, no bond, repeatable
  for every intent.
- **Fix:** the guard is keyed on `msg.sender` (`mapping(bytes32 => mapping(address =>
  bool))`), so an account can only ever spend its own slot. Name-of-victim griefing buys
  nothing, and two accounts of one solver still cannot collect twice because the
  settlement door removes the intent on the first proven fulfilment.
- **Regression tests:** `test_binding_another_solvers_key_cannot_burn_its_slot` (the
  attacker's fulfilment does not block the awarded solver) plus the reworked
  `test_an_intent_is_fulfilled_once`, `test_the_once_per_intent_guard_is_per_account` and
  `test_the_payload_hash_commits_to_the_bound_solver`.

### AF-28 - `bud` signed with the chain id the node supplied (`cli`, `medium`)

- **Where:** `src/bin/bud.rs`. The Strix thread was opened against `bud tx send` on #97
  (`consensus-of-consensuses`); the same construction exists in this tree in four places -
  `run_tx_send`, `send_v5` (every wallet-backed command: stake, unstake, delegate,
  undelegate, redelegate, claim, BNS, Graft, domain), `send_signed` (the validator
  transactions) and `run_validator_join` (the consensus-key registration digest) - each of
  which read `bud_chainId` from the node and put the answer inside the signature.
- **Observed:** a seed controls the same address on every network, so the chain id is the
  only thing that says where a signature is valid. Taken from the node, it let the node
  choose: a hostile peer, or anyone on the plaintext path to it, could present itself as
  another chain and submit the captured transaction there, at a nonce it also chose.
- **Fix:** the chain is named by the operator (`--signing-chain-id`, a global flag with no
  default) and the node's answer is only ever compared against it. `node_chain_id` is the
  single door through which the node's `bud_chainId` may enter a signing path; it refuses
  when the flag is absent and when the ids differ, both before anything is signed. The
  same fix landed on #97 for its `bud tx send` (`--chain-id` there, a required
  subcommand flag, because that tree has the one signing path).
- **Regression tests:** `a_node_on_another_network_cannot_choose_the_replay_domain` and
  `the_chain_to_sign_for_is_a_global_flag` (`src/bin/bud.rs`).
- **Follow-through, same finding (the harnesses and the docs are signing clients too):**
  making the flag required broke every in-repo caller that had relied on the node's answer,
  which is exactly what the check is for. `xtask/tools/src/multinode_smoke.rs` now names the
  devnet id (45262) in `join_args`, `xtask/tools/src/testnet_rehearsal.rs` names the testnet
  id (45261) once in `bud_args` for every scenario command, and `docs/TESTNET.md`,
  `docs/VALIDATOR_GUIDE.md` and `docs/DELEGATION.md` show the flag on every signing example
  plus the reason it has no default. Two tests hold the harnesses to it:
  `the_join_names_the_chain_it_signs_for` and `every_bud_call_names_the_chain_it_signs_for`.
- **Decision note:** a process-wide cell set once from `argv` rather than a parameter
  threaded through fourteen `send_v5` call sites. The property being defended is that no
  signing path can skip the check, and the cell makes the check the only way to obtain the
  value; a parameter is a thing a future call site can forget to pass.

### AF-19 to AF-27 status

All nine are closed by code and tests in the same tree; CI on the head that carries them
is the confirmation. No finding in this round was closed as a false positive or with a
stub, and the one place where a conservative refusal stands in for the full fix (AF-24)
says so in its own entry and in the module note.

### AF-30 - three gate inputs the bundle work left behind (`ci`, `medium`)

Found by running the repository gates over the tree that carries AF-19 to AF-28 rather than
trusting the previous green: three of them were red, and each named a real loose end.

- **Where:** `xtask/gates/pins/budzero-tree.pins`, `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs`,
  `src/chain/chain_actor.rs`, `src/chain/blockchain.rs`, `src/mempool/pool.rs`,
  `src/rpc/server.rs`, `src/bin/budlum-light.rs`.
- **Observed 1 - `tree-pin` red.** AF-24's change to `budzero/bud-pul/src/pul_air.rs` and
  `keccak_chip.rs` landed without re-pinning the budzero tree, so the integrity gate could not
  tell an intentional edit from an outside one: both pins were stale. Fixed by re-pinning the
  two files (`tree-pin --pin`), which is the gate's own documented procedure for an intentional
  change; the pin file is committed with the change that moved it.
- **Observed 2 - `no-out-of-block-consensus-writes` red.** `ChainActor` now calls
  `Blockchain::add_transaction_bundle` and the call was unclassified. Classified `NodeLocal`,
  with the reason written where the next reader looks: a bundle admission touches the pool and
  its pool file, never `self.state`, so a node that admits a bundle and loses it still holds
  the same state root as its peers.
- **Observed 3 - `no-idle-code` red, and the five items were genuinely idle.** AF-19 made
  bundle admission atomic inside the pool, which removed the last external caller of
  `ChainActor::remove_transaction`, `ChainCommand::RemoveTransaction` and
  `Blockchain::remove_transaction`: the per-member rollback that needed them no longer exists,
  and `Blockchain::add_transaction_bundle` persists only after the pool has admitted every
  member. Deleting the three doors is the honest fix, and the `remove_transaction` entry left
  `no_out_of_block_consensus_writes::CALLS` with it. `Mempool::remove_transaction` stays: the
  pool's journal still uses it, and `Blockchain` still calls it from the two places that drop
  a transaction the chain itself invalidated.
- **Observed 3, the other two items, wired rather than deleted:** `BundleRefusal` is now the
  return type all the way up (`Mempool` -> `Blockchain` -> `ChainCommand` -> `ChainActor`), and
  `bud_sendTxBundle` puts the refused member's index in the JSON-RPC error's `data` as
  `{"member": n}` as well as in the message - which is the client-facing half of AF-19 that a
  `String` was throwing away. `LightClient::with_scheme_registry` (AF-22's operator door) is
  wired into its production path: `budlum-light --scheme-registry <file>` parses the registry,
  refuses anything that is not exactly the scheme and suite tables, and installs it before a
  single checkpoint is judged, so the verifier judges a checkpoint by the policy the chain
  publishes instead of by a fresh genesis.
- **Regression tests:** `a_pinned_registry_must_be_the_whole_table` (`src/bin/budlum-light.rs`)
  for the door, the three `Mempool` bundle tests for the refusal path that now carries its
  index to the RPC answer, and the gates themselves: `tree-pin`, `no-out-of-block-consensus-writes`,
  `no-idle-code`, `dead-public-api-is-ratcheted` and `guards-are-reachable` re-run green over
  the tree.

### AF-31 - three findings from the standing #110 review summary that no thread carried (`security`, `high`)

The Strix summary on #110 lists five "to fix before merging" items. Two of them were inline
threads and are closed by AF-23 and AF-27. The other three were written in the summary body
only - no thread, no line anchor - so they were invisible to a thread-by-thread sweep. All
three are read, fixed and pinned here.

- **HIGH: permissionless domain registration let an attacker claim a canonical external chain
  id and write a forged external state root (`src/settlement/domains.rs`).** `external_roots`
  is the only trust anchor the bridge, the relayer and `verify_anchored_result` read for an
  external chain, and the gate that protects it compared the registrant's own
  `domain_chain_id` with the canonical id of the domain id it registered. Registration is
  permissionless, so a registrant supplied both sides of that comparison: mainnet genesis
  seeds only ids 1 to 4, so ids 5 (Polygon), 6 (Arbitrum) and 7 (Optimism) were open to any
  funded account, which could declare the matching chain id, mine a one-header chain at its
  own one-bit difficulty floor and have that root read as Polygon's finalized state.
  **Fix:** `ANCHOR_RECOGNIZED_CHAINS` - the named chains this chain holds an anchor for are
  the ones a genesis seeds a domain for, and the list is written in code because the registry
  is permissionless. A domain at an unseeded canonical id is still registrable and still
  advances; it anchors nothing. Adding a chain is a protocol decision that comes with a
  genesis domain, and `a_bridge_enabled_genesis_domain_is_an_anchor_recognized_chain`
  (`src/chain/genesis.rs`) pins the two to each other on all three networks.
  **Regression test:** `a_chain_no_genesis_seeded_cannot_be_claimed_into_an_anchor` - the
  attacker's best case (Polygon's id, Polygon's canonical chain id, `bridge_enabled`, one-bit
  floor) advances the domain and writes no anchor.
- **MEDIUM: a reorg replacing the block at the active finality checkpoint stopped this node
  voting at that height (`src/network/node.rs`).** Read and confirmed, and the behaviour is
  kept on purpose: signing a second, different hash at one height is equivocation, the one
  fault a validator is slashed for. What was missing was any statement of that, so the two
  doors are now one named predicate, `prevote_is_due` (the round is above the high-water mark,
  or it is the *identical* round being retried), carrying the reasoning. Finality is not
  starved by one silent validator: a quorum needs two thirds, and the validators that did not
  sign the abandoned hash still can. Liveness resumes at the next checkpoint, because the
  interval carries the height past the mark.
  **Regression test:** `a_reorged_checkpoint_is_not_voted_twice_and_the_next_one_is` - the
  same round retries, a different hash at a signed height is refused, and the next checkpoint
  opens both the prevote and the precommit mark.
- **LOW: the two-second reorg window let one peer commission a chain-wide reconstruction every
  two seconds forever (`src/network/node.rs`).** The floor is what fork healing needs - the
  devnet's slot time is the reason it is two seconds and not five minutes - so the fix is not
  a higher floor but a backoff on top of it: every reconstruction that reaches
  `try_reorg_suffix` and comes back an error doubles the window (2, 4, 8, 16, 32, 64 s), and
  any other outcome resets it to the floor. A peer can then only spend work at the rate its
  own failures have bought, while honest fork healing is untouched (the fork it presents is
  either taken or known to be worse, and neither is an error).
  **Regression test:** `a_failing_reconstruction_backs_off_and_a_success_clears_it`.

- **Not a repo defect, recorded so it is not mistaken for one:** Strix's install on this
  workspace is billing-blocked ("this workspace's trial has ended", `issues/97` comment
  2026-10-26). Approval on the PR cannot be produced from inside the tree; the review request
  is posted on the head that carries these fixes.

### AF-29 - the seven dependency-bump PRs are red because `main` is red (`ci`, `medium`)

- **Where:** #113 to #119 (dependabot). Audit of all seven: their own diffs are
  dependency-only, and 62 to 72 of their checks already pass.
- **Observed, job by job:** the red sets repeat the same names - `Secret Scan (gitleaks, full
  history)` (nine `generic-api-key` findings, every one of them in main's history:
  `fuzz/Cargo.lock`, `crates/wallet-core/Cargo.lock`, `Cargo.lock`, `src/crypto/pq.rs`,
  `budzero/bud-vm/src/lib.rs`, `budzero/bud-proof/src/plonky3_prover.rs`,
  `src/cli/commands.rs` - lockfile checksums, ML-DSA type names, `let key = 0x..u64` test
  fixtures and one `self.pkcs11_pq_key_label = ...` field copy), `Cargo Deny (root)`
  (RUSTSEC-2026-0385, -0346, -0347, -0348, -0349, -0382, -0381), `OSV Scanner` (the fuzz
  lockfile), `docker-smoke` (Trivy on the runtime image: `perl-base` CVE-2026-13221, fixed in
  `5.36.0-7+deb12u4`, while main's pinned `bookworm-slim` digest ships `+deb12u3`), plus
  `Repo Lint`, `Coverage`, `Stage 1 (pinned/independent)`, `Auditable + Audit`, `Grype` and
  `Dependency Audit + SBOM`.
- **Verified, not assumed:** every one of those is reproducible on main's head (`c5b06799`,
  72 green of 1236 check-runs, with `RustSec drift` red on repeat) and already fixed in
   `consensus-of-consensuses`: the `.gitleaks.toml` allowlists are path-AND-line scoped
  (`644f021`), the root and sub-lockfiles carry rustls 0.23.46, rustls-webpki 0.103.16,
  webpki-roots 1.0.10 or later, tokio 1.53.3 or later, quinn-proto 0.11.19 (and
  `crates/wallet-core` is on chacha20 0.10.2), and `ops/Dockerfile` pins the newer
  `bookworm-slim` digest with `perl-base` named in the install line so a sliding digest
  cannot reintroduce it.
- **Decision:** no code change and no workflow change inside those seven branches. Their
  branches cannot see the fix because their base cannot, and rewriting their lockfiles would
  copy it into seven places and hand the branch that really carries it seven conflicts. They
  go green when `consensus-of-consensuses` lands on `main`; a rebase after that is free.
- **The one exception is not a failing diff:** #114 to #117 bump the p3 crates to 0.8.0 and
  break the build (`CryptographicHasher` / `PseudoCompressionFunction` bounds,
  `PreprocessedProverData::as_ref`). p3 is pinned `=0.7.0` deliberately - the AIR layouts are
  const-asserted against it and `docs/pq/MEASUREMENTS.md` is measured on it - so 0.8.0 is a
  migration round with a fresh soundness measurement, not a dependency bump. Recorded as a
  decision rather than closed silently.

## Panic bar: what was read, not just what the lints say

`todo!` and `unimplemented!` appear nowhere in `src/`, `crates/`, `budzero/` or `bud/`
outside test modules. `unwrap`/`expect` are denied workspace-wide for library and binary
targets (`Cargo.toml` `[lints.clippy]`), so the panics that remain are `unreachable!`
calls. Each one was located and read, and the enclosing module was computed rather than
guessed:

| Site | Enclosing module | Why it cannot be reached by input |
|---|---|---|
| `src/core/block.rs:491` | none (production) | `slice::chunks(2)` yields only 1- and 2-element slices; the arm is unreachable by construction. |
| `src/storage/db.rs:167` | none (production) | the bounded retry loop returns on success, on the final attempt and on every non-lock error; only the loop's arithmetic is left. |
| `src/security/quantum_canary.rs:366` | `weierstrass` (production) | try-and-increment over a 32-bit counter; exhausting it needs 2^32 consecutive SHA3 outputs that all fail to decode as a curve point. Honest reading: not a compile-time invariant, but not reachable by an input either, because the counter is internal and the digest is a hash of a fixed label. |
| `src/security/quantum_canary.rs:375` | `weierstrass` (production) | `expand_message_xmd` with fixed, valid lengths. |
| `src/domain/finality_adapter.rs:1999`, `src/registry/evidence.rs:1019,1038`, `src/domain/storage_deal.rs:5588`, `src/storage/generated.rs:1536,1577,1594`, `src/core/transaction.rs:5146-5348` (eight), `src/main.rs:2132` | `tests`, `v29_signing_tests` | test modules: a panic is the right behaviour there. |

Nothing was suppressed to make this true: no `#[allow]`, no baseline entry, no lint
downgrade, and the count above is the tree's, not a report's.

## Known gaps that are recorded, not hidden

1. **Validator resource table (`docs/TESTNET.md`, "Validator resources").** Both
   profiles read "not yet measured". The numbers come from
   `budlum-tools resource-sample` against a live validator over ten minutes, which no
   CI job runs and which cannot be produced from a smoke test. Writing plausible
   numbers there would be a placeholder dressed as a measurement, which the directive
   forbids, so the table stays empty and `docs/MAINNET_READINESS.md` already tracks it
   as an open item with the tool named. The testnet participation document is complete
   in every other respect: endpoints, ports, genesis, wallet, faucet, transaction,
   staking, joining, upgrades and the two rehearsals.

---

### AF-32 - §11.7's slash table had one row with no code, and another whose code disagrees with the table (`registry`, `high`)

Read while implementing İP-20's repair-verification leg. §11.7 enumerates seven
behaviours; four of them had no representation anywhere in the tree.

**Closed here.**

`Kanıtlı hatalı onarım` (§6.10 item 8, 1% of stake) had no `SlashingCondition`,
no `SlashingProof`, no parameter and no verifier, so a bad repair produced no
penalty at all - the whole reason a repairer has an incentive to produce correct
symbols was missing. Closed by:

- `SlashingCondition::BadRepair` (`src/registry/permissionless.rs`), its own
  condition because §11.7 prices it at 1% while the only alternative
  (`MaliciousBehaviour`, via a fourth `Other` tag) is 100%: filing a 1% offence
  under a 100% condition would take a Full validator's whole bond.
- `SlashingProof::BadRepair` (`src/registry/evidence.rs`) carrying the object,
  segment, epoch, ESI and the two digests, with a shape check that refuses a
  report whose claimed symbol equals its own re-derivation.
- `RegistryParams::bad_repair_slash_ratio_fixed`, default 1%, whitelisted for
  governance in `core/governance.rs` **and** applied in
  `AccountState::apply_registry_parameter_update` (the pair that has drifted
  before: a name whitelisted but not applied passes the vote and does nothing).
- `src/storage/bud3/repair.rs`: the assignment order (§6.10 item 3, Full only,
  20-block deadline), the 1-in-100 verification draw over consensus data, the
  re-derivation and the report. This file is in İP-20's lock list and did not
  exist.
- Block validation of a `BadRepair` report in
  `Blockchain::apply_block_slashing_reports_in_state`: the object must be live,
  the segment and ESI inside it, the two digests different, and the epoch not
  after the block's.

`Denetim kaçırma` (missed audit) and `İçerik reddi` (declining content) already
produced no penalty, which is what the table says; both are now held by
`bud3_missed_audit_does_not_slash` and `bud3_decline_content_reassigns`.

**Open, and it is a decision rather than a fix.**

§11.7's first row reads *Blok veya kesinlik oyunda çift imza | Tam | Stake'in
yüzde 5'i kesilir. 7 dönem hapis.* The code cuts **50%**
(`RegistryParams::double_sign_slash_ratio_fixed = FIXED_POINT_SCALE / 2`,
pinned by `pos_default_fixed_point_constants_are_exact_integers` and described as
50% in three places in `src/network/node.rs`). A tenfold disagreement between the
directive and the code on a consensus-critical number is not something to change
as a side effect of a storage package: the jailing term in the same row (7
epochs) is the `LIVENESS_JAIL_EPOCHS` constant, already flagged as a
deliberate deviation, and the ratio is İP-16 item 6 ("Kesinti tablosu (Bölüm
11.7) parametreleri"). Recorded here so the number is not discovered by an
operator reading the directive during an incident.
