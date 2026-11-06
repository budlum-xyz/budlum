//! Chain, consensus and state regression tests.
//!
//! Each test locks a fix that is already in the tree: it is green and stays
//! permanent.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use std::sync::Arc;

/// Source of a production file with its `#[cfg(test)]` tail cut off, so a
/// source-scan assertion never matches a test fixture.
fn production_part(src: &str) -> &str {
    src.split("\n#[cfg(test)]\nmod ").next().unwrap_or(src)
}

/// Return the text of the first `{ ... }`-free window of `len` bytes that
/// starts at `anchor`, so a source lock can stay inside one function.
fn window<'a>(src: &'a str, anchor: &str, len: usize) -> &'a str {
    let start = src
        .find(anchor)
        .unwrap_or_else(|| panic!("anchor `{anchor}` not found"));
    let end = (start + len).min(src.len());
    // Stay on a char boundary.
    let mut end = end;
    while !src.is_char_boundary(end) {
        end -= 1;
    }
    &src[start..end]
}

/// A slot whose round-0 election is empty must be able to re-roll.
/// The round is part of the VRF seed (a fresh draw per round), and the round
/// ladder is priced by the parent's timestamp and capped.
#[test]
fn leader_round_rerolls_seed_and_ladder_is_capped() {
    use crate::consensus::pos::{PoSConfig, PoSEngine};
    use crate::consensus::{
        affordable_leader_round, MAX_LEADER_ROUNDS, MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS,
    };
    use crate::core::block::Block;

    let engine = PoSEngine::new(PoSConfig::default(), None);
    let chain = vec![Block::genesis()];
    let chain_id = crate::core::transaction::DEFAULT_CHAIN_ID;
    let r0 = engine
        .calculate_seed_with_chain(chain_id, 0, 1, 0, &chain)
        .unwrap();
    let r1 = engine
        .calculate_seed_with_chain(chain_id, 0, 1, 1, &chain)
        .unwrap();
    assert_ne!(
        r0, r1,
        "round must change the seed so an empty slot re-rolls"
    );
    assert!(
        engine
            .calculate_seed_with_chain(chain_id, 0, 1, MAX_LEADER_ROUNDS + 1, &chain)
            .is_err(),
        "rounds above the cap are refused"
    );

    let parent = 1_000_000u128;
    assert_eq!(affordable_leader_round(parent, parent), 0);
    assert_eq!(
        affordable_leader_round(parent, parent + MIN_BLOCK_INTERVAL_MS + ROUND_TIMEOUT_MS),
        1
    );
    assert_eq!(
        affordable_leader_round(parent, parent + 10_000_000_000),
        MAX_LEADER_ROUNDS
    );
    // A parent stamped in the future pins the ladder at round 0, not a panic.
    assert_eq!(affordable_leader_round(parent + 50_000, parent), 0);
}

/// A peer-controlled hash string in a vote log line must never be
/// cut at a byte offset (a multi-byte character on the cut would panic and
/// abort a release node). Source-level lock: the in-file behavioural test is
/// `network::node::tests::log_prefix_survives_multibyte_input`.
#[test]
fn no_utf8_byte_slice_of_peer_strings_in_vote_handlers() {
    let node = production_part(include_str!("../network/node.rs"));
    assert!(node.contains("fn log_prefix(s: &str, max_chars: usize)"));
    assert!(
        node.matches("log_prefix(&checkpoint_hash, 16)").count() >= 3,
        "Prevote, Precommit and FinalityCert handlers log through log_prefix"
    );
    for forbidden in ["checkpoint_hash[..", "voter_id[..", "&block.hash[.."] {
        assert!(
            !node.contains(forbidden),
            "byte slice `{forbidden}` of a peer string found in network/node.rs"
        );
    }
}

/// `TransactionType::StateUpdate` no longer writes any account
/// nonce. Every sender is refused with `state_update_retired` before any
/// state is touched (commitment nonce writes belong to the settlement door).
#[test]
fn state_update_is_retired_for_every_sender() {
    use crate::core::transaction::{Transaction, TransactionType};
    let mut node = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
    let attacker = Address::from([0xAD; 32]);
    let victim = Address::from([0xB0; 32]);
    node.state.add_balance(&attacker, 1_000_000);
    node.state.add_balance(&victim, 500);
    let tx = Transaction::new_with_chain_id(
        attacker,
        Address::zero(),
        0,
        1,
        node.state.get_nonce(&attacker),
        Vec::new(),
        45262,
        TransactionType::StateUpdate {
            domain_id: 1,
            domain_height: 1,
            state_updates: vec![(victim, u64::MAX - 1001)],
        },
    );
    let err = crate::execution::executor::Executor::apply_transaction_checked(&mut node.state, &tx)
        .expect_err("StateUpdate must be refused");
    assert_eq!(err.code(), "state_update_retired");
    assert_eq!(node.state.get_nonce(&victim), 0, "victim nonce untouched");
}

/// The block producer executes every candidate transaction against a
/// disposable copy and publishes it only on success, so a transaction that
/// fails halfway cannot leave partial writes in the selection prefix.
/// Source-level lock (the failing-halfway fixture needs a bespoke executor
/// arm). The residual gap, that `Executor` has no nonce or signature check of
/// its own, is still open.
#[test]
fn producer_executes_on_a_disposable_candidate_state() {
    let src = production_part(include_str!("../chain/blockchain.rs"));
    let body = window(src, "fn collect_block_transactions(", 5130);
    let clone_at = body
        .find("let mut candidate_state = temp_state.clone();")
        .expect("candidate copy");
    let apply_at = body
        .find("Executor::apply_transaction_checked(&mut candidate_state, tx)")
        .expect("apply on the candidate, not on temp_state");
    let publish_at = body
        .find("temp_state = candidate_state;")
        .expect("publish only after success");
    assert!(clone_at < apply_at && apply_at < publish_at);
    assert!(
        !body.contains("Executor::apply_transaction_checked(&mut temp_state"),
        "the producer must never execute straight on the selection prefix"
    );
}

/// A bond adds to an existing role stake (no override), and the
/// out-of-block RPC doors that wrote the registry on one node are refused.
#[test]
fn role_bond_is_additive_and_rpc_doors_are_refused() {
    use crate::core::account::AccountState;
    use crate::registry::role::roles;
    let mut state = AccountState::new();
    let who = Address::from([0x21; 32]);
    state.add_balance(&who, 10_000_000);
    let min = state.registry.params().min_stake;
    state.bond_relayer(&who, min).unwrap();
    state.bond_relayer(&who, 7).unwrap();
    assert_eq!(
        state.registry.get(&who, roles::RELAYER).unwrap().stake,
        min + 7,
        "a second bond must add to the stake, not replace it"
    );
    assert_eq!(state.get_balance(&who), 10_000_000 - min - 7);

    let rpc = production_part(include_str!("../rpc/server.rs"));
    assert!(rpc.contains("Out-of-block relayer bonding is refused"));
    assert!(rpc.contains("Out-of-block prover bonding is refused"));
    assert!(rpc.contains("Out-of-block role unbonding is refused"));
}

/// Closed proposals are dropped after a
/// retention window, so `GovernanceState::proposals` and the governance root
/// stay bounded. (The `bpqs::EpochWindow` half is `u32::try_from` in
/// `crates/bpqs/src/epoch.rs::epoch_of`, outside this crate's test target.)
/// One proposer cannot hold more than 8
/// active proposals.
#[test]
fn closed_proposals_are_pruned_and_slots_are_capped() {
    use crate::core::governance::{GovernanceState, ProposalType};
    let proposer = Address::from([0x31; 32]);
    let param = || ProposalType::ParameterUpdate("min_stake".into(), "2000".into());

    let mut gov = GovernanceState::default();
    let first = gov.create_proposal(proposer, param(), 0, 10).unwrap();
    gov.find_proposal_mut(first).unwrap().finalize(100, 67, 10);
    assert_eq!(
        gov.proposals.len(),
        1,
        "closed proposal is kept for history"
    );
    // Far beyond activation + retention: the next submission prunes it.
    let far = 1_000_000;
    gov.create_proposal(proposer, param(), far, 10).unwrap();
    assert_eq!(
        gov.proposals.len(),
        1,
        "the closed proposal must be pruned once its retention window passed"
    );

    let mut capped = GovernanceState::default();
    for i in 0..8 {
        capped
            .create_proposal(proposer, param(), 0, 10 + i)
            .unwrap_or_else(|e| panic!("proposal {i} refused: {e}"));
    }
    let err = capped
        .create_proposal(proposer, param(), 0, 10)
        .expect_err("a ninth active proposal from one proposer must be refused");
    assert!(
        err.contains("Too many active proposals for this proposer"),
        "{err}"
    );
}

/// The settlement root is derived from the chain prefix at one place
/// (`apply_block_end_roots`), and every path that re-executes a block
/// (production, validation, candidate validation, reorg persistence, replay)
/// calls it before comparing the state root.
#[test]
fn every_replay_path_derives_the_settlement_root_from_the_prefix() {
    let src = production_part(include_str!("../chain/blockchain.rs"));
    let body = window(src, "fn apply_block_end_roots(", 700);
    assert!(body.contains("state.settlement_root ="));
    assert!(body.contains("settlement_finality_window_for(preceding, chain_id)"));
    assert!(
        src.matches("Self::apply_block_end_roots(").count() >= 4,
        "production, candidate validation, reorg persistence and replay all derive the end roots"
    );
}

/// A remote report of invalid BLS vote signatures cannot slash an
/// innocent validator. The block door re-verifies the voter's own auth
/// signature over the accused sample, binds sample to chain and vote, and
/// refuses a sample whose vote signature is in fact valid.
#[test]
fn invalid_signature_spam_proof_is_authenticated_and_bound() {
    let src = production_part(include_str!("../chain/blockchain.rs"));
    for needle in [
        "InvalidSignatureSpam auth signature failed verification",
        "InvalidSignatureSpam sample carries a valid vote signature",
        "InvalidSignatureSpam sample does not bind this chain",
        "InvalidSignatureSpam sample does not bind the vote it accuses",
        "InvalidSignatureSpam proof contains duplicate vote sample",
    ] {
        assert!(src.contains(needle), "missing refusal: {needle}");
    }
}

/// Reload derives the end-of-block roots and compares the whole state root.
#[test]
fn replay_derives_end_roots() {
    let chain = production_part(include_str!("../chain/blockchain.rs"));
    let at = chain
        .find("Reorg persistence state root mismatch")
        .expect("reorg persistence compares the whole state root");
    let derive = chain[..at]
        .rfind("apply_block_end_roots(")
        .expect("end roots derived before the comparison");
    assert!(
        at - derive < 900,
        "the end roots are derived right before the root comparison"
    );
}

/// The NftBoost share distribution runs in u128, reports overflow as
/// an error instead of aborting, and hands the rounding dust to an operator so
/// no part of the share is lost.
#[test]
f

/// Gossipsub holds a message until the application verdict, so an
/// honest validator's relay is never banned on a pre-validation guess.
#[test]
fn gossip_forwarding_waits_for_the_application_verdict() {
    let code = production_part(include_str!("../network/node.rs"));
    assert!(code.contains(".validate_messages()"));
    for verdict in ["Accept", "Reject", "Ignore"] {
        assert!(code.contains(&format!("gossipsub::MessageAcceptance::{verdict}")));
    }
    let match_pos = code
        .find("match msg {")
        .expect("dispatch on decoded message");
    let accept_pos = code
        .find("gossipsub::MessageAcceptance::Accept")
        .expect("accept verdict");
    let credit_pos = code.find(".record_valid(&peer_id").expect("score credit");
    assert!(accept_pos > match_pos && credit_pos > match_pos);
}

/// A validator cannot re-activate itself by adding stake mid-jail, a
/// governance slash proposal has an execution arm, and a slash reaches stake
/// that already moved into the unbonding queue.
#[test]
fn jail_slash_and_unbonding_are_enforced() {
    let exec = production_part(include_str!("../execution/executor.rs"));
    let stake = window(exec, "TransactionType::Stake =>", 6000);
    assert!(stake.contains("validator_slashed"));
    assert!(stake.contains("&& !v.jailed"), "stake must not lift a jail");
    let account = production_part(include_str!("../core/account.rs"));
    assert!(account.contains("ProposalType::SlashValidator {"));
    let report = window(account, "fn slash_from_report", 6000);
    assert!(
        report.contains("unbonding_queue"),
        "slash must reach unbonding stake"
    );
}

/// No actor command writes state-root-bearing
/// storage state between blocks; each is refused with a pointer to the signed
/// transaction door.
#[test]
f

/// A missed storage challenge settles through
/// the one `apply_bond_slash` path, and the replayable-signature domain tag the
/// ledger names is no longer in the tree.
#[test]
f

/// Every node derives the same
/// finality round from the finalized height alone (the lowest unfinalized
/// checkpoint), and a node votes only once the checkpoint has
/// `FINALITY_VOTE_DEPTH` (4) blocks on top of it. Taking the round from the tip
/// made nodes one block apart vote at different checkpoints and no quorum ever
/// formed. This does not replace a four-node run.
#[test]
fn finality_round_is_the_lowest_unfinalized_checkpoint_after_vote_depth() {
    let producer = Address::from([0x18; 32]);
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
    let interval = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(45262);
    assert!(interval > 0);

    // Tip three blocks above the first checkpoint: too shallow to vote.
    for _ in 0..(interval + 3) {
        bc.produce_block(producer).expect("block");
    }
    bc.start_pending_finality_round();
    assert!(
        bc.finality_aggregator.is_none(),
        "a checkpoint with fewer than 4 blocks on top must not start a round"
    );

    // One more block: the round starts, at the first checkpoint, not at the tip.
    bc.produce_block(producer).expect("block");
    bc.start_pending_finality_round();
    let round = bc.finality_aggregator.as_ref().expect("round started");
    assert_eq!(round.checkpoint_height, interval);

    // After that checkpoint finalizes the next round is exactly one interval up.
    bc.finalized_height = interval;
    for _ in 0..interval {
        bc.produce_block(producer).expect("block");
    }
    bc.start_pending_finality_round();
    let next = bc.finality_aggregator.as_ref().expect("next round");
    assert_eq!(next.checkpoint_height, interval * 2);
}

/// Genesis supply is checked as one total. Plain allocations,
/// the tokenomics distribution and bootstrap validator stake together may not
/// exceed `BUD_TOTAL_SUPPLY`; each part was once checked alone.
#[test]
fn genesis_issuance_is_checked_as_one_total() {
    let mut config = crate::chain::genesis::mainnet_genesis();
    config
        .validate_total_issuance()
        .expect("the pinned mainnet distribution is exactly the fixed supply");
    config.allocations.push((Address::from([0x77; 32]), 1));
    let error = config
        .validate_total_issuance()
        .expect_err("one base unit over the fixed supply must be refused");
    assert!(error.contains("above the fixed supply"), "{error}");
}

/// The default secret and data directories that every profile writes
/// to are excluded from Git (closed in the ledger; this keeps it closed).
#[test]
fn default_secret_and_data_dirs_are_git_ignored() {
    let ignore = include_str!("../../.gitignore");
    let lines: Vec<&str> = ignore.lines().map(str::trim).collect();
    assert!(lines.contains(&"/secrets/"), "/secrets/ must stay ignored");
    assert!(lines.contains(&"/data/"), "/data/ must stay ignored");
}

/// The verification reward pool is paid by the production epoch
/// transition, not only by tests. Source lock: the epoch-close routine in
/// `Blockchain` calls `reward_pool::pay_epoch` with the closed epoch.
#[test]
fn reward_pool_is_paid_from_the_epoch_transition() {
    let src = production_part(include_str!("../chain/blockchain.rs"));
    let at = src
        .find("crate::tokenomics::reward_pool::pay_epoch(state, &schedule, closed_epoch)")
        .expect("pay_epoch must be called from the production epoch transition");
    assert!(
        src[..at]
            .rfind("closed_epoch")
            .is_some_and(|p| at - p < 2500),
        "the call sits in the routine that closes an epoch"
    );
    // The pool pays only what it holds: the budget is capped by its balance.
    let pool = production_part(include_str!("../tokenomics/reward_pool.rs"));
    assert!(pool.contains("state.get_balance(&pool)"));
}

/// The archive profile carries the testnet chain id (not 42), the
/// shipped compose file runs PoS as it claims, and the Dockerfile is English.
#[test]
fn archive_profile_compose_and_dockerfile_are_consistent() {
    let archive = include_str!("../../config/archive.toml");
    assert!(archive.contains("chain_id = 45261"));
    assert!(!archive.contains("chain_id = 42"));
    let testnet = include_str!("../../config/testnet.toml");
    assert!(testnet.contains("chain_id = 45261"));

    let compose = include_str!("../../ops/docker-compose.yml");
    assert!(compose.contains("--consensus=pos"));
    assert!(!compose.contains("--consensus=pow"));
    assert!(!compose.contains("--difficulty=0"));

    let dockerfile = include_str!("../../ops/Dockerfile");
    let turkish = [
        '\u{e7}', '\u{11f}', '\u{131}', '\u{f6}', '\u{15f}', '\u{fc}', '\u{130}', '\u{15e}',
        '\u{11e}', '\u{c7}', '\u{d6}', '\u{dc}',
    ];
    assert!(
        !dockerfile.chars().any(|c| turkish.contains(&c)),
        "ops/Dockerfile must be English"
    );
}

/// Finality certificates are verified with stake weight and a signer
/// count (not a bare head count), and the account-proof trie cache is keyed by
/// the exact account list it was built from, so it cannot serve a stale trie
/// at the same chain height.
#[test]
fn qc_import_is_weighted_and_proof_cache_is_content_keyed() {
    let chain = production_part(include_str!("../chain/blockchain.rs"));
    assert!(chain.contains(
        "if stake < snapshot.quorum_stake() || verified_signers.len() < snapshot.quorum_count()"
    ));
    let actor = production_part(include_str!("../chain/chain_actor.rs"));
    let cache = window(actor, "fn account_proof(&mut self", 1200);
    assert!(cache.contains("cached.leaves.len() == accounts.len()"));
    assert!(cache.contains("l.1 == acct.balance && l.2 == acct.nonce"));
}

/// An interrupted-commit marker that cannot be read or rolled back
/// stops the open instead of being swallowed.
#[test]
fn interrupted_commit_recovery_errors_propagate() {
    let db = production_part(include_str!("../storage/db.rs"));
    assert!(
        db.matches("recover_interrupted_commit()?;").count() >= 2,
        "both open paths must propagate a recovery error"
    );
    let body = window(db, "pub fn recover_interrupted_commit(", 900);
    assert!(
        body.contains("IN_PROGRESS_HEIGHT holds"),
        "a corrupt marker is an error, not height 0"
    );
}

/// Replay slices the chain by `block.index`; the loader only
/// returns a chain whose indices step by one from a verified walk, so the
/// slice cannot go out of bounds.
#[test]
fn stored_chain_is_walk_checked_before_replay_slices_it() {
    let db = production_part(include_str!("../storage/db.rs"));
    let load = window(db, "pub fn load_chain(", 2600);
    assert!(load.contains("Self::check_walk_step("));
}

/// The executor holds no lock of its own, so there is no lock error
/// left to swallow there (the finding is invalid on live).
#[test]
fn executor_takes_no_locks() {
    let exec = production_part(include_str!("../execution/executor.rs"));
    for needle in [
        ".lock()",
        ".read()",
        ".write()",
        ".try_lock()",
        ".try_read()",
        ".try_write()",
    ] {
        assert!(!exec.contains(needle), "executor.rs now calls `{needle}`");
    }
}

/// Every transaction type has an apply arm. Every variant of
/// `TransactionType` is named inside `apply_transaction_checked`.
#[test]
fn every_transaction_type_has_an_apply_arm() {
    let tx_src = include_str!("../core/transaction.rs");
    let enum_start = tx_src.find("pub enum TransactionType {").expect("enum");
    let body = &tx_src[enum_start..];
    let body = &body[..body.find("\n}\n").expect("end of enum")];
    let variants: Vec<&str> = body
        .lines()
        .skip(1)
        .filter(|l| {
            l.starts_with("    ") && !l.starts_with("     ") && !l.trim_start().starts_with("//")
        })
        .filter_map(|l| {
            let name: &str = l.trim().split(|c: char| !c.is_alphanumeric()).next()?;
            name.chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
                .then_some(name)
        })
        .collect();
    assert!(
        variants.len() >= 60,
        "parsed only {} variants",
        variants.len()
    );
    let exec = production_part(include_str!("../execution/executor.rs"));
    let apply = window(exec, "pub fn apply_transaction_checked(", 400_000);
    for v in &variants {
        assert!(
            apply.contains(&format!("TransactionType::{v}")),
            "no apply arm names TransactionType::{v}"
        );
    }
}
