//! Tests for this turn's features:
//!  1. CrossDomainMessage -> relayer registration gating
//!  2. Slashing-report anti-spam fee (with refund on actionable reports)
//!  3. Liveness fault detection -> slash via the existing report flow
//!
//! Unit-level behaviour of the liveness tracker itself lives in
//! `registry::liveness::tests`; here we exercise the wiring through
//! `Blockchain` / `AccountState`.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::account::AccountState;
use crate::core::address::Address;

use crate::core::chain_config::FIXED_POINT_SCALE;
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};
use crate::cross_domain::MessageKind;
use crate::registry::evidence::{SlashingProof, SlashingReport};
use crate::registry::role::roles;
use crate::storage::db::Storage;
use std::collections::HashSet;
use std::sync::Arc;
use tempfile::tempdir;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn fresh_chain() -> Blockchain {
    let consensus = Arc::new(PoWEngine::new(0));
    Blockchain::new(consensus, None, 45262, None)
}

/// The default is observe-only (`liveness_slashing_enabled = false`), so the
/// end-to-end slashing tests opt in explicitly instead of relying on a default
/// that a later change can flip underneath them.
fn enable_liveness_slashing(bc: &mut Blockchain) {
    let mut params = *bc.state.registry.params();
    params.liveness_slashing_enabled = true;
    bc.state.registry.set_params(params);
}

fn relayed_message(sender: Address, nonce: u64) -> CrossDomainMessage {
    CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 2,
        source_height: 10,
        event_index: 0,
        nonce,
        sender,
        recipient: addr(0xEE),
        payload_hash: [9u8; 32],
        kind: MessageKind::BridgeLock,
        expiry_height: 100,
    })
}

/// A V4 transaction from `keypair` that carries `message` through the
/// `RelayCrossDomainMessage` door (N-12).
fn relay_tx(
    keypair: &crate::crypto::primitives::KeyPair,
    message: CrossDomainMessage,
) -> crate::core::transaction::Transaction {
    let from = Address::from(keypair.public_key_bytes());
    let mut tx = crate::core::transaction::Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        1,
        0,
        Vec::new(),
        45262,
        crate::core::transaction::TransactionType::RelayCrossDomainMessage(message),
    );
    tx.sign(keypair);
    tx
}

/// A bonded relayer with a fresh Ed25519 key, funded for fees.
fn bonded_relayer(bc: &mut Blockchain) -> (crate::crypto::primitives::KeyPair, Address) {
    let keypair = crate::crypto::primitives::KeyPair::generate().unwrap();
    let relayer = Address::from(keypair.public_key_bytes());
    bc.state.add_balance(&relayer, 5_000);
    bc.state.bond_relayer(&relayer, 2_000).unwrap();
    assert!(bc.state.registry.is_active_relayer(&relayer));
    (keypair, relayer)
}

// --- 1. Relayer gating (the RelayCrossDomainMessage door, N-12) -------------

#[test]
fn unregistered_account_cannot_submit_cross_domain_message() {
    let mut bc = fresh_chain();
    let stranger = addr(0x01);
    let err = bc
        .state
        .register_relayed_cross_domain_message(&stranger, &relayed_message(stranger, 1))
        .unwrap_err();
    assert!(err.contains("not an active relayer"), "{err}");
    // No message stored.
    assert_eq!(bc.state.message_registry.len(), 0);
}

/// The door end to end: a signed transaction through the executor registers
/// the message, charges the fee and advances the nonce.
#[test]
fn active_relayer_registers_through_the_transaction_door() {
    let mut bc = fresh_chain();
    let (keypair, relayer) = bonded_relayer(&mut bc);
    let balance_before = bc.state.get_balance(&relayer);
    let tx = relay_tx(&keypair, relayed_message(relayer, 1));
    assert!(
        tx.is_valid(),
        "a well-formed relay transaction passes the shape check"
    );

    crate::execution::executor::Executor::apply_transaction(&mut bc.state, &tx).unwrap();

    assert_eq!(bc.state.message_registry.len(), 1);
    assert_eq!(bc.state.get_balance(&relayer), balance_before - tx.fee);
    assert_eq!(bc.state.get_nonce(&relayer), 1);
}

/// The transaction signature is the authentication, so the message must
/// name the signer as its sender. Naming another active relayer is the
/// spoof BLG-0113 closed, and it stays closed at the new door.
#[test]
fn a_relayed_message_must_name_its_signer_as_sender() {
    let mut bc = fresh_chain();
    let (keypair, relayer) = bonded_relayer(&mut bc);
    let (_, other_relayer) = bonded_relayer(&mut bc);

    // Naming another relayer: refused by the shape check and by the body.
    let spoof = relayed_message(other_relayer, 1);
    assert!(!relay_tx(&keypair, spoof.clone()).is_valid());
    let err = bc
        .state
        .register_relayed_cross_domain_message(&relayer, &spoof)
        .unwrap_err();
    assert!(err.contains("not the transaction signer"), "{err}");

    // A body tampered after the id was computed: the id no longer matches
    // its preimage, so a pre-registered id cannot be reused for a different
    // message.
    let mut tampered = relayed_message(relayer, 1);
    tampered.recipient = addr(0xEF);
    let err = bc
        .state
        .register_relayed_cross_domain_message(&relayer, &tampered)
        .unwrap_err();
    assert!(err.contains("preimage"), "{err}");
    assert_eq!(bc.state.message_registry.len(), 0, "nothing registered");
}

/// The envelope is outside the signing preimage, so the door refuses any
/// bytes there rather than store something a relay could have rewritten.
#[test]
fn a_relayed_message_with_a_sender_envelope_is_refused() {
    let mut bc = fresh_chain();
    let (keypair, relayer) = bonded_relayer(&mut bc);
    let mut msg = relayed_message(relayer, 1);
    msg.sender_public_key = keypair.public_key_bytes().to_vec();
    msg.sender_signature = keypair.sign(&msg.message_id).to_vec();
    let err = bc
        .state
        .register_relayed_cross_domain_message(&relayer, &msg)
        .unwrap_err();
    assert!(err.contains("envelope"), "{err}");
    assert_eq!(bc.state.message_registry.len(), 0);
}

#[test]
fn a_relayed_message_past_its_expiry_is_refused() {
    let mut bc = fresh_chain();
    let (_, relayer) = bonded_relayer(&mut bc);
    // `relayed_message` expires at height 100.
    bc.state.current_block_height = 101;
    let err = bc
        .state
        .register_relayed_cross_domain_message(&relayer, &relayed_message(relayer, 1))
        .unwrap_err();
    assert!(err.contains("expired"), "{err}");
    assert_eq!(bc.state.message_registry.len(), 0);
}

#[test]
fn slashed_relayer_cannot_submit_cross_domain_message() {
    let mut bc = fresh_chain();
    let relayer = addr(0x03);
    bc.state.add_balance(&relayer, 5_000);
    bc.state.bond_relayer(&relayer, 2_000).unwrap();
    // Slash the relayer role fully.
    bc.state
        .registry
        .slash(
            relayer,
            roles::RELAYER,
            crate::registry::SlashingCondition::MaliciousBehaviour,
            FIXED_POINT_SCALE,
        )
        .unwrap();
    assert!(!bc.state.registry.is_active_relayer(&relayer));

    let err = bc
        .state
        .register_relayed_cross_domain_message(&relayer, &relayed_message(relayer, 1))
        .unwrap_err();
    assert!(err.contains("not an active relayer"), "{err}");
}

#[test]
fn unbonding_relayer_can_still_submit() {
    // Decision: unbonding is an exit process, not a punishment; the stake is
    // Still locked and slashable, so the relayer may keep relaying.
    let mut bc = fresh_chain();
    let (_, relayer) = bonded_relayer(&mut bc);
    bc.state
        .registry
        .begin_unbonding(relayer, roles::RELAYER, 0)
        .unwrap();
    assert!(bc.state.registry.is_active_relayer(&relayer));
    bc.state
        .register_relayed_cross_domain_message(&relayer, &relayed_message(relayer, 1))
        .unwrap();
    assert_eq!(bc.state.message_registry.len(), 1);
}

#[test]
fn system_bridge_path_bypasses_relayer_gate() {
    // The internal primitive (used by bridge lock/burn events) must NOT require
    // Relayer registration - those messages come from authorized on-chain logic.
    let mut bc = fresh_chain();
    bc.submit_cross_domain_message(relayed_message(addr(0x05), 1))
        .unwrap();
    assert_eq!(bc.state.message_registry.len(), 1);
}

// --- 2. Anti-spam fee -------------------------------------------------------

fn double_sign_report(
    keys: &crate::crypto::primitives::KeyPair,
    reporter: Option<Address>,
) -> SlashingReport {
    let offender = Address::from(keys.public_key_bytes());
    let (h1, h2) = ([0x55u8; 32], [0x66u8; 32]);
    SlashingReport::consensus_double_sign(
        offender,
        SlashingProof::DoubleSign {
            height: 7,
            kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
            epoch: None,
            block_hash_1: hex::encode(h1),
            block_hash_2: hex::encode(h2),
            signature_1: keys.sign(&h1).to_vec(),
            signature_2: keys.sign(&h2).to_vec(),
        },
        reporter,
    )
}

#[test]
fn actionable_report_refunds_fee() {
    let mut bc = fresh_chain();
    let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let offender = Address::from(keys.public_key_bytes());
    let reporter = addr(0x12);
    bc.state.add_balance(&offender, 1_000_000);
    bc.state.bond_relayer(&offender, 10_000).unwrap(); // registered so slashable
                                                       // Register offender as validator too (double-sign is a validator offence).
    bc.state.add_validator(offender, 10_000);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&reporter, fee);

    let before = bc.state.get_balance(&reporter);
    let outcome = bc
        .submit_registry_slashing_report(double_sign_report(&keys, Some(reporter)))
        .unwrap();
    assert!(outcome.is_some(), "validator should have been slashed");
    // Fee refunded because the report was actionable.
    assert_eq!(bc.state.get_balance(&reporter), before);
}

#[test]
fn an_unprovable_report_is_refused_before_the_fee_is_taken() {
    // This used to assert the opposite, that the fee was burned, and the
    // assertion was right about the code and wrong about what the code should
    // do. Every externally submitted report arrived `Unverified`, every
    // `Unverified` report was refused, and the refusal burned the fee. The
    // endpoint could take money and could not produce a slash, so an honest
    // reporter holding real proof paid to be ignored.
    //
    // A report that cannot be checked still must not slash anybody. What
    // changed is that it no longer costs anything either: refusal happens
    // before the debit.
    let mut bc = fresh_chain();
    let offender = addr(0x13);
    let reporter = addr(0x14);
    bc.state.add_validator(offender, 10_000);
    bc.state.sync_validator_registration(&offender);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&reporter, fee);

    let report = SlashingReport::new(
        offender,
        roles::VALIDATOR,
        SlashingProof::DoubleSign {
            height: 7,
            kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
            epoch: None,
            block_hash_1: "aa".into(),
            block_hash_2: "bb".into(),
            signature_1: vec![1],
            signature_2: vec![2],
        },
        Some(reporter),
    );
    assert!(bc.submit_registry_slashing_report(report).is_err());
    assert_eq!(
        bc.state.get_balance(&reporter),
        fee,
        "an unprovable report must cost nothing: it proves nothing either way"
    );
    // Offender untouched.
    assert!(bc.state.registry.is_active(&offender, roles::VALIDATOR));
}

#[test]
fn a_provable_report_from_a_stranger_slashes_and_refunds() {
    // The case the endpoint serves: a report whose provenance was already
    // established by the consensus path (the aggregator verified both
    // signatures against the validator snapshot at ingest) is actionable.
    // An `Unverified` report is refused at the RPC boundary now: two valid
    // signatures over two different hashes are not, on their own, an
    // equivocation proof, because a validator signs one block per height
    // and the node does not hold the rival block.
    let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let offender = Address::from(keys.public_key_bytes());
    let reporter = addr(0x1A);

    let mut bc = fresh_chain();
    bc.state.add_validator(offender, 10_000);
    bc.state.sync_validator_registration(&offender);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&reporter, fee);

    let (h1, h2) = ([0x11u8; 32], [0x22u8; 32]);
    let report = SlashingReport::new_verified(
        offender,
        roles::VALIDATOR,
        SlashingProof::DoubleSign {
            height: 7,
            kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
            epoch: None,
            block_hash_1: hex::encode(h1),
            block_hash_2: hex::encode(h2),
            signature_1: keys.sign(&h1).to_vec(),
            signature_2: keys.sign(&h2).to_vec(),
        },
        Some(reporter),
    );

    let outcome = bc
        .submit_registry_slashing_report(report)
        .expect("a consensus-verified equivocation must be actionable");
    assert!(outcome.is_some(), "the equivocating validator is slashed");
    assert_eq!(
        bc.state.get_balance(&reporter),
        fee,
        "an honest reporter gets the fee back"
    );
}

#[test]
fn a_stranger_cannot_slash_a_validator_by_asserting_provenance() {
    // The report claims to be consensus-verified. It is not, and the
    // signatures are somebody else's. If the endpoint believed either claim,
    // slashing would be a thing any account could do to any validator for the
    // price of the fee.
    let victim_keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let attacker_keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let victim = Address::from(victim_keys.public_key_bytes());
    let attacker = addr(0x1B);

    let mut bc = fresh_chain();
    bc.state.add_validator(victim, 10_000);
    bc.state.sync_validator_registration(&victim);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&attacker, fee);
    let stake_before = bc
        .state
        .registry
        .get(&victim, roles::VALIDATOR)
        .unwrap()
        .stake;

    let (h1, h2) = ([0x33u8; 32], [0x44u8; 32]);
    let report = SlashingReport::new(
        victim,
        roles::VALIDATOR,
        SlashingProof::DoubleSign {
            height: 7,
            kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
            epoch: None,
            block_hash_1: hex::encode(h1),
            block_hash_2: hex::encode(h2),
            // Signed by the attacker's key, filed against the victim.
            signature_1: attacker_keys.sign(&h1).to_vec(),
            signature_2: attacker_keys.sign(&h2).to_vec(),
        },
        // The RPC layer overwrites this to `Unverified`; asserted here to
        // show the chain layer does not depend on the RPC layer to do so.
        Some(attacker),
    );

    assert!(bc.submit_registry_slashing_report(report).is_err());
    assert_eq!(
        bc.state
            .registry
            .get(&victim, roles::VALIDATOR)
            .unwrap()
            .stake,
        stake_before,
        "an innocent validator keeps every unit of stake"
    );
    assert!(bc.state.registry.is_active(&victim, roles::VALIDATOR));
}

#[test]
fn a_self_asserted_consensus_verified_report_with_forged_data_is_refused() {
    let victim_keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let attacker_keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let victim = Address::from(victim_keys.public_key_bytes());
    let attacker = addr(0x1C);

    let mut bc = fresh_chain();
    bc.state.add_validator(victim, 10_000);
    bc.state.sync_validator_registration(&victim);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&attacker, fee);
    let stake_before = bc
        .state
        .registry
        .get(&victim, roles::VALIDATOR)
        .unwrap()
        .stake;

    let (h1, h2) = ([0x33u8; 32], [0x44u8; 32]);
    let proofs = [
        // Made-up hashes and signatures.
        SlashingProof::DoubleSign {
            height: 7,
            kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
            epoch: None,
            block_hash_1: "aa".into(),
            block_hash_2: "bb".into(),
            signature_1: vec![1],
            signature_2: vec![2],
        },
        // Well formed, but signed by another key.
        SlashingProof::DoubleSign {
            height: 7,
            kind: crate::registry::evidence::DoubleSignKind::BlockHeader,
            epoch: None,
            block_hash_1: hex::encode(h1),
            block_hash_2: hex::encode(h2),
            signature_1: attacker_keys.sign(&h1).to_vec(),
            signature_2: attacker_keys.sign(&h2).to_vec(),
        },
    ];
    for proof in proofs {
        let report = SlashingReport::consensus_double_sign(victim, proof, Some(attacker));
        assert!(bc.submit_registry_slashing_report(report).is_err());
    }
    assert_eq!(
        bc.state
            .registry
            .get(&victim, roles::VALIDATOR)
            .unwrap()
            .stake,
        stake_before,
        "an innocent validator keeps every unit of stake"
    );
    assert_eq!(
        bc.state.get_balance(&attacker),
        fee,
        "a refused report costs nothing"
    );
}

#[test]
fn report_fee_insufficient_balance_rejected_without_state_change() {
    let mut bc = fresh_chain();
    let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let offender = Address::from(keys.public_key_bytes());
    let reporter = addr(0x16); // no balance
    bc.state.add_validator(offender, 10_000);
    bc.state.sync_validator_registration(&offender);

    let err = bc
        .submit_registry_slashing_report(double_sign_report(&keys, Some(reporter)))
        .unwrap_err();
    assert!(err.contains("insufficient balance"));
    // Offender not slashed.
    assert!(bc.state.registry.is_active(&offender, roles::VALIDATOR));
}

#[test]
fn consensus_internal_report_pays_no_fee() {
    // Reporter: None -> no fee charged (used by consensus-generated reports).
    let mut bc = fresh_chain();
    let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let offender = Address::from(keys.public_key_bytes());
    bc.state.add_validator(offender, 10_000);
    bc.state.sync_validator_registration(&offender);
    let outcome = bc
        .submit_registry_slashing_report(double_sign_report(&keys, None))
        .unwrap();
    assert!(outcome.is_some());
}

#[test]
fn report_against_unregistered_still_refunds_fee() {
    // Ok(None): verified but offender unregistered -> treated as actionable,
    // So the honest reporter is refunded (regression of previous-turn noop test).
    let mut bc = fresh_chain();
    let reporter = addr(0x18);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&reporter, fee);
    let before = bc.state.get_balance(&reporter);
    let outcome = bc
        .submit_registry_slashing_report(double_sign_report(
            &crate::crypto::primitives::KeyPair::generate().unwrap(),
            Some(reporter),
        ))
        .unwrap();
    assert_eq!(outcome, None);
    assert_eq!(bc.state.get_balance(&reporter), before);
}

// --- 3. Liveness ------------------------------------------------------------

fn state_with_validator(v: Address, stake: u64) -> AccountState {
    let mut state = AccountState::new();
    state.add_validator(v, stake);
    state.sync_validator_registration(&v);
    state
}

#[test]
fn consecutive_liveness_failures_trigger_slash() {
    // Use an isolated AccountState with exactly one validator so the count is
    // Deterministic (fresh_chain seeds a genesis validator).
    let v = addr(0x21);
    let mut state = state_with_validator(v, 10_000);
    let k = state.registry.params().liveness_max_missed_epochs;

    let none: HashSet<Address> = HashSet::new();
    // Miss k-1 epochs: no report yet.
    for e in 1..k {
        assert!(state.record_liveness_epoch(e, &none).is_empty());
    }
    assert!(state.registry.is_active(&v, roles::VALIDATOR));
    // K-th consecutive miss produces exactly one report for this validator.
    let reports = state.record_liveness_epoch(k, &none);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].offender, v);
}

#[test]
fn liveness_slash_applied_through_blockchain_flow() {
    // End-to-end: reports generated at the chain level are routed through the
    // Existing report->slash flow and the target validator ends up slashed.
    let mut bc = fresh_chain();
    enable_liveness_slashing(&mut bc);
    let v = addr(0x2A);
    bc.state.add_validator(v, 10_000);
    bc.state.sync_validator_registration(&v);
    let k = bc.state.registry.params().liveness_max_missed_epochs;

    // Everyone participates except `v` (so the genesis validator is unaffected).
    let mut present: HashSet<Address> = bc.state.validators.keys().copied().collect();
    present.remove(&v);

    for e in 1..k {
        assert_eq!(bc.record_liveness_epoch(e, &present), 0);
    }
    assert_eq!(bc.record_liveness_epoch(k, &present), 1);
    // A liveness fault is a timed jail (BLG-0087, decision B): the validator
    // leaves the active set but is not slashed, so its release is possible.
    let jailed = bc.state.validators.get(&v).expect("still a validator");
    assert!(jailed.jailed && !jailed.active && !jailed.slashed);
}

#[test]
fn liveness_counter_resets_on_participation() {
    let mut state = state_with_validator(addr(0x22), 10_000);
    let v = addr(0x22);
    let k = state.registry.params().liveness_max_missed_epochs;
    let none: HashSet<Address> = HashSet::new();
    let mut present: HashSet<Address> = HashSet::new();
    present.insert(v);

    for e in 1..k {
        state.record_liveness_epoch(e, &none);
    }
    assert_eq!(state.liveness.missed_count(&v), k - 1);
    // Participation resets the streak.
    state.record_liveness_epoch(k, &present);
    assert_eq!(state.liveness.missed_count(&v), 0);
}

#[test]
fn liveness_slash_uses_configured_rate() {
    let mut bc = fresh_chain();
    enable_liveness_slashing(&mut bc);
    let v = addr(0x23);
    let stake = 10_000u64;
    bc.state.add_validator(v, stake);
    bc.state.sync_validator_registration(&v);
    let k = bc.state.registry.params().liveness_max_missed_epochs;
    let rate = bc.state.registry.params().liveness_slash_ratio_fixed;
    // Computed by the same function production uses, not by a second copy of
    // the expression. A test that recomputes the formula by hand agrees with
    // production only until one of the two changes, and B35 was exactly that:
    // five copies, two spellings of the narrowing, and a mirror test that
    // compared them only where they happened to agree.
    let expected_penalty = crate::core::chain_config::slash_penalty(stake, rate);

    let none: HashSet<Address> = HashSet::new();
    for e in 1..=k {
        bc.record_liveness_epoch(e, &none);
    }
    let member = bc.state.registry.get(&v, roles::VALIDATOR).unwrap();
    assert_eq!(member.stake, stake - expected_penalty);
}

#[test]
fn liveness_does_not_affect_double_sign_flow() {
    // Regression: the double-sign path still slashes at its own (50%) rate,
    // Unaffected by liveness wiring.
    let mut bc = fresh_chain();
    let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let offender = Address::from(keys.public_key_bytes());
    let stake = 10_000u64;
    bc.state.add_validator(offender, stake);
    bc.state.sync_validator_registration(&offender);
    let outcome = bc
        .submit_registry_slashing_report(double_sign_report(&keys, None))
        .unwrap()
        .unwrap();
    assert_eq!(outcome.penalty, stake / 2);
}

// --- 4. Quarantine ledger persistence (E1 acceptance) ----------------------

#[test]
fn quarantine_ledger_rows_survive_restart_after_slash() {
    let dir = tempdir().unwrap();
    let db_path = dir
        .path()
        .join("quarantine.db")
        .to_string_lossy()
        .to_string();

    let mut bc = Blockchain::new(
        Arc::new(PoWEngine::new(0)),
        Some(Storage::new(&db_path).unwrap()),
        45262,
        None,
    );
    let keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let offender = Address::from(keys.public_key_bytes());
    let reporter = addr(0x12);
    bc.state.add_balance(&offender, 1_000_000);
    bc.state.bond_relayer(&offender, 10_000).unwrap();
    bc.state.add_validator(offender, 10_000);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&reporter, fee);

    bc.submit_registry_slashing_report(double_sign_report(&keys, Some(reporter)))
        .unwrap()
        .expect("validator should have been slashed");

    // The slash lands in both ledgers before the node drops.
    assert_eq!(bc.quarantine_ledger.quarantined_entities.len(), 1);
    assert_eq!(bc.quarantine_ledger.alarms.len(), 1);
    drop(bc);

    // Same storage path, brand-new node: the rows must still be there.
    let restarted = Blockchain::new(
        Arc::new(PoWEngine::new(0)),
        Some(Storage::new(&db_path).unwrap()),
        45262,
        None,
    );
    assert_eq!(restarted.quarantine_ledger.quarantined_entities.len(), 1);
    assert_eq!(restarted.quarantine_ledger.alarms.len(), 1);
    let entry = restarted
        .quarantine_ledger
        .quarantined_entities
        .values()
        .next()
        .expect("quarantine row survived the restart");
    assert!(matches!(
        entry.reason,
        crate::registry::QuarantineReason::OperatorSlash(_)
    ));
    let alarm = restarted
        .quarantine_ledger
        .alarms
        .values()
        .next()
        .expect("alarm row survived the restart");
    assert_eq!(alarm.severity, 3);
}
