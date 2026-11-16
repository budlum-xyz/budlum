//! Validator classes and the single registration door, and the Mobile duty
//! lane those classes feed.
//!
//! The lane's two named tests (`mobile_duty_tx_lane_is_rate_limited`,
//! `duty_lane_budget_is_twenty_percent`) live here because the lane exists for
//! the Mobile class: a Full validator answers audits from a machine that pays
//! fees without noticing, and the free, rate limited lane is what makes a
//! phone's duty work affordable.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::crypto::primitives::{KeyPair, ValidatorKeys};
use crate::crypto::scheme::SchemeId;
use crate::execution::executor::Executor;
use crate::mempool::duty_lane::{block_bytes, block_share_bytes, is_duty, window_at, DutyRefusal};
use crate::mempool::pool::{Mempool, MempoolConfig, MempoolError, DEFAULT_DUTY_BLOCK_BYTES};
use crate::storage::bud3::tx::StorageTxV3;
use crate::validators::{
    quota_update_message, LeaderCommitment, SeatFields, ValidatorClass, ValidatorRegistration,
    ValidatorTx,
};

const TESTNET: u64 = 45261;

fn operator_seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn operator_key(n: u8) -> Vec<u8> {
    crate::crypto::pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &operator_seed(n)).unwrap()
}

fn operator_sign(n: u8, chain_id: u64, owner: &Address, quota: u64, seq: u64) -> Vec<u8> {
    crate::crypto::pq::ml_dsa_sign(
        SchemeId::ML_DSA_65,
        &operator_seed(n),
        &quota_update_message(chain_id, owner, quota, seq),
        crate::crypto::ctx::VALIDATOR_V1,
        &[0u8; 32],
    )
    .unwrap()
}

struct Fixture {
    owner: Address,
    bls_key: Vec<u8>,
    bls_pop: Vec<u8>,
    seat: SeatFields,
}

fn fixture(owner_byte: u8, chain_id: u64) -> Fixture {
    fixture_for(Address::from([owner_byte; 32]), chain_id)
}

fn fixture_for(owner: Address, chain_id: u64) -> Fixture {
    let keys = ValidatorKeys::generate().unwrap();
    let bls = keys.bls_key.as_ref().unwrap();
    Fixture {
        owner,
        bls_key: bls.public_key.clone(),
        bls_pop: bls.generate_pop(chain_id, &owner),
        seat: SeatFields {
            vrf_key: keys.vrf_key.public.to_bytes().to_vec(),
            pq_vote_key: keys.pq_key.as_ref().unwrap().public_key_bytes().to_vec(),
            leader_commitment: LeaderCommitment {
                commitment: [7u8; 32],
                length: 1024,
            },
        },
    }
}

fn registration(f: &Fixture, class: ValidatorClass, n: u8) -> ValidatorRegistration {
    ValidatorRegistration {
        owner: f.owner,
        class,
        operator_key: operator_key(n),
        bls_key: f.bls_key.clone(),
        bls_pop: f.bls_pop.clone(),
        seat: class.holds_seat().then(|| f.seat.clone()),
        custody_quota_bytes: 1 << 30,
        relay_offer: None,
        gateway_offer: None,
        peer_id: [n; 32],
    }
}

fn tx(from: Address, amount: u64, nonce: u64, chain_id: u64, v: ValidatorTx) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        1,
        nonce,
        Vec::new(),
        chain_id,
        TransactionType::Validator(v),
    )
}

fn apply(state: &mut AccountState, t: &Transaction) -> Result<(), String> {
    Executor::apply_transaction_checked(state, t).map_err(|e| e.code().to_string())
}

fn funded(owner: &Address, amount: u64) -> AccountState {
    let mut state = AccountState::new();
    state.add_balance(owner, amount);
    state
}

#[test]
fn validator_registration_requires_class_min_stake() {
    // Devnet floors: Full 1_000, Mobile 100.
    let f = fixture(1, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    let full = registration(&f, ValidatorClass::Full, 1);
    let below = tx(
        f.owner,
        999,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(full.clone())),
    );
    assert_eq!(
        apply(&mut state, &below).unwrap_err(),
        "validator_stake_below_class_floor"
    );
    let at_floor = tx(
        f.owner,
        1_000,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(full)),
    );
    apply(&mut state, &at_floor).unwrap();
    let validator = state
        .validators
        .get(&f.owner)
        .expect("Full joins the consensus set");
    assert!(validator.active, "a registered Full validator is active");
    assert_eq!(validator.stake, 1_000);
    assert_eq!(
        state.validator_directory.get(&f.owner).unwrap().class,
        ValidatorClass::Full
    );

    let m = fixture(2, DEFAULT_CHAIN_ID);
    let mut state = funded(&m.owner, 10_000);
    let mobile = registration(&m, ValidatorClass::Mobile, 2);
    let below = tx(
        m.owner,
        99,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(mobile.clone())),
    );
    assert_eq!(
        apply(&mut state, &below).unwrap_err(),
        "validator_stake_below_class_floor"
    );
    let ok = tx(
        m.owner,
        100,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(mobile)),
    );
    apply(&mut state, &ok).unwrap();
    assert!(
        !state.validators.contains_key(&m.owner),
        "a mobile validator holds no consensus seat"
    );
    assert_eq!(state.validator_directory.get(&m.owner).unwrap().stake, 100);
}

#[test]
fn the_testnet_floors_are_ten_bud_for_a_phone_and_a_thousand_for_a_full_validator() {
    use crate::tokenomics::bud;
    let m = fixture(3, TESTNET);
    let mut state = funded(&m.owner, bud(2_000));
    let mobile = registration(&m, ValidatorClass::Mobile, 3);
    let ten = tx(
        m.owner,
        bud(10),
        0,
        TESTNET,
        ValidatorTx::Register(Box::new(mobile)),
    );
    apply(&mut state, &ten).unwrap();

    let f = fixture(4, TESTNET);
    let mut state = funded(&f.owner, bud(2_000));
    let full = registration(&f, ValidatorClass::Full, 4);
    let ten = tx(
        f.owner,
        bud(10),
        0,
        TESTNET,
        ValidatorTx::Register(Box::new(full.clone())),
    );
    assert_eq!(
        apply(&mut state, &ten).unwrap_err(),
        "validator_stake_below_class_floor"
    );
    let thousand = tx(
        f.owner,
        bud(1_000),
        0,
        TESTNET,
        ValidatorTx::Register(Box::new(full)),
    );
    apply(&mut state, &thousand).unwrap();
}

#[test]
fn mobile_registration_refuses_seat_fields() {
    let f = fixture(5, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);

    let mut with_seat = registration(&f, ValidatorClass::Mobile, 5);
    with_seat.seat = Some(f.seat.clone());
    let t = tx(
        f.owner,
        100,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(with_seat)),
    );
    assert_eq!(
        apply(&mut state, &t).unwrap_err(),
        "validator_mobile_refuses_seat_fields"
    );

    let mut with_relay = registration(&f, ValidatorClass::MobileOpportunistic, 5);
    with_relay.relay_offer = Some(crate::validators::RelayOffer {
        multiaddrs: vec!["/ip4/203.0.113.7/tcp/5001".into()],
        capacity_kbps: 1_000,
    });
    let t = tx(
        f.owner,
        100,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(with_relay)),
    );
    assert_eq!(
        apply(&mut state, &t).unwrap_err(),
        "validator_mobile_refuses_relay_offer"
    );

    let mut with_gateway = registration(&f, ValidatorClass::Mobile, 5);
    with_gateway.gateway_offer = Some(crate::validators::GatewayOffer {
        address: "gw.example".into(),
    });
    let t = tx(
        f.owner,
        100,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(with_gateway)),
    );
    assert_eq!(
        apply(&mut state, &t).unwrap_err(),
        "validator_mobile_refuses_gateway_offer"
    );

    // A Full registration without the seat fields is refused the other way.
    let mut no_seat = registration(&f, ValidatorClass::Full, 5);
    no_seat.seat = None;
    let t = tx(
        f.owner,
        1_000,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(no_seat)),
    );
    assert_eq!(
        apply(&mut state, &t).unwrap_err(),
        "validator_full_needs_seat_fields"
    );
    assert!(state.validator_directory.is_empty());
}

#[test]
fn change_class_activates_next_epoch() {
    let f = fixture(6, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    let reg = registration(&f, ValidatorClass::Mobile, 6);
    apply(
        &mut state,
        &tx(
            f.owner,
            1_000,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(reg)),
        ),
    )
    .unwrap();

    // Mobile to opportunistic: effective one epoch later.
    let change = tx(
        f.owner,
        0,
        1,
        DEFAULT_CHAIN_ID,
        ValidatorTx::ChangeClass {
            new_class: ValidatorClass::MobileOpportunistic,
            seat: None,
        },
    );
    apply(&mut state, &change).unwrap();
    assert_eq!(
        state.validator_directory.get(&f.owner).unwrap().class,
        ValidatorClass::Mobile,
        "the class does not change in the epoch of the request"
    );
    state.advance_epoch(1_000, DEFAULT_CHAIN_ID);
    assert_eq!(
        state.validator_directory.get(&f.owner).unwrap().class,
        ValidatorClass::MobileOpportunistic
    );

    // Opportunistic to Full: the seat fields arrive with the request, the bond
    // moves into the consensus set at the epoch boundary.
    let upgrade = tx(
        f.owner,
        0,
        2,
        DEFAULT_CHAIN_ID,
        ValidatorTx::ChangeClass {
            new_class: ValidatorClass::Full,
            seat: Some(f.seat.clone()),
        },
    );
    apply(&mut state, &upgrade).unwrap();
    assert!(!state.validators.contains_key(&f.owner));
    state.advance_epoch(2_000, DEFAULT_CHAIN_ID);
    let record = state.validator_directory.get(&f.owner).unwrap();
    assert_eq!(record.class, ValidatorClass::Full);
    assert_eq!(
        record.stake, 0,
        "the bond left the record for the consensus set"
    );
    let validator = state
        .validators
        .get(&f.owner)
        .expect("Full holds a seat now");
    assert_eq!(validator.stake, 1_000);
    assert!(validator.active);
}

#[test]
fn a_full_validator_does_not_change_class_through_the_directory() {
    let f = fixture(7, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    let reg = registration(&f, ValidatorClass::Full, 7);
    apply(
        &mut state,
        &tx(
            f.owner,
            1_000,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(reg)),
        ),
    )
    .unwrap();
    let change = tx(
        f.owner,
        0,
        1,
        DEFAULT_CHAIN_ID,
        ValidatorTx::ChangeClass {
            new_class: ValidatorClass::Mobile,
            seat: None,
        },
    );
    assert_eq!(
        apply(&mut state, &change).unwrap_err(),
        "validator_full_leaves_through_handover"
    );
}

#[test]
fn operator_key_cannot_withdraw_stake() {
    let f = fixture(8, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    let reg = registration(&f, ValidatorClass::Mobile, 8);
    apply(
        &mut state,
        &tx(
            f.owner,
            500,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(reg)),
        ),
    )
    .unwrap();
    let before = state.validator_directory.get(&f.owner).unwrap().clone();
    let owner_balance_before = state.get_balance(&f.owner);

    // Every owner-only operation names the sender as the owner. An account
    // that is not the owner, such as the operator's own account, is refused.
    let operator_account = Address::from([0xEE; 32]);
    state.add_balance(&operator_account, 100);
    for v in [
        ValidatorTx::ChangeClass {
            new_class: ValidatorClass::MobileOpportunistic,
            seat: None,
        },
        ValidatorTx::RotateOperatorKey {
            new_operator_key: operator_key(99),
        },
    ] {
        let t = tx(operator_account, 0, 0, DEFAULT_CHAIN_ID, v);
        assert_eq!(
            apply(&mut state, &t).unwrap_err(),
            "validator_not_registered"
        );
    }

    // The operator signature unlocks the quota update only, and only the
    // registered operator key's signature does.
    let wrong_key_signature = operator_sign(77, DEFAULT_CHAIN_ID, &f.owner, 2 << 30, 0);
    let forged = tx(
        operator_account,
        0,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::UpdateCustodyQuota {
            owner: f.owner,
            new_quota_bytes: 2 << 30,
            seq: 0,
            operator_signature: wrong_key_signature,
        },
    );
    assert_eq!(
        apply(&mut state, &forged).unwrap_err(),
        "validator_operator_signature_invalid"
    );

    let genuine = tx(
        operator_account,
        0,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::UpdateCustodyQuota {
            owner: f.owner,
            new_quota_bytes: 2 << 30,
            seq: 0,
            operator_signature: operator_sign(8, DEFAULT_CHAIN_ID, &f.owner, 2 << 30, 0),
        },
    );
    apply(&mut state, &genuine).unwrap();
    let after = state.validator_directory.get(&f.owner).unwrap();
    assert_eq!(after.stake, before.stake, "the operator key moved no stake");
    assert_eq!(
        after.class, before.class,
        "the operator key changed no class"
    );
    assert_eq!(
        after.owner, before.owner,
        "the operator key changed no reward address"
    );
    assert_eq!(
        state.get_balance(&f.owner),
        owner_balance_before,
        "the owner balance is untouched"
    );
}

#[test]
fn roles_5_and_9_are_reserved_and_refused() {
    use crate::registry::role::roles;
    let who = Address::from([9u8; 32]);
    let mut state = funded(&who, 10_000_000);
    let min = crate::registry::MIN_REGISTRATION_STAKE;
    for role in [roles::STORAGE_OPERATOR, roles::CONTENT_VALIDATOR] {
        assert!(matches!(
            state.bond_role(&who, role, min),
            Err(crate::registry::RegistryError::UnsupportedRole { .. })
        ));
        let t = Transaction::new_with_chain_id(
            who,
            Address::zero(),
            min,
            1,
            0,
            Vec::new(),
            DEFAULT_CHAIN_ID,
            TransactionType::RoleBond { role: role.value() },
        );
        assert_eq!(apply(&mut state, &t).unwrap_err(), "role_bond_failed");
    }
    assert_eq!(
        state.get_balance(&who),
        10_000_000,
        "a refused bond moves nothing"
    );
}

#[test]
fn rotate_operator_key_takes_effect_next_epoch() {
    let f = fixture(10, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    let reg = registration(&f, ValidatorClass::Mobile, 10);
    apply(
        &mut state,
        &tx(
            f.owner,
            500,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(reg)),
        ),
    )
    .unwrap();

    let new_key = operator_key(11);
    apply(
        &mut state,
        &tx(
            f.owner,
            0,
            1,
            DEFAULT_CHAIN_ID,
            ValidatorTx::RotateOperatorKey {
                new_operator_key: new_key.clone(),
            },
        ),
    )
    .unwrap();
    assert_eq!(
        state
            .validator_directory
            .get(&f.owner)
            .unwrap()
            .operator_key,
        operator_key(10),
        "the old key stays in force until the next epoch"
    );
    state.advance_epoch(1_000, DEFAULT_CHAIN_ID);
    assert_eq!(
        state
            .validator_directory
            .get(&f.owner)
            .unwrap()
            .operator_key,
        new_key
    );

    let carrier = Address::from([0xCC; 32]);
    state.add_balance(&carrier, 100);
    let quota_tx = |signer: u8, nonce| {
        tx(
            carrier,
            0,
            nonce,
            DEFAULT_CHAIN_ID,
            ValidatorTx::UpdateCustodyQuota {
                owner: f.owner,
                new_quota_bytes: 2 << 30,
                seq: 0,
                operator_signature: operator_sign(signer, DEFAULT_CHAIN_ID, &f.owner, 2 << 30, 0),
            },
        )
    };
    assert_eq!(
        apply(&mut state, &quota_tx(10, 0)).unwrap_err(),
        "validator_operator_signature_invalid",
        "the rotated-out key no longer signs"
    );
    apply(&mut state, &quota_tx(11, 0)).unwrap();
}

#[test]
fn quota_increase_activates_next_epoch() {
    let f = fixture(12, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    let reg = registration(&f, ValidatorClass::Mobile, 12);
    apply(
        &mut state,
        &tx(
            f.owner,
            500,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(reg)),
        ),
    )
    .unwrap();
    let old = state
        .validator_directory
        .get(&f.owner)
        .unwrap()
        .custody_quota_bytes;

    let raise = |quota: u64, seq: u64, nonce: u64| {
        tx(
            f.owner,
            0,
            nonce,
            DEFAULT_CHAIN_ID,
            ValidatorTx::UpdateCustodyQuota {
                owner: f.owner,
                new_quota_bytes: quota,
                seq,
                operator_signature: operator_sign(12, DEFAULT_CHAIN_ID, &f.owner, quota, seq),
            },
        )
    };
    apply(&mut state, &raise(old * 2, 0, 1)).unwrap();
    assert_eq!(
        state
            .validator_directory
            .get(&f.owner)
            .unwrap()
            .custody_quota_bytes,
        old,
        "the quota does not change in the epoch of the request"
    );
    state.advance_epoch(1_000, DEFAULT_CHAIN_ID);
    assert_eq!(
        state
            .validator_directory
            .get(&f.owner)
            .unwrap()
            .custody_quota_bytes,
        old * 2
    );

    // The same signed update cannot be replayed, and a decrease is not an
    // increase: lowering the quota goes through ReleaseShares.
    assert_eq!(
        apply(&mut state, &raise(old * 2, 0, 2)).unwrap_err(),
        "validator_quota_sequence"
    );
    assert_eq!(
        apply(&mut state, &raise(old, 1, 2)).unwrap_err(),
        "validator_quota_decrease_via_release"
    );
}

#[test]
fn the_directory_is_part_of_the_state_root_and_the_snapshot() {
    let f = fixture(13, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    let before = state.calculate_state_root();
    let reg = registration(&f, ValidatorClass::Mobile, 13);
    apply(
        &mut state,
        &tx(
            f.owner,
            500,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(reg)),
        ),
    )
    .unwrap();
    assert_ne!(before, state.calculate_state_root());

    let snapshot = crate::chain::snapshot::StateSnapshotV2::from_state(
        &state,
        crate::chain::snapshot::StateSnapshotV2Params {
            height: 1,
            block_hash: "block-digest".into(),
            genesis_hash: "genesis-digest".into(),
            chain_id: DEFAULT_CHAIN_ID,
            finalized_height: 0,
            finalized_hash: "fin-digest".into(),
            finality_certificates: vec![],
        },
    );
    assert!(snapshot.verify(), "the digest covers the directory");
    let restored = AccountState::from_snapshot_v2(&snapshot);
    assert_eq!(
        restored.validator_directory, state.validator_directory,
        "a restore keeps the directory"
    );
}

#[test]
fn the_validator_transaction_survives_the_wire() {
    let f = fixture(14, DEFAULT_CHAIN_ID);
    let reg = registration(&f, ValidatorClass::Full, 14);
    let original = tx(
        f.owner,
        1_000,
        0,
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(reg)),
    );
    let proto = crate::network::proto_conversions::pb::ProtoTransaction::from(&original);
    let back = Transaction::try_from(proto).expect("the payload decodes");
    assert_eq!(back.tx_type, original.tx_type);
}

#[test]
fn the_directory_answers_get_validator_list_relays_and_list_gateways() {
    use crate::validators::{DirectoryQuery, GatewayOffer, RelayOffer};
    let f = fixture(15, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    let mut reg = registration(&f, ValidatorClass::Full, 15);
    reg.relay_offer = Some(RelayOffer {
        multiaddrs: vec!["/ip4/203.0.113.7/tcp/5001".into()],
        capacity_kbps: 5_000,
    });
    reg.gateway_offer = Some(GatewayOffer {
        address: "https://gw.example".into(),
    });
    apply(
        &mut state,
        &tx(
            f.owner,
            1_000,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(reg)),
        ),
    )
    .unwrap();

    let directory = &state.validator_directory;
    let one = directory.query_json(DirectoryQuery::One(f.owner));
    assert_eq!(one["class"], "full");
    assert_eq!(one["relayOffer"]["capacityKbps"], 5_000);
    assert_eq!(directory.query_json(DirectoryQuery::Relays)["count"], 1);
    assert_eq!(directory.query_json(DirectoryQuery::Gateways)["count"], 1);
    assert!(directory
        .query_json(DirectoryQuery::One(Address::from([0x55; 32])))
        .is_null());
}

/// A signed custody acknowledgement: the duty batch item of section 7.3.
fn duty_ack(keypair: &KeyPair, nonce: u64, object: [u8; 32]) -> Transaction {
    let from = Address::from(keypair.public_key_bytes());
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        0,
        nonce,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::StorageV3(Box::new(StorageTxV3::CustodyAck { object })),
    );
    tx.hash = tx.calculate_hash();
    tx.sign(keypair);
    tx
}

/// Section 7.12: one batch per validator per window, and the lane's byte
/// ceiling.
///
/// Four properties, and the third is the one that makes the limit usable: a
/// replacement of the pending batch is admitted, because a phone that collects
/// one more audit before the window closes must be able to say so. Refusing it
/// would leave the validator with either a stale batch on chain or no batch at
/// all until the next window.
#[test]
fn mobile_duty_tx_lane_is_rate_limited() {
    let keypair = KeyPair::from_seed(&[21u8; 32]).unwrap();
    let now: u128 = 4_200_005;
    let window = window_at(now);

    let mut pool = Mempool::new(MempoolConfig {
        // A fee floor the batch must not pay: the lane is free (section 11.6)
        // for registered active validators.
        min_fee: 5,
        duty_block_bytes: 64 * 1024,
        ..MempoolConfig::default()
    });

    // An unregistered account cannot bypass `min_fee` or occupy the free duty
    // lane merely by sending a duty-shaped transaction.
    let first = duty_ack(&keypair, 0, [1u8; 32]);
    assert_eq!(first.fee, 0);
    assert!(is_duty(&first));
    assert_eq!(
        pool.admit_at(first.clone(), now),
        Err(MempoolError::FeeTooLow)
    );

    // Once the validator is synced into the active set, its duty batch enters
    // the free lane.
    pool.sync_duty_validators([first.from]);
    assert!(pool.admit_at(first, now).is_ok());

    // A second batch in the same window is refused, and the refusal says which
    // window and which batch is in the way.
    let second = duty_ack(&keypair, 1, [2u8; 32]);
    let refused = pool.admit_at(second, now).unwrap_err();
    assert_eq!(
        refused,
        MempoolError::DutyLaneRefused(DutyRefusal::SecondBatchInWindow {
            window,
            open_nonce: 0,
        })
    );

    // A replacement of the pending batch is admitted: the rule is one batch
    // per window, not one submission.
    let replacement = duty_ack(&keypair, 0, [3u8; 32]);
    assert!(pool.admit_at(replacement, now).is_ok());
    assert_eq!(pool.len(), 1);

    // The next window has its own slot, so the validator keeps sending.
    let next_window = now + 600_000;
    let later = duty_ack(&keypair, 1, [4u8; 32]);
    assert!(pool.admit_at(later, next_window).is_ok());
    assert_eq!(pool.len(), 2);

    // The lane's pool ceiling is four blocks of its share. One byte of block
    // budget is four bytes of ceiling, and no batch is that small, so the batch
    // is refused rather than admitted and dropped later.
    let mut tiny = Mempool::new(MempoolConfig {
        min_fee: 1,
        duty_block_bytes: 1,
        ..MempoolConfig::default()
    });
    let tiny_tx = duty_ack(&keypair, 0, [5u8; 32]);
    tiny.sync_duty_validators([tiny_tx.from]);
    let refused = tiny.admit_at(tiny_tx, now);
    assert!(matches!(
        refused,
        Err(MempoolError::DutyLaneRefused(
            DutyRefusal::LaneBytesFull { .. }
        ))
    ));
    assert_eq!(tiny.len(), 0);
}

/// Section 7.3, item 6: the duty lane fills at most 20 percent of a block, and
/// the batch past the share waits rather than disappearing.
#[test]
fn duty_lane_budget_is_twenty_percent() {
    assert_eq!(
        block_share_bytes(crate::consensus::MAX_BLOCK_SIZE),
        crate::consensus::MAX_BLOCK_SIZE / 5
    );
    assert_eq!(DEFAULT_DUTY_BLOCK_BYTES, 200_000);

    let now: u128 = 4_200_005;
    let batches: Vec<Transaction> = (1u8..=5)
        .map(|n| {
            let keypair = KeyPair::from_seed(&[n; 32]).unwrap();
            duty_ack(&keypair, 0, [n; 32])
        })
        .collect();
    let per_batch = batches.iter().map(block_bytes).max().unwrap_or(0);
    assert!(per_batch > 0);

    // A block of fifteen batches carries three of them in the lane's fifth.
    let cap = per_batch.saturating_mul(3);
    assert_eq!(block_share_bytes(per_batch.saturating_mul(15)), cap);

    let mut pool = Mempool::new(MempoolConfig {
        min_fee: 1,
        duty_block_bytes: cap,
        ..MempoolConfig::default()
    });
    pool.sync_duty_validators(batches.iter().map(|b| b.from));
    for batch in batches {
        assert!(pool.admit_at(batch, now).is_ok());
    }
    assert_eq!(pool.len(), 5);

    let picked = pool.get_sorted_transactions(64);
    let mut carried = 0usize;
    let mut carried_bytes = 0usize;
    for tx in &picked {
        if is_duty(tx) {
            carried += 1;
            carried_bytes = carried_bytes.saturating_add(block_bytes(tx));
        }
    }
    assert!(
        carried_bytes <= cap,
        "the lane took {carried_bytes} of {cap}"
    );
    assert!(carried > 0);
    assert!(
        carried < 5,
        "the share, not the fee order, is what stops the lane"
    );
    assert_eq!(
        pool.len(),
        5,
        "a batch past the share waits for the next block, it is not dropped"
    );

    // The share is a block rule, not a pool rule: the snapshot the reorg path
    // rebuilds the pool from carries every batch, because a transaction left
    // out of it is a transaction the node forgets.
    assert_eq!(pool.all_pending_transactions(pool.len()).len(), 5);
}

/// Register `keypair`'s account as a validator of `class` on `state`, bonded
/// at the devnet floor, and return its address.
fn register_class(
    state: &mut AccountState,
    keypair: &KeyPair,
    class: ValidatorClass,
    n: u8,
) -> Address {
    let owner = Address::from(keypair.public_key_bytes());
    state.add_balance(&owner, 10_000);
    let f = fixture_for(owner, DEFAULT_CHAIN_ID);
    let bond = if class.holds_seat() { 1_000 } else { 100 };
    let register = tx(
        owner,
        bond,
        state.get_nonce(&owner),
        DEFAULT_CHAIN_ID,
        ValidatorTx::Register(Box::new(registration(&f, class, n))),
    );
    apply(state, &register).unwrap();
    owner
}

/// The free lane's signer set is the validators that still have a bond and
/// may still do duty. A directory record outlives a penalty, so the record
/// alone does not put its owner in the lane.
#[test]
fn duty_lane_signers_exclude_slashed_jailed_and_unbonded_validators() {
    let full_key = KeyPair::from_seed(&[41u8; 32]).unwrap();
    let phone_key = KeyPair::from_seed(&[42u8; 32]).unwrap();
    let mut state = AccountState::new();
    let full = register_class(&mut state, &full_key, ValidatorClass::Full, 41);
    let phone = register_class(&mut state, &phone_key, ValidatorClass::Mobile, 42);
    assert!(state.validator_directory.get(&full).is_some());
    assert!(state.validator_directory.get(&phone).is_some());
    assert_eq!(
        state.duty_lane_signers(),
        std::collections::BTreeSet::from([full, phone]),
        "a bonded Full validator and a bonded phone both have the lane"
    );

    // Each penalty on the consensus entry takes the Full validator out, and
    // the directory record it still has does not put it back.
    for penalty in 0..3u8 {
        let mut penalised = state.clone();
        let seat = penalised.validators.get_mut(&full).unwrap();
        match penalty {
            0 => seat.jailed = true,
            1 => seat.slashed = true,
            _ => seat.active = false,
        }
        assert!(penalised.validator_directory.get(&full).is_some());
        assert_eq!(
            penalised.duty_lane_signers(),
            std::collections::BTreeSet::from([phone])
        );
    }

    // A seat class with no consensus entry at all has no seat to do duty from.
    let mut seatless = state.clone();
    seatless.validators.remove(&full);
    assert_eq!(
        seatless.duty_lane_signers(),
        std::collections::BTreeSet::from([phone])
    );

    // A phone whose bond is gone keeps its record and loses the lane.
    let mut unbonded = state.clone();
    unbonded
        .validator_directory
        .finish_class_change(&phone, ValidatorClass::Mobile, 100);
    assert_eq!(unbonded.validator_directory.get(&phone).unwrap().stake, 0);
    assert_eq!(
        unbonded.duty_lane_signers(),
        std::collections::BTreeSet::from([full])
    );
}

/// The same rule through the chain's own admission door, which installs the
/// signer set on every submission: a bonded phone's free batch is admitted,
/// and the batch of a phone that has no bond left is refused for its fee.
#[test]
fn chain_admission_door_gives_the_free_duty_lane_only_to_bonded_validators() {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;

    let bonded_key = KeyPair::from_seed(&[43u8; 32]).unwrap();
    let unbonded_key = KeyPair::from_seed(&[44u8; 32]).unwrap();
    let jailed_key = KeyPair::from_seed(&[45u8; 32]).unwrap();
    let mut chain = Blockchain::new(
        std::sync::Arc::new(PoWEngine::new(0)),
        None,
        DEFAULT_CHAIN_ID,
        None,
    );
    let bonded = register_class(&mut chain.state, &bonded_key, ValidatorClass::Mobile, 43);
    let unbonded = register_class(&mut chain.state, &unbonded_key, ValidatorClass::Mobile, 44);
    let jailed = register_class(&mut chain.state, &jailed_key, ValidatorClass::Full, 45);
    chain
        .state
        .validator_directory
        .finish_class_change(&unbonded, ValidatorClass::Mobile, 100);
    chain.state.validators.get_mut(&jailed).unwrap().jailed = true;

    // Every transaction pays the consensus floor. The lane lifts the node's
    // own pool floor, which here sits above it.
    let floor = chain.state.base_fee;
    chain.mempool.set_min_fee(floor.saturating_add(5));
    let batch_of = |key: &KeyPair, nonce: u64| {
        let from = Address::from(key.public_key_bytes());
        let mut tx = Transaction::new_with_chain_id(
            from,
            Address::zero(),
            0,
            floor,
            nonce,
            Vec::new(),
            DEFAULT_CHAIN_ID,
            TransactionType::StorageV3(Box::new(StorageTxV3::CustodyAck { object: [9u8; 32] })),
        );
        tx.hash = tx.calculate_hash();
        tx.sign(key);
        tx
    };

    for (key, owner) in [(&unbonded_key, unbonded), (&jailed_key, jailed)] {
        let batch = batch_of(key, chain.state.get_nonce(&owner));
        let refusal = chain
            .add_transaction(batch)
            .expect_err("no bond behind the batch, no lane");
        assert!(refusal.contains("FeeTooLow"), "{refusal}");
    }
    assert_eq!(chain.mempool.len(), 0);

    let batch = batch_of(&bonded_key, chain.state.get_nonce(&bonded));
    chain
        .add_transaction(batch)
        .expect("a bonded phone's duty batch is not held to the pool floor");
    assert_eq!(chain.mempool.len(), 1);
}

/// The lane's pool ceiling is one number for every validator, so it must not
/// belong to whoever reached it first. A validator that parks batches fills
/// the lane, and the next validator's batch still gets in: the room comes from
/// the signer holding the most. A signer never displaces one that holds no
/// more than it would, and a refusal removes nothing.
#[test]
fn duty_lane_ceiling_is_shared_and_not_first_come() {
    let hog = KeyPair::from_seed(&[31u8; 32]).unwrap();
    let other = KeyPair::from_seed(&[32u8; 32]).unwrap();
    let newcomer = KeyPair::from_seed(&[33u8; 32]).unwrap();
    let now: u128 = 4_200_005;
    let window_ms: u128 = 600_000;

    let probes = [
        duty_ack(&hog, 0, [1u8; 32]),
        duty_ack(&hog, 1, [2u8; 32]),
        duty_ack(&hog, 2, [3u8; 32]),
        duty_ack(&hog, 3, [4u8; 32]),
        duty_ack(&other, 0, [5u8; 32]),
        duty_ack(&newcomer, 0, [6u8; 32]),
    ];
    // The batches submitted further down. A batch's size depends on its
    // signature and its fields, so the block share is taken from all of them:
    // none is then refused for its own size, and four of any of them fill the
    // lane.
    let fifth = duty_ack(&hog, 4, [7u8; 32]);
    let other_second = duty_ack(&other, 1, [8u8; 32]);
    let greedy = [
        duty_ack(&other, 2, [9u8; 32]),
        duty_ack(&hog, 2, [10u8; 32]),
    ];
    let largest = probes
        .iter()
        .chain([&fifth, &other_second])
        .chain(greedy.iter())
        .map(block_bytes)
        .max()
        .unwrap();
    let hog_address = probes[0].from;
    let other_address = probes[4].from;
    let newcomer_address = probes[5].from;

    // The lane holds four blocks of its share, so four batches fill it.
    let mut pool = Mempool::new(MempoolConfig {
        min_fee: 5,
        duty_block_bytes: largest,
        ..MempoolConfig::default()
    });
    pool.sync_duty_validators([hog_address, other_address, newcomer_address]);

    // One validator, one batch per window, four windows: the lane is full of
    // batches that all belong to it.
    let mut at = now;
    for batch in &probes[..4] {
        pool.admit_at(batch.clone(), at)
            .expect("the hog's batch fits");
        at += window_ms;
    }
    assert_eq!(pool.len(), 4);
    let late = now + window_ms * 4;

    // It cannot take more than the lane: nobody else holds anything to give.
    assert!(matches!(
        pool.admit_at(fifth, late),
        Err(MempoolError::DutyLaneRefused(
            DutyRefusal::LaneBytesFull { .. }
        ))
    ));
    assert_eq!(pool.len(), 4);

    // Another validator's batch is admitted, and the hog gives up its last
    // batch for it. The batches queued before that one are untouched.
    pool.admit_at(probes[4].clone(), late)
        .expect("a full lane still admits a signer that holds less of it");
    assert_eq!(pool.len(), 4);
    assert!(pool.get(&probes[4].hash).is_some());
    assert!(pool.get(&probes[3].hash).is_none());
    for kept in &probes[..3] {
        assert!(pool.get(&kept.hash).is_some());
    }

    // A second batch of that validator, in the next window, takes one more.
    pool.admit_at(other_second.clone(), late + window_ms)
        .expect("two batches against the hog's three");
    assert!(pool.get(&probes[2].hash).is_none());
    assert_eq!(pool.len(), 4);

    // Now both hold two. Neither can grow at the other's expense: it would
    // hold three against the other's two, and the refusal removes nothing.
    let before: Vec<String> = {
        let mut hashes: Vec<String> = pool
            .all_pending_transactions(pool.len())
            .into_iter()
            .map(|tx| tx.hash)
            .collect();
        hashes.sort();
        hashes
    };
    for batch in greedy {
        let refusal = pool.admit_at(batch, late + window_ms * 2);
        assert!(
            matches!(
                refusal,
                Err(MempoolError::DutyLaneRefused(
                    DutyRefusal::LaneBytesFull { .. }
                ))
            ),
            "{refusal:?}"
        );
    }
    let after: Vec<String> = {
        let mut hashes: Vec<String> = pool
            .all_pending_transactions(pool.len())
            .into_iter()
            .map(|tx| tx.hash)
            .collect();
        hashes.sort();
        hashes
    };
    assert_eq!(before, after, "a refused batch evicts nothing");

    // A third validator has no batch in the lane yet, so it is lighter than
    // both and is admitted. Whoever gives way loses its last batch, never its first.
    pool.admit_at(probes[5].clone(), late + window_ms * 2)
        .expect("a newcomer is lighter than every signer in the lane");
    assert_eq!(pool.len(), 4);
    assert!(pool.get(&probes[5].hash).is_some());
    assert!(pool.get(&probes[0].hash).is_some());
    assert!(pool.get(&probes[4].hash).is_some());
    let hog_second = pool.get(&probes[1].hash).is_some();
    let other_second_kept = pool.get(&other_second.hash).is_some();
    assert!(
        hog_second != other_second_kept,
        "exactly one of the two heavier signers gave up its last batch"
    );
}

/// A batch larger than the lane's share of one block can never be carried by
/// a block, so it is refused at the door instead of holding lane bytes until
/// it expires.
#[test]
fn duty_batch_larger_than_the_block_share_is_refused() {
    let keypair = KeyPair::from_seed(&[34u8; 32]).unwrap();
    let now: u128 = 4_200_005;
    let batch = duty_ack(&keypair, 0, [1u8; 32]);
    let batch_bytes = block_bytes(&batch);

    let mut pool = Mempool::new(MempoolConfig {
        min_fee: 5,
        duty_block_bytes: batch_bytes - 1,
        ..MempoolConfig::default()
    });
    pool.sync_duty_validators([batch.from]);
    assert_eq!(
        pool.admit_at(batch.clone(), now),
        Err(MempoolError::DutyLaneRefused(
            DutyRefusal::BatchExceedsBlockShare {
                batch_bytes,
                share: batch_bytes - 1,
            }
        ))
    );
    assert_eq!(pool.len(), 0);

    // At exactly the share it is a batch a block can carry.
    let mut exact = Mempool::new(MempoolConfig {
        min_fee: 5,
        duty_block_bytes: batch_bytes,
        ..MempoolConfig::default()
    });
    exact.sync_duty_validators([batch.from]);
    exact.admit_at(batch, now).expect("a batch at the share");
    assert_eq!(exact.get_sorted_transactions(8).len(), 1);
}

#[test]
fn resume_validator_is_suspension_only_and_activates_one_epoch_later() {
    let f = fixture(0x70, DEFAULT_CHAIN_ID);
    let mut state = funded(&f.owner, 10_000);
    apply(
        &mut state,
        &tx(
            f.owner,
            1_000,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(registration(&f, ValidatorClass::Full, 0x70))),
        ),
    )
    .unwrap();

    let resume = || tx(f.owner, 0, 1, DEFAULT_CHAIN_ID, ValidatorTx::Resume);
    assert_eq!(
        apply(&mut state, &resume()).unwrap_err(),
        "validator_not_suspended",
        "an active validator cannot manufacture a resume request"
    );
    assert_eq!(state.get_nonce(&f.owner), 1, "a refusal spends no nonce");

    let mut params = *state.registry.params();
    params.liveness_max_missed_epochs = 1;
    assert_eq!(
        state
            .liveness
            .record_epoch(1, &[f.owner], |_| false, &params),
        vec![f.owner]
    );
    // Epoch-close applies the tracker's suspension to validator duty.
    state.validators.get_mut(&f.owner).unwrap().active = false;
    state.epoch_index = 1;
    let stake_before = state.validators.get(&f.owner).unwrap().stake;

    apply(&mut state, &resume()).expect("the suspended owner requests resume");
    assert!(state.liveness.is_suspended(&f.owner));
    assert!(!state.validators.get(&f.owner).unwrap().active);

    state.advance_epoch(2, DEFAULT_CHAIN_ID);
    assert!(!state.liveness.is_suspended(&f.owner));
    let validator = state.validators.get(&f.owner).unwrap();
    assert!(validator.active && !validator.slashed && !validator.jailed);
    assert_eq!(
        validator.stake, stake_before,
        "absence and resume move no stake"
    );
}
