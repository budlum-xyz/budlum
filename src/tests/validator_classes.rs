//! Validator classes and the single registration door, and the mobile duty lane.
//!
//! The duty lane (`src/mempool/duty_lane.rs`) carries `CustodyAck` and
//! `CustodyProofBatch`: free (Section 7.3 item 6), one batch per validator per
//! window, and never more than 20 percent of a block. `PresenceSignal` is the
//! third family the directive names and has no transaction variant yet, so it is
//! named in `DutyKind` and not carried; the module doc there says why.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::crypto::primitives::ValidatorKeys;
use crate::crypto::scheme::SchemeId;
use crate::execution::executor::Executor;
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
    let owner = Address::from([owner_byte; 32]);
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

// ---------------------------------------------------------------------------
// The mobile duty lane, Section 7.3 item 6.
// ---------------------------------------------------------------------------

/// A signed `CustodyAck` for `seed`, paying `fee`.
///
/// Duty work is free on the paying path, so the refusal this test looks for has
/// to come from the lane and not from the fee floor: the transaction below is
/// built with fee zero on purpose, which the floor would refuse if the lane did
/// not offer it.
fn custody_ack(seed: u8, nonce: u64, fee: u64) -> Transaction {
    use crate::storage::bud3::tx::StorageTxV3;
    let keypair = crate::crypto::primitives::KeyPair::from_seed(&[seed; 32]).unwrap();
    let from = Address::from(keypair.public_key_bytes());
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        fee,
        nonce,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::StorageV3(Box::new(StorageTxV3::CustodyAck { object: [seed; 32] })),
    );
    tx.hash = tx.calculate_hash();
    tx.sign(&keypair);
    tx
}

fn lobby() -> crate::mempool::pool::Mempool {
    crate::mempool::pool::Mempool::new(crate::mempool::pool::MempoolConfig::default())
}

#[test]
fn mobile_duty_tx_lane_is_rate_limited() {
    use crate::mempool::pool::MempoolError;

    let mut pool = lobby();
    let window = 7;
    let first = custody_ack(11, 0, 0);
    let sender = first.from;

    // Free: the pool's fee floor is 1 by default and this transaction pays 0.
    pool.add_transaction_in_window(first, window)
        .expect("a duty ack is free and the lane has not been used this epoch");

    // A second batch from the same validator in the same epoch is the thing the
    // rate limit exists to refuse.
    let second = custody_ack(11, 1, 0);
    assert_eq!(
        pool.add_transaction_in_window(second.clone(), window),
        Err(MempoolError::DutyWindowExhausted),
        "one batch per validator per window"
    );

    // The next epoch starts empty, so the validator is not locked out.
    let mut third = custody_ack(11, 1, 0);
    third.hash = third.calculate_hash();
    pool.add_transaction_in_window(third, window + 1)
        .expect("a new window grants a new batch");

    // A second validator is unaffected by the first one's use of its own slot.
    pool.add_transaction_in_window(custody_ack(12, 0, 0), window)
        .expect("the limit is per validator, not per lane");

    // A paying transaction is never refused by the duty window: the epoch is
    // spent for `sender`, and an ordinary transfer still gets in.
    let keypair = crate::crypto::primitives::KeyPair::from_seed(&[13; 32]).unwrap();
    let from = Address::from(keypair.public_key_bytes());
    let mut transfer = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        100,
        5,
        0,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    transfer.hash = transfer.calculate_hash();
    transfer.sign(&keypair);
    pool.add_transaction_in_window(transfer, window)
        .expect("the duty lane does not gate paying traffic");
}

#[test]
fn duty_lane_budget_is_twenty_percent() {
    use crate::mempool::duty_lane::{
        DutyLane, DUTY_LANE_SHARE_PERCENT, DUTY_SUBMISSIONS_PER_WINDOW,
    };
    use crate::mempool::pool::MempoolError;

    // The constant the directive fixes (Section 7.3 item 6, TESTNET-DEFAULT).
    assert_eq!(DUTY_LANE_SHARE_PERCENT, 20);
    assert_eq!(DUTY_SUBMISSIONS_PER_WINDOW, 1);

    // A block of 1 000 000 bytes gives the corridor 200 000, rounded down.
    assert_eq!(DutyLane::new(1_000_000).corridor_bytes(), 200_000);
    assert_eq!(DutyLane::new(7).corridor_bytes(), 1, "rounded down, never up");

    // The pool builds its corridor from the consensus block limit.
    let pool = lobby();
    let expected =
        crate::consensus::MAX_BLOCK_SIZE * usize::from(DUTY_LANE_SHARE_PERCENT) / 100;
    assert_eq!(
        pool.duty_corridor_bytes(),
        expected,
        "the pool's corridor is a fifth of MAX_BLOCK_SIZE"
    );

    // The corridor's ceiling is measured against a batch of known size, so the
    // arithmetic is exact rather than dependent on how large an ML-DSA-87
    // signature happens to be today: a 1 000 byte block gives 200, and 150 + 60
    // is refused while 150 + 50 is admitted.
    let mut lane = DutyLane::new(1_000);
    lane.record(&Address::from([1u8; 32]), 1, 150);
    assert_eq!(
        lane.admit(&Address::from([2u8; 32]), 1, 60),
        Err(crate::mempool::duty_lane::DutyRefusal::CorridorFull),
        "150 + 60 is past a 200 byte corridor"
    );
    assert_eq!(
        lane.admit(&Address::from([2u8; 32]), 1, 50),
        Ok(()),
        "150 + 50 is exactly the corridor"
    );

    // End to end through the pool: every duty transaction it admits is charged
    // to the corridor, and the corridor is never exceeded.
    let mut pool = lobby();
    let corridor = pool.duty_corridor_bytes();
    let mut admitted = 0usize;
    for seed in 20u8..24 {
        if pool.add_transaction_in_window(custody_ack(seed, 0, 0), 1).is_ok() {
            admitted += 1;
        }
    }
    assert!(admitted >= 1, "at least one duty transaction fits the corridor");
    assert!(
        pool.duty_bytes_this_block() <= corridor,
        "the corridor admitted {} bytes against a {corridor} byte ceiling",
        pool.duty_bytes_this_block()
    );

    // A new block resets the corridor; the window stays spent, which is the
    // difference between "a new block" and "a new epoch".
    let before = pool.duty_bytes_this_block();
    assert!(before > 0, "the previous block had used some of the corridor");
    pool.begin_block(1);
    assert_eq!(pool.duty_bytes_this_block(), 0, "a new block, a new corridor");
    assert_eq!(
        pool.add_transaction_in_window(custody_ack(20, 1, 0), 1),
        Err(MempoolError::DutyWindowExhausted),
        "a new block is not a new window"
    );
}
