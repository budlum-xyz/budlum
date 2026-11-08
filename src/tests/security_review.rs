//! Independent execution, mobile/validator authority, and client review: execution, mobile/validator authority,
//! BUD supply conservation, and adversarial regression locks.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::crypto::primitives::ValidatorKeys;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::execution::executor::Executor;
use crate::validators::{
    quota_update_message, LeaderCommitment, SeatFields, ValidatorClass, ValidatorRegistration,
    ValidatorTx, MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES,
};

const TESTNET: u64 = 45261;

fn op_seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn op_pubkey(n: u8) -> Vec<u8> {
    crate::crypto::pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &op_seed(n)).unwrap()
}

fn op_sign(n: u8, chain_id: u64, owner: &Address, quota: u64, seq: u64) -> Vec<u8> {
    crate::crypto::pq::ml_dsa_sign(
        SchemeId::ML_DSA_65,
        &op_seed(n),
        &quota_update_message(chain_id, owner, quota, seq),
        crate::crypto::ctx::VALIDATOR_V1,
        &[0u8; 32],
    )
    .unwrap()
}

struct ValFixture {
    owner: Address,
    bls_key: Vec<u8>,
    bls_pop: Vec<u8>,
    seat: SeatFields,
}

fn make_fixture(owner_byte: u8, chain_id: u64) -> ValFixture {
    let owner = Address::from([owner_byte; 32]);
    let keys = ValidatorKeys::generate().unwrap();
    let bls = keys.bls_key.as_ref().unwrap();
    ValFixture {
        owner,
        bls_key: bls.public_key.clone(),
        bls_pop: bls.generate_pop(chain_id, &owner),
        seat: SeatFields {
            vrf_key: keys.vrf_key.public.to_bytes().to_vec(),
            pq_vote_key: keys.pq_key.as_ref().unwrap().public_key_bytes().to_vec(),
            leader_commitment: LeaderCommitment {
                commitment: [9u8; 32],
                length: 512,
            },
        },
    }
}

fn make_reg(f: &ValFixture, class: ValidatorClass, op_idx: u8) -> ValidatorRegistration {
    ValidatorRegistration {
        owner: f.owner,
        class,
        operator_key: op_pubkey(op_idx),
        bls_key: f.bls_key.clone(),
        bls_pop: f.bls_pop.clone(),
        seat: class.holds_seat().then(|| f.seat.clone()),
        custody_quota_bytes: 2 << 30, // 2 GiB
        relay_offer: None,
        gateway_offer: None,
        peer_id: [op_idx; 32],
    }
}

fn vtx(from: Address, amount: u64, nonce: u64, chain_id: u64, inner: ValidatorTx) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        1,
        nonce,
        Vec::new(),
        chain_id,
        TransactionType::Validator(inner),
    )
}

#[test]
fn opportunistic_quota_cap_enforced_across_pending_class_and_quota() {
    let f = make_fixture(0x21, TESTNET);
    let mut state_a = AccountState::new();
    state_a.add_balance(&f.owner, 1_000_000);

    // Register as Mobile with 2 GiB quota.
    let reg = vtx(
        f.owner,
        1_000,
        0,
        TESTNET,
        ValidatorTx::Register(Box::new(make_reg(&f, ValidatorClass::Mobile, 1))),
    );
    Executor::apply_transaction_checked(&mut state_a, &reg).unwrap();

    // Order A: queue ChangeClass -> MobileOpportunistic, then try raising quota to 16 GiB (> 8 GiB cap).
    let to_opp = vtx(
        f.owner,
        0,
        1,
        TESTNET,
        ValidatorTx::ChangeClass {
            new_class: ValidatorClass::MobileOpportunistic,
            seat: None,
        },
    );
    Executor::apply_transaction_checked(&mut state_a, &to_opp).unwrap();

    let over_cap = MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES + 1;
    let raise_over = vtx(
        f.owner,
        0,
        2,
        TESTNET,
        ValidatorTx::UpdateCustodyQuota {
            owner: f.owner,
            new_quota_bytes: over_cap,
            seq: 0,
            operator_signature: op_sign(1, TESTNET, &f.owner, over_cap, 0),
        },
    );
    let err_a = Executor::apply_transaction_checked(&mut state_a, &raise_over).unwrap_err();
    assert_eq!(err_a.code(), "validator_quota_above_class_cap");

    // Order B: queue UpdateCustodyQuota to 16 GiB while Mobile, then try ChangeClass -> MobileOpportunistic.
    let mut state_b = AccountState::new();
    state_b.add_balance(&f.owner, 1_000_000);
    Executor::apply_transaction_checked(&mut state_b, &reg).unwrap();
    let raise_first = vtx(
        f.owner,
        0,
        1,
        TESTNET,
        ValidatorTx::UpdateCustodyQuota {
            owner: f.owner,
            new_quota_bytes: over_cap,
            seq: 0,
            operator_signature: op_sign(1, TESTNET, &f.owner, over_cap, 0),
        },
    );
    Executor::apply_transaction_checked(&mut state_b, &raise_first).unwrap();

    let to_opp_second = vtx(
        f.owner,
        0,
        2,
        TESTNET,
        ValidatorTx::ChangeClass {
            new_class: ValidatorClass::MobileOpportunistic,
            seat: None,
        },
    );
    let err_b = Executor::apply_transaction_checked(&mut state_b, &to_opp_second).unwrap_err();
    assert_eq!(err_b.code(), "validator_quota_above_class_cap");
}

#[test]
fn pending_operator_key_cannot_be_claimed_twice() {
    let f1 = make_fixture(0x31, TESTNET);
    let f2 = make_fixture(0x32, TESTNET);
    let f3 = make_fixture(0x33, TESTNET);
    let mut state = AccountState::new();
    state.add_balance(&f1.owner, 1_000_000);
    state.add_balance(&f2.owner, 1_000_000);
    state.add_balance(&f3.owner, 1_000_000);

    Executor::apply_transaction_checked(
        &mut state,
        &vtx(
            f1.owner,
            1_000,
            0,
            TESTNET,
            ValidatorTx::Register(Box::new(make_reg(&f1, ValidatorClass::Mobile, 10))),
        ),
    )
    .unwrap();
    Executor::apply_transaction_checked(
        &mut state,
        &vtx(
            f2.owner,
            1_000,
            0,
            TESTNET,
            ValidatorTx::Register(Box::new(make_reg(&f2, ValidatorClass::Mobile, 11))),
        ),
    )
    .unwrap();

    // f1 queues rotation to operator key #99.
    let shared_target_key = op_pubkey(99);
    Executor::apply_transaction_checked(
        &mut state,
        &vtx(
            f1.owner,
            0,
            1,
            TESTNET,
            ValidatorTx::RotateOperatorKey {
                new_operator_key: shared_target_key.clone(),
            },
        ),
    )
    .unwrap();

    // f2 cannot rotate to the same pending operator key #99.
    let err_rot = Executor::apply_transaction_checked(
        &mut state,
        &vtx(
            f2.owner,
            0,
            1,
            TESTNET,
            ValidatorTx::RotateOperatorKey {
                new_operator_key: shared_target_key,
            },
        ),
    )
    .unwrap_err();
    assert_eq!(err_rot.code(), "validator_peer_or_operator_key_in_use");

    // f3 cannot register with the pending operator key #99 either.
    let mut reg3 = make_reg(&f3, ValidatorClass::Mobile, 99);
    reg3.peer_id = [0xEE; 32];
    let err_reg = Executor::apply_transaction_checked(
        &mut state,
        &vtx(f3.owner, 1_000, 0, TESTNET, ValidatorTx::Register(Box::new(reg3))),
    )
    .unwrap_err();
    assert_eq!(err_reg.code(), "validator_peer_or_operator_key_in_use");
}

#[test]
fn stolen_operator_key_frozen_during_rotation_window() {
    let f = make_fixture(0x41, TESTNET);
    let mut state = AccountState::new();
    state.add_balance(&f.owner, 1_000_000);

    Executor::apply_transaction_checked(
        &mut state,
        &vtx(
            f.owner,
            1_000,
            0,
            TESTNET,
            ValidatorTx::Register(Box::new(make_reg(&f, ValidatorClass::Mobile, 20))),
        ),
    )
    .unwrap();

    // Owner rotates away from compromised phone key #20 -> #21 (R-16).
    Executor::apply_transaction_checked(
        &mut state,
        &vtx(
            f.owner,
            0,
            1,
            TESTNET,
            ValidatorTx::RotateOperatorKey {
                new_operator_key: op_pubkey(21),
            },
        ),
    )
    .unwrap();
    let root_before = state.calculate_state_root();

    // Attacker holding compromised phone key #20 tries to inflate quota before E + 1.
    let target_quota = 4 << 30;
    let stolen_quota_tx = vtx(
        f.owner,
        0,
        2,
        TESTNET,
        ValidatorTx::UpdateCustodyQuota {
            owner: f.owner,
            new_quota_bytes: target_quota,
            seq: 0,
            operator_signature: op_sign(20, TESTNET, &f.owner, target_quota, 0),
        },
    );
    let err = Executor::apply_transaction_checked(&mut state, &stolen_quota_tx).unwrap_err();
    assert_eq!(err.code(), "validator_rotation_pending");
    assert_eq!(state.calculate_state_root(), root_before);
}

#[test]
fn change_class_validates_seat_keys_and_failed_install_rolls_back() {
    let f = make_fixture(0x51, DEFAULT_CHAIN_ID);
    let mut state = AccountState::new();
    state.add_balance(&f.owner, 50_000_000);

    Executor::apply_transaction_checked(
        &mut state,
        &vtx(
            f.owner,
            100_000,
            0,
            DEFAULT_CHAIN_ID,
            ValidatorTx::Register(Box::new(make_reg(&f, ValidatorClass::Mobile, 30))),
        ),
    )
    .unwrap();
    let root_before = state.calculate_state_root();

    // Seat with all-zero VRF key passes length==32 shape check, must be refused
    // by `check_validator_tx` on `ChangeClass` without mutating state or charging fee.
    let mut bad_seat = f.seat.clone();
    bad_seat.vrf_key = vec![0u8; 32];
    let bad_upgrade = vtx(
        f.owner,
        0,
        1,
        DEFAULT_CHAIN_ID,
        ValidatorTx::ChangeClass {
            new_class: ValidatorClass::Full,
            seat: Some(bad_seat),
        },
    );
    assert!(Executor::apply_transaction_checked(&mut state, &bad_upgrade).is_err());
    assert_eq!(state.calculate_state_root(), root_before);

    // Also verify `install_full_validator` at `epoch_index = u64::MAX` refuses
    // cleanly without leaving a dangling validator in `state.validators`.
    let f2 = make_fixture(0x52, DEFAULT_CHAIN_ID);
    state.epoch_index = u64::MAX;
    assert!(state
        .install_full_validator(
            f2.owner,
            100_000,
            &f2.bls_key,
            &f2.bls_pop,
            &f2.seat,
            DEFAULT_CHAIN_ID,
        )
        .is_err());
    assert!(!state.validators.contains_key(&f2.owner));
}

#[test]
fn randomized_bud_supply_conservation_and_atomic_rollback() {
    // Audits G-3 (zero minting / exact fee + burn conservation), G-4 (refusals
    // do not mutate), Y-2 (single deterministic state root), Y-3 (all-or-nothing
    // block execution), and Y-4 (single BUD balance ledger).
    let producer = Address::from([0x90; 32]);
    let accounts: Vec<Address> = (1..=6u8).map(|i| Address::from([i; 32])).collect();
    let mut state = AccountState::new();
    for addr in &accounts {
        state.add_balance(addr, 10_000);
    }
    let initial_balances: u64 = accounts
        .iter()
        .map(|a| state.get_balance(a))
        .sum::<u64>()
        + state.get_balance(&producer);
    let initial_burned = state.tokenomics.total_burned;

    let mut rng = 0xCAFE_BABE_1234_5678u64;
    for step in 0..80u64 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let from_idx = usize::try_from(rng % 6).unwrap_or(0);
        let to_idx = usize::try_from((rng >> 8) % 6).unwrap_or(0);
        let from = accounts[from_idx];
        let to = accounts[to_idx];
        let nonce = state.get_nonce(&from);
        // Half valid amounts, half intentionally over-balance or bad-nonce to exercise G-4/Y-3.
        let amount = if step % 3 == 0 { 50_000 } else { 150 };
        let fee = 10;
        let mut tx1 = Transaction::new_with_chain_id(
            from,
            to,
            100,
            fee,
            nonce,
            Vec::new(),
            DEFAULT_CHAIN_ID,
            TransactionType::Transfer,
        );
        tx1.hash = tx1.calculate_hash();
        let mut tx2 = Transaction::new_with_chain_id(
            from,
            to,
            amount,
            fee,
            nonce + 1,
            Vec::new(),
            DEFAULT_CHAIN_ID,
            TransactionType::Transfer,
        );
        tx2.hash = tx2.calculate_hash();

        let root_before = state.calculate_state_root();
        let res = Executor::apply_block_checked(&mut state, &[tx1, tx2], Some(&producer));
        if res.is_err() {
            assert_eq!(
                state.calculate_state_root(),
                root_before,
                "failed block at step {step} must leave state root unchanged"
            );
        }
        let live_balances: u64 = accounts
            .iter()
            .map(|a| state.get_balance(a))
            .sum::<u64>()
            + state.get_balance(&producer);
        let newly_burned = state.tokenomics.total_burned.saturating_sub(initial_burned);
        assert_eq!(
            live_balances + newly_burned,
            initial_balances,
            "BUD conservation violated at step {step}"
        );
    }
}

#[test]
fn quantum_class_and_chain_id_replay_separation() {
    // Audits Y-7, K-3, K-4, and R-36: operator signatures bind `chain_id`,
    // `owner`, `new_quota_bytes`, and `seq` under `ctx::VALIDATOR_V1`, and
    // post-quantum verification uses the canonical `SchemeStatusRegistry`.
    let owner = Address::from([0x71; 32]);
    let other_owner = Address::from([0x72; 32]);
    let pk = op_pubkey(44);
    let sig_testnet = op_sign(44, TESTNET, &owner, 4 << 30, 0);
    let registry = SchemeStatusRegistry::genesis();

    // Valid on TESTNET (45261).
    assert!(crate::crypto::pq::verify_in(
        &registry,
        SchemeId::ML_DSA_65,
        &pk,
        &quota_update_message(TESTNET, &owner, 4 << 30, 0),
        crate::crypto::ctx::VALIDATOR_V1,
        &sig_testnet,
    )
    .is_ok());

    // Cross-chain replay onto DEFAULT_CHAIN_ID fails.
    assert!(crate::crypto::pq::verify_in(
        &registry,
        SchemeId::ML_DSA_65,
        &pk,
        &quota_update_message(DEFAULT_CHAIN_ID, &owner, 4 << 30, 0),
        crate::crypto::ctx::VALIDATOR_V1,
        &sig_testnet,
    )
    .is_err());

    // Cross-owner replay fails.
    assert!(crate::crypto::pq::verify_in(
        &registry,
        SchemeId::ML_DSA_65,
        &pk,
        &quota_update_message(TESTNET, &other_owner, 4 << 30, 0),
        crate::crypto::ctx::VALIDATOR_V1,
        &sig_testnet,
    )
    .is_err());

    // Wrong FIPS 204 context tag fails.
    assert!(crate::crypto::pq::verify_in(
        &registry,
        SchemeId::ML_DSA_65,
        &pk,
        &quota_update_message(TESTNET, &owner, 4 << 30, 0),
        b"WRONG_CONTEXT_V1",
        &sig_testnet,
    )
    .is_err());
}
