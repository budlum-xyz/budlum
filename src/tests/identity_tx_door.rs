//! The executor's identity arm - the transaction door onto the master
//! registry.
//!
//! Everything BEHIND the arm (sender-binding rules, the registry's own PoA
//! gate, the recovery quorum arithmetic, the crypto door for approvals) is
//! tested at full depth in `src/registry/identity.rs`. What is tested here
//! is the door: the domain fed to the body comes from state and never from a
//! caller, a value-carrying transaction is refused at the frame, and the
//! fee-plus-nonce epilogue runs exactly once on success and zero times on
//! every refusal.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::domain::ConsensusKind;
use crate::execution::executor::Executor;
use crate::registry::{
    GuardianApproval, IdentityRecord, IdentityTx, MethodKind, VerificationMethod,
};

fn test_keypair(byte: u8) -> crate::crypto::primitives::KeyPair {
    crate::crypto::primitives::KeyPair::from_seed(&[byte; 32]).expect("deterministic test keypair")
}

fn addr(byte: u8) -> Address {
    Address::from(test_keypair(byte).public_key_bytes())
}

fn subject_record(subject: Address) -> IdentityRecord {
    IdentityRecord::new(
        subject,
        vec![VerificationMethod::new([7u8; 32], MethodKind::MlDsa87)],
        vec![],
        0,
    )
    .expect("a one-method record with no guardians is well-formed")
}

/// A state running as the PoA authority's chain - the way `Blockchain`
/// builds one for a node whose engine declared itself PoA. A bare
/// `AccountState::new()` never volunteers this: the default stays PoS and
/// the door stays closed.
fn poa_state(subject: &Address) -> AccountState {
    let mut state = AccountState::new();
    state.execution_domain = ConsensusKind::PoA;
    state.add_balance(subject, 1_000);
    state
}

fn identity_tx(from: Address, body: IdentityTx, nonce: u64) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        1,
        nonce,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::Identity(body),
    )
}

#[test]
fn the_arm_writes_the_master_registry_under_a_poa_domain() {
    let subject = addr(1);
    let mut state = poa_state(&subject);
    Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(
            subject,
            IdentityTx::Register {
                record: subject_record(subject),
            },
            0,
        ),
    )
    .expect("the register must pass through the arm into the registry");
    assert_eq!(
        state.identity.record(&subject).map(|r| r.subject),
        Some(subject),
        "the record lives in the registry, keyed by the subject"
    );
    // The epilogue ran exactly once: one fee taken, one nonce spent.
    assert_eq!(state.get_balance(&subject), 999);
    assert_eq!(state.get_nonce(&subject), 1);
}

#[test]
fn a_default_state_cannot_open_the_door_even_for_the_right_sender() {
    let subject = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&subject, 1_000);
    let err = Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(
            subject,
            IdentityTx::Register {
                record: subject_record(subject),
            },
            0,
        ),
    )
    .expect_err("a node with a non-PoA engine must refuse identity writes");
    assert_eq!(err.code(), "identity_tx_failed");
    assert!(
        err.message().contains("PoA-domain authority"),
        "the refusal is the registry's own gate, surfaced verbatim: {err:?}"
    );
    // A refused write consumed nothing: no fee, no nonce, no record. The
    // refusal failing BEFORE the epilogue is what makes retries safe.
    assert_eq!(state.get_balance(&subject), 1_000);
    assert_eq!(state.get_nonce(&subject), 0);
    assert!(
        state.identity.record(&subject).is_none(),
        "nothing was written"
    );
}

#[test]
fn an_identity_transaction_carrying_value_is_refused_at_the_frame() {
    let subject = addr(1);
    let mut state = poa_state(&subject);
    let mut tx = identity_tx(
        subject,
        IdentityTx::Register {
            record: subject_record(subject),
        },
        0,
    );
    tx.amount = 10;
    let err = Executor::apply_transaction_checked(&mut state, &tx)
        .expect_err("identity writes commit state; they never move value");
    assert_eq!(err.code(), "identity_amount_must_be_zero");
    assert!(
        state.identity.record(&subject).is_none(),
        "and it wrote nothing"
    );
    assert_eq!(state.get_balance(&subject), 1_000, "and it took nothing");
}

#[test]
fn the_sender_binding_survives_the_arm() {
    // The body refuses a sender who is not the subject. Threading that
    // through the executor is what proves the arm passes `tx.from` into
    // the check and not the payload's self-reported subject - a wiring
    // mistake there would make the rule vacuous, and the unit tests on the
    // body alone cannot see it.
    let subject = addr(1);
    let other = addr(5);
    let mut state = poa_state(&other);
    let err = Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(
            other,
            IdentityTx::Register {
                record: subject_record(subject),
            },
            0,
        ),
    )
    .expect_err("registering somebody else's DID is refused");
    assert!(err.message().contains("register: sender"), "{err:?}");
    assert!(state.identity.record(&subject).is_none());
}

#[test]
fn a_refused_recovery_changes_nothing_through_the_arm() {
    // Junk approvals must die at the crypto door with the DID exactly where
    // it was, and the refusal must surface through the executor - the arm
    // adds no best-effort path where a half-applied rotation could land.
    let subject = addr(1);
    let mut state = poa_state(&subject);
    let record = IdentityRecord::new(
        subject,
        vec![VerificationMethod::new([7u8; 32], MethodKind::MlDsa87)],
        vec![addr(2), addr(3)],
        2,
    )
    .expect("two guardians, threshold two");
    Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(subject, IdentityTx::Register { record }, 0),
    )
    .unwrap();

    let junk = IdentityTx::Recover {
        subject,
        new_key: [9u8; 32],
        approvals: vec![GuardianApproval {
            public_key: vec![0u8; 4],
            signature: vec![],
        }],
    };
    let err = Executor::apply_transaction_checked(&mut state, &identity_tx(subject, junk, 1))
        .expect_err("an approval with a junk key cannot rotate a DID");
    assert_eq!(err.code(), "identity_tx_failed");
    let live = state
        .identity
        .record(&subject)
        .expect("the record is still there");
    assert!(
        live.live_method(&[7u8; 32], state.epoch_index).is_some(),
        "the original key is still live: a refused rotation changed nothing"
    );
    assert!(
        live.live_method(&[9u8; 32], state.epoch_index).is_none(),
        "the proposed key did not arrive either"
    );
    // The failed recovery still spent its nonce and paid its fee: refusal
    // is not refund, and the door must not let retries of one nonce
    // double-write.
    assert_eq!(state.get_nonce(&subject), 1, "only the register moved it");
    assert_eq!(state.get_balance(&subject), 999, "only the register paid");
}
