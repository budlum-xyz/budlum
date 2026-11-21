//! The executor's identity arm - the transaction door onto the master
//! registry.
//!
//! Everything BEHIND the arm (sender-binding rules, the registry's own `PoA`
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

/// The table deposit a DID row locks - the door tests fund it explicitly
/// so the fee arithmetic they pin stays visible.
fn reg_deposit() -> u64 {
    crate::tokenomics::pool_deposit::policy_of(
        crate::tokenomics::pool_deposit::SharedPool::IdentityRecord,
    )
    .deposit
}

fn cred_deposit() -> u64 {
    crate::tokenomics::pool_deposit::policy_of(
        crate::tokenomics::pool_deposit::SharedPool::IssuedCredential,
    )
    .deposit
}

/// A state running as the `PoA` authority's chain - the way `Blockchain`
/// builds one for a node whose engine declared itself `PoA`. A bare
/// `AccountState::new()` never volunteers this: the default stays `PoS` and
/// the door stays closed.
fn poa_state(subject: &Address) -> AccountState {
    let mut state = AccountState::new();
    state.execution_domain = ConsensusKind::PoA;
    state.add_balance(subject, 1_000 + reg_deposit());
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
    // The epilogue ran exactly once: one fee taken, one nonce spent, and
    // the row's deposit sits in escrow behind the record.
    assert_eq!(state.get_balance(&subject), 999);
    assert_eq!(state.get_nonce(&subject), 1);
    assert_eq!(
        state.pool_deposit_escrow.get(&subject).copied(),
        Some(reg_deposit()),
        "the live DID row locks the table deposit"
    );
    assert!(state.pool_deposit_rows.contains_key(&format!(
        "identity-record:{}",
        hex::encode(subject.as_bytes())
    )));
}

#[test]
fn a_default_state_cannot_open_the_door_even_for_the_right_sender() {
    let subject = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&subject, 1_000 + reg_deposit());
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
    assert_eq!(state.get_balance(&subject), 1_000 + reg_deposit());
    assert_eq!(state.get_nonce(&subject), 0);
    assert!(
        state.pool_deposit_escrow.is_empty(),
        "a refused write strands no deposit"
    );
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
    assert_eq!(
        state.get_balance(&subject),
        1_000 + reg_deposit(),
        "and it took nothing"
    );
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
    // The failed recovery spent neither its nonce nor its fee: a refused
    // transaction leaves the account untouched.
    assert_eq!(state.get_nonce(&subject), 1, "only the register moved it");
    assert_eq!(state.get_balance(&subject), 999, "only the register paid");
}

#[cfg(feature = "wallet-ml-dsa")]
#[test]
fn a_signed_recovery_cannot_bypass_the_domain_gate_through_the_executor() {
    use crate::crypto::primitives::WalletKeyPair;
    use crate::registry::recovery_digest;

    let subject = addr(1);
    let guardian_one = WalletKeyPair::from_seed(&[21; 32]);
    let guardian_two = WalletKeyPair::from_seed(&[22; 32]);
    let mut state = poa_state(&subject);
    let record = IdentityRecord::new(
        subject,
        vec![VerificationMethod::new([7u8; 32], MethodKind::MlDsa87)],
        vec![guardian_one.address(), guardian_two.address()],
        2,
    )
    .expect("two guardians, threshold two");
    Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(subject, IdentityTx::Register { record }, 0),
    )
    .expect("the PoA domain can establish the recovery record");
    let original_record = state
        .identity
        .record(&subject)
        .expect("registration stored the identity")
        .clone();

    let new_key = [9u8; 32];
    let digest = recovery_digest(
        &subject,
        &new_key,
        state.epoch_index,
        DEFAULT_CHAIN_ID,
        state.identity.recovery_nonce_of(&subject),
    );
    let approvals = vec![
        GuardianApproval {
            public_key: guardian_one.public_key_bytes().to_vec(),
            signature: guardian_one
                .sign(crate::crypto::ctx::IDENTITY_V2, &digest)
                .to_vec(),
        },
        GuardianApproval {
            public_key: guardian_two.public_key_bytes().to_vec(),
            signature: guardian_two
                .sign(crate::crypto::ctx::IDENTITY_V2, &digest)
                .to_vec(),
        },
    ];

    // The transaction arm reads the active domain from AccountState, exactly
    // as it does during block execution. Even a valid guardian quorum cannot
    // rotate a PoA-owned registry from a PoS execution context.
    state.execution_domain = ConsensusKind::PoS;
    let err = Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(
            subject,
            IdentityTx::Recover {
                subject,
                new_key,
                approvals,
            },
            1,
        ),
    )
    .expect_err("signed recovery remains restricted to the PoA domain");
    assert_eq!(err.code(), "identity_tx_failed");
    assert!(err.message().contains("PoA-domain authority"), "{err:?}");
    assert_eq!(
        state.identity.record(&subject),
        Some(&original_record),
        "the valid approvals must not mutate the registry under PoS"
    );
    assert_eq!(state.get_nonce(&subject), 1, "the refusal spends no nonce");
    assert_eq!(
        state.get_balance(&subject),
        999,
        "the refusal spends no fee"
    );
}

/// At the pre-deposit tree a 1,000-atom balance bought a permanent DID row
/// for a 1-atom fee. The deposit economy ends that: a sender who cannot
/// lock the table's deposit cannot occupy the registry, and the refusal
/// mutates nothing.
#[test]
fn a_register_that_cannot_cover_the_pool_deposit_is_refused() {
    let subject = addr(1);
    let mut state = AccountState::new();
    state.execution_domain = ConsensusKind::PoA;
    // One atom short of deposit + fee.
    state.add_balance(&subject, reg_deposit());
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
    .expect_err("an uncovered deposit must refuse the row");
    assert_eq!(err.code(), "identity_pool_deposit");
    assert!(state.identity.record(&subject).is_none(), "nothing written");
    assert_eq!(state.get_balance(&subject), reg_deposit(), "nothing taken");
    assert!(state.pool_deposit_escrow.is_empty(), "nothing locked");
}

/// An issued credential locks its row deposit; a successful revoke closes
/// the row and refunds the issuer exactly once - a second revoke is
/// refused by the registry and cannot refund again, because the row
/// record is already gone.
#[test]
fn an_issue_locks_and_a_revoke_refunds_exactly_once() {
    use crate::registry::identity::{credential_id, CredentialCommitment, FieldCommitment};
    let subject = addr(1);
    let mut state = AccountState::new();
    state.execution_domain = ConsensusKind::PoA;
    state.add_balance(&subject, 1_000 + reg_deposit() + cred_deposit());
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
    .expect("the subject registers first");

    // Self-issuance: issuer == subject, so no consent envelope is needed.
    let credential = CredentialCommitment {
        issuer: subject,
        subject,
        schema: "kyc".to_string(),
        fields: vec![FieldCommitment {
            name: "tier".to_string(),
            commitment: [3u8; 32],
        }],
        issued_at: 0,
        expires_at: None,
    };
    let row_key = format!(
        "identity-credential:{}",
        hex::encode(credential_id(&credential))
    );
    Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(
            subject,
            IdentityTx::Issue {
                credential: credential.clone(),
                consent: None,
            },
            1,
        ),
    )
    .expect("the self-issuance lands");
    assert_eq!(
        state.pool_deposit_escrow.get(&subject).copied(),
        Some(reg_deposit() + cred_deposit()),
        "both live rows are backed"
    );
    assert!(state.pool_deposit_rows.contains_key(&row_key));
    let balance_after_issue = state.get_balance(&subject);

    Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(
            subject,
            IdentityTx::Revoke {
                credential: credential.clone(),
            },
            2,
        ),
    )
    .expect("the issuer revokes its own credential");
    assert_eq!(
        state.pool_deposit_escrow.get(&subject).copied(),
        Some(reg_deposit()),
        "the credential deposit came back; the DID row stays backed"
    );
    assert!(!state.pool_deposit_rows.contains_key(&row_key));
    assert_eq!(
        state.get_balance(&subject),
        balance_after_issue + cred_deposit() - 1,
        "the refund landed, minus the revoke fee"
    );

    let err = Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(subject, IdentityTx::Revoke { credential }, 3),
    )
    .expect_err("a second revoke is refused by the registry");
    assert_eq!(err.code(), "identity_tx_failed");
    assert_eq!(
        state.pool_deposit_escrow.get(&subject).copied(),
        Some(reg_deposit()),
        "and it cannot refund a second time"
    );
}

/// A credential row recorded before the deposit era carries no claim:
/// revoking it succeeds and refunds nothing - inventing a refund here
/// would mint supply out of a map entry.
#[test]
fn a_legacy_credential_revoke_refunds_nothing() {
    use crate::registry::identity::{credential_id, CredentialCommitment, FieldCommitment};
    let subject = addr(1);
    let mut state = AccountState::new();
    state.execution_domain = ConsensusKind::PoA;
    state.add_balance(&subject, 1_000 + reg_deposit() + cred_deposit());
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
    .expect("the subject registers first");
    let credential = CredentialCommitment {
        issuer: subject,
        subject,
        schema: "kyc".to_string(),
        fields: vec![FieldCommitment {
            name: "tier".to_string(),
            commitment: [4u8; 32],
        }],
        issued_at: 0,
        expires_at: None,
    };
    let row_key = format!(
        "identity-credential:{}",
        hex::encode(credential_id(&credential))
    );
    Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(
            subject,
            IdentityTx::Issue {
                credential: credential.clone(),
                consent: None,
            },
            1,
        ),
    )
    .expect("the issuance lands");
    // Simulate the pre-deposit era: the registry row exists, the deposit
    // record does not. The locked aggregate is released through the normal
    // path so the ledgers stay consistent for the rest of the test.
    state
        .release_pool_deposit_row(&row_key)
        .expect("clearing the record refunds through the aggregate");
    let balance_before_revoke = state.get_balance(&subject);

    Executor::apply_transaction_checked(
        &mut state,
        &identity_tx(subject, IdentityTx::Revoke { credential }, 2),
    )
    .expect("revoking a legacy credential still works");
    assert_eq!(
        state.get_balance(&subject),
        balance_before_revoke - 1,
        "only the fee moved: a recordless row refunds nothing"
    );
}
