//! The executor's quantum-account arm - the transaction door onto the
//! account-abstraction registry.
//!
//! Everything BEHIND the arm (address-key binding, duplicate refusal,
//! capacity, pact-root equality, the structural guards) is tested at full
//! depth in `src/account_abstraction/registry.rs`. What is tested here is
//! the door: a value-carrying or balance-minting registration is refused at
//! the frame, the registration must be signed by the account's own
//! post-quantum key, the row deposit locks on success and is returned in
//! the same breath on every registry refusal, and the fee-plus-nonce
//! epilogue runs exactly once on success and zero times on every refusal.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{
    QuantumAccountPactEntry, QuantumAccountRegisterTx, Transaction, TransactionType,
    DEFAULT_CHAIN_ID,
};
use crate::crypto::primitives::{WalletKeyPair, ML_DSA_87_PUBLIC_KEY_LEN};
use crate::execution::executor::Executor;

fn test_keypair(byte: u8) -> crate::crypto::primitives::KeyPair {
    crate::crypto::primitives::KeyPair::from_seed(&[byte; 32]).expect("deterministic test keypair")
}

fn addr(byte: u8) -> Address {
    Address::from(test_keypair(byte).public_key_bytes())
}

fn qacc_deposit() -> u64 {
    crate::tokenomics::pool_deposit::policy_of(
        crate::tokenomics::pool_deposit::SharedPool::QuantumAccount,
    )
    .deposit
}

/// A deterministic ML-DSA-87 wallet and the account record its key derives.
fn quantum_account(seed: u8) -> (WalletKeyPair, crate::account_abstraction::QuantumAccount) {
    let wallet = WalletKeyPair::from_seed(&[seed; 32]);
    let pk = wallet.public_key_bytes();
    let guardians: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]> = (1..=3u8)
        .map(|i| {
            let mut g = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
            g[0] = i;
            g
        })
        .collect();
    let account = crate::account_abstraction::QuantumAccount {
        address: crate::account_abstraction::QuantumAccount::address_from_public_key(&pk),
        pq_public_key: pk,
        storage_root: [0u8; 32],
        pact_root: [0u8; 32],
        guardian_root: crate::account_abstraction::QuantumAccount::guardian_root(&guardians),
        guardians,
        multisig_threshold: 2,
        recovery_threshold: 2,
        timelock_blocks: 10,
        nonce: 0,
        balance: 0,
        storage_bytes: 0,
    };
    (wallet, account)
}

/// The exact digest the executor verifies; a test that drifted from the
/// production preimage would sign the wrong thing and fail loudly.
fn possession_digest(
    chain_id: u64,
    account: &crate::account_abstraction::QuantumAccount,
    based_on_root: &[u8; 32],
) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_QACC_REG_V1",
        &chain_id.to_le_bytes(),
        &account.address,
        &account.pq_public_key,
        &account.storage_root,
        &account.pact_root,
        &account.guardian_root,
        based_on_root,
    ])
}

fn signed_payload(
    wallet: &WalletKeyPair,
    account: crate::account_abstraction::QuantumAccount,
    pacts: Vec<QuantumAccountPactEntry>,
    based_on_root: [u8; 32],
) -> QuantumAccountRegisterTx {
    let digest = possession_digest(DEFAULT_CHAIN_ID, &account, &based_on_root);
    let possession_sig = wallet
        .sign(crate::crypto::ctx::QACC_REG_V1, &digest)
        .to_vec();
    QuantumAccountRegisterTx {
        account,
        pacts,
        based_on_root,
        possession_sig,
    }
}

fn register_tx(from: Address, payload: QuantumAccountRegisterTx, nonce: u64) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        1,
        nonce,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::QuantumAccountRegister(Box::new(payload)),
    )
}

fn funded_state(sender: &Address) -> AccountState {
    let mut state = AccountState::new();
    state.add_balance(sender, 1_000 + qacc_deposit());
    state
}

#[test]
fn a_register_signed_by_the_accounts_own_key_enters_the_registry() {
    let sender = addr(1);
    let mut state = funded_state(&sender);
    let (wallet, account) = quantum_account(9);
    let q_address = account.address;
    let root = state.quantum_accounts.root();
    Executor::apply_transaction_checked(
        &mut state,
        &register_tx(sender, signed_payload(&wallet, account, vec![], root), 0),
    )
    .expect("a well-formed possession-signed registration must enter the registry");
    assert!(state.quantum_accounts.is_registered(&q_address));
    // The epilogue ran exactly once: one fee taken, one nonce spent, and
    // the row's deposit sits in escrow behind the record.
    assert_eq!(state.get_balance(&sender), 999);
    assert_eq!(state.get_nonce(&sender), 1);
    assert_eq!(
        state.pool_deposit_escrow.get(&sender).copied(),
        Some(qacc_deposit()),
        "the live account row locks the table deposit"
    );
    assert!(state
        .pool_deposit_rows
        .contains_key(&format!("quantum-account:{}", hex::encode(q_address))));
}

#[test]
fn a_registration_not_signed_by_the_accounts_key_is_refused_before_any_state_moves() {
    let sender = addr(1);
    let mut state = funded_state(&sender);
    let (_owner, account) = quantum_account(9);
    let q_address = account.address;
    let root = state.quantum_accounts.root();
    // A different wallet signs: the digest is right, the key is not.
    let stranger = WalletKeyPair::from_seed(&[77u8; 32]);
    let err = Executor::apply_transaction_checked(
        &mut state,
        &register_tx(sender, signed_payload(&stranger, account, vec![], root), 0),
    )
    .expect_err("a stranger must not occupy a published key's derived address");
    assert_eq!(err.code(), "quantum_account_possession");
    assert!(!state.quantum_accounts.is_registered(&q_address));
    assert!(state.pool_deposit_escrow.is_empty(), "nothing locked");
    assert_eq!(state.get_nonce(&sender), 0, "no epilogue on refusal");
}

#[test]
fn a_value_carrying_or_balance_minting_registration_is_refused_at_the_frame() {
    let sender = addr(1);
    let mut state = funded_state(&sender);
    let (wallet, account) = quantum_account(9);
    let root = state.quantum_accounts.root();

    let mut value_tx = register_tx(
        sender,
        signed_payload(&wallet, account.clone(), vec![], root),
        0,
    );
    value_tx.amount = 7;
    let err = Executor::apply_transaction_checked(&mut state, &value_tx)
        .expect_err("a registration cannot carry value");
    assert_eq!(err.code(), "quantum_account_amount_must_be_zero");

    let mut minted = account;
    minted.balance = 5;
    let err = Executor::apply_transaction_checked(
        &mut state,
        &register_tx(sender, signed_payload(&wallet, minted, vec![], root), 0),
    )
    .expect_err("a fresh record cannot bring its own balance");
    assert_eq!(err.code(), "quantum_account_fresh_record");
    assert!(state.quantum_accounts.is_empty());
    assert!(state.pool_deposit_escrow.is_empty());
}

#[test]
fn a_pact_root_that_does_not_match_the_presented_set_is_refused_and_the_deposit_returns() {
    let sender = addr(1);
    let mut state = funded_state(&sender);
    let (wallet, mut account) = quantum_account(9);
    account.storage_root = [1u8; 32];
    account.pact_root = [0xAB; 32]; // not the root of the presented set
    let root = state.quantum_accounts.root();
    let pact = QuantumAccountPactEntry {
        id: [1u8; 32],
        program_hash: [2u8; 32],
        seed: [3u8; 32],
        commitment: [4u8; 32],
        residual_commitment: [0u8; 32],
        byte_budget: 64,
        mode_flag: 0,
    };
    let err = Executor::apply_transaction_checked(
        &mut state,
        &register_tx(
            sender,
            signed_payload(&wallet, account, vec![pact], root),
            0,
        ),
    )
    .expect_err("a pact root that does not open to the presented set must refuse");
    assert_eq!(err.code(), "quantum_account_register_failed");
    assert!(
        state.pool_deposit_escrow.is_empty(),
        "the refused row returned its deposit in the same breath"
    );
    assert_eq!(state.get_nonce(&sender), 0, "no epilogue on refusal");
}

#[test]
fn a_pact_carrying_registration_binds_the_root_the_module_computes() {
    let sender = addr(1);
    let mut state = funded_state(&sender);
    let (wallet, mut account) = quantum_account(9);
    let entry = QuantumAccountPactEntry {
        id: [1u8; 32],
        program_hash: [2u8; 32],
        seed: [3u8; 32],
        commitment: [4u8; 32],
        residual_commitment: [0u8; 32],
        byte_budget: 64,
        mode_flag: 0,
    };
    // Compute the root the way the executor will: through the pact
    // module's own door.
    let mut mirror = crate::storage::pact_binding::PactRegistry::new();
    mirror
        .add_pact(crate::storage::pact_binding::Pact {
            id: entry.id,
            program_hash: entry.program_hash,
            seed: entry.seed,
            commitment: entry.commitment,
            residual_commitment: entry.residual_commitment,
            byte_budget: entry.byte_budget,
            mode_flag: entry.mode_flag,
        })
        .expect("a structurally valid pact enters the mirror");
    account.storage_root = [1u8; 32];
    account.pact_root = mirror.root;
    let q_address = account.address;
    let root = state.quantum_accounts.root();
    Executor::apply_transaction_checked(
        &mut state,
        &register_tx(
            sender,
            signed_payload(&wallet, account, vec![entry], root),
            0,
        ),
    )
    .expect("a pact set whose root the account commits to must register");
    let registered = state.quantum_accounts.get(&q_address).expect("row is live");
    assert_eq!(registered.pact_root, mirror.root);
}

#[test]
fn a_registration_built_against_a_moved_registry_is_refused_and_the_deposit_returns() {
    let sender = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&sender, 2_000 + 2 * qacc_deposit());
    let stale_root = state.quantum_accounts.root();
    let (first_wallet, first_account) = quantum_account(9);
    Executor::apply_transaction_checked(
        &mut state,
        &register_tx(
            sender,
            signed_payload(&first_wallet, first_account, vec![], stale_root),
            0,
        ),
    )
    .expect("first registration moves the registry root");

    let (second_wallet, second_account) = quantum_account(10);
    let q2 = second_account.address;
    let err = Executor::apply_transaction_checked(
        &mut state,
        &register_tx(
            sender,
            // Built against the pre-move root: the registry refuses the
            // stale read instead of silently applying onto moved state.
            signed_payload(&second_wallet, second_account, vec![], stale_root),
            1,
        ),
    )
    .expect_err("a stale based_on_root must refuse, not re-apply");
    assert_eq!(err.code(), "quantum_account_register_failed");
    assert!(!state.quantum_accounts.is_registered(&q2));
    assert_eq!(
        state.pool_deposit_rows.len(),
        1,
        "only the first row's deposit stays locked; the refused one returned"
    );
}
