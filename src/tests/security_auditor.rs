//! Security Auditor's Stress Suite.
//! Targeted at catching vulnerabilities in Transaction parsing,
//! Signature verification, and Range boundaries.

use crate::core::address::Address;

use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::KeyPair;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

#[test]
fn security_reject_max_u64_amount_plus_fee() {
    let mut state = crate::core::account::AccountState::new();
    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    state.add_balance(&alice, u64::MAX);

    // Amount + Fee would overflow u64
    let mut tx = Transaction::new_with_fee(alice, addr(2), u64::MAX, 1000, 0, vec![]);
    tx.sign(&alice_kp);

    // Validate_transaction should use saturating_add or check for overflow
    assert!(state.validate_transaction(&tx).is_err());
}

#[test]
fn security_reject_empty_signature() {
    let mut state = crate::core::account::AccountState::new();
    let alice = addr(1);
    state.add_balance(&alice, 1000);

    let mut tx = Transaction::new(alice, addr(2), 100, vec![]);
    tx.signature = None; // Explicitly none

    assert!(state.validate_transaction(&tx).is_err());
}

#[test]
fn security_reject_zero_length_data_for_contract_call() {
    let mut state = crate::core::account::AccountState::new();
    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    state.add_balance(&alice, 1000);

    let mut tx = Transaction::new(alice, addr(2), 0, vec![]);
    tx.tx_type = TransactionType::ContractCall;
    tx.sign(&alice_kp);

    // Protocol rule: ContractCall data MUST be non-empty BudZKVM bytecode
    // (validated before signature cost, anti-spam). The VM never sees an
    // Empty call payload.
    assert!(state.validate_transaction(&tx).is_err());
}

/// Sixty distinct senders with no account behind them. A wrong nonce is refused
/// for the nonce, and the right nonce is refused for the missing balance, so each
/// sender hits a different gate and the reason is pinned for both.
#[test]
fn security_unfunded_senders_are_refused_for_nonce_and_for_balance() {
    let state = crate::core::account::AccountState::new();
    let fee = state.base_fee + 1;
    for idx in 1u8..=60 {
        let sender = addr(idx);

        let wrong_nonce =
            Transaction::new_with_fee(sender, addr(0), 1, fee, u64::from(idx), vec![]);
        let err = state
            .validate_transaction(&wrong_nonce)
            .expect_err("a nonce the account has not reached must be refused");
        assert!(err.contains("Invalid nonce"), "sender {idx}: {err}");

        let no_balance = Transaction::new_with_fee(sender, addr(0), 1, fee, 0, vec![]);
        let err = state
            .validate_transaction(&no_balance)
            .expect_err("a sender without balance must be refused");
        assert!(err.contains("Insufficient balance"), "sender {idx}: {err}");
    }
}
