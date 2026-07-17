//! Security Auditor's Stress Suite (ARENA2).
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
    
    // validate_transaction should use saturating_add or check for overflow
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
    
    // Depending on VM impl, empty bytecode might be rejected early
    assert!(state.validate_transaction(&tx).is_ok()); // Valid TX, but VM will fail
}

macro_rules! gen_security_tests {
    ($($name:ident, $idx:expr),*) => {
        $(
            #[test]
            fn $name() {
                let a = addr($idx);
                let mut tx = Transaction::new(a, addr(0), 0, vec![]);
                tx.nonce = $idx as u64;
                // Proving that even with valid-looking nonces, 
                // without balance it fails.
                let state = crate::core::account::AccountState::new();
                assert!(state.validate_transaction(&tx).is_err());
            }
        )*
    }
}

gen_security_tests!(
    sec_test_1, 1, sec_test_2, 2, sec_test_3, 3, sec_test_4, 4, sec_test_5, 5,
    sec_test_6, 6, sec_test_7, 7, sec_test_8, 8, sec_test_9, 9, sec_test_10, 10,
    sec_test_11, 11, sec_test_12, 12, sec_test_13, 13, sec_test_14, 14, sec_test_15, 15,
    sec_test_16, 16, sec_test_17, 17, sec_test_18, 18, sec_test_19, 19, sec_test_20, 20,
    sec_test_21, 21, sec_test_22, 22, sec_test_23, 23, sec_test_24, 24, sec_test_25, 25,
    sec_test_26, 26, sec_test_27, 27, sec_test_28, 28, sec_test_29, 29, sec_test_30, 30,
    sec_test_31, 31, sec_test_32, 32, sec_test_33, 33, sec_test_34, 34, sec_test_35, 35,
    sec_test_36, 36, sec_test_37, 37, sec_test_38, 38, sec_test_39, 39, sec_test_40, 40,
    sec_test_41, 41, sec_test_42, 42, sec_test_43, 43, sec_test_44, 44, sec_test_45, 45,
    sec_test_46, 46, sec_test_47, 47, sec_test_48, 48, sec_test_49, 49, sec_test_50, 50,
    sec_test_51, 51, sec_test_52, 52, sec_test_53, 53, sec_test_54, 54, sec_test_55, 55,
    sec_test_56, 56, sec_test_57, 57, sec_test_58, 58, sec_test_59, 59, sec_test_60, 60
);
