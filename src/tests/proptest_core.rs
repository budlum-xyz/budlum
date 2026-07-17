//! Property-Based Testing (PBT) for Budlum Core (ARENA2).
//! Targeted at industrial-strength verification of parsing and invariant consistency.

use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use proptest::prelude::*;

proptest! {
    /// Address properties: Any 32-byte array must be a valid address, 
    /// and string round-trip must be identical.
    #[test]
    fn address_roundtrip_string(bytes in prop::collection::vec(any::<u8>(), 32)) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let addr = Address::from(arr);
        let s = addr.to_string();
        let addr2 = Address::from_hex(&s).expect("Must parse own hex output");
        prop_assert_eq!(addr, addr2);
    }

    /// Transaction invariants: Total cost must always be amount + fee.
    #[test]
    fn transaction_cost_invariant(amount in any::<u64>(), fee in any::<u64>()) {
        let sender = Address::zero();
        let receiver = Address::zero();
        let tx = Transaction::new_with_fee(sender, receiver, amount, fee, 0, vec![]);
        
        let expected_cost = amount.saturating_add(fee);
        prop_assert_eq!(tx.total_cost(), expected_cost);
    }

    /// Serialization robustness: Any random byte vector must not cause a panic 
    /// when attempting to deserialize as a Transaction.
    #[test]
    fn transaction_deserialization_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = bincode::deserialize::<Transaction>(&bytes);
        // If it doesn't panic, the test passes.
    }
}
