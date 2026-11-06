//! The account address, defined once in `budlum-types` and re-exported here.
//!
//! K-4: one definition per primitive. The mobile core binds `budlum-types`
//! directly because it must not link the whole node (7.9.5); the node keeps
//! importing `core::address::Address` unchanged. Both names now resolve to the
//! same type, so a phone and a validator cannot drift apart on what an address
//! is or how it prints. The identity is pinned by `node_address_is_the_shared_type`
//! below, which fails to compile if a second copy is ever reintroduced.
//!
//! # Looking for `from_hex`?
//!
//! The body moved to `crates/budlum-types/src/lib.rs`. In particular, BLG-151
//! (#43), which tightens the accepted input spellings, now applies to that
//! `from_hex` and not to this file.

pub use budlum_types::Address;

#[cfg(test)]
mod single_definition_tests {
    use super::Address;

    /// K-4 (single definition): the node's address and the shared type crate's
    /// address must be the *same* type, not two lookalikes that happen to agree
    /// today. `identity` coerces with no conversion, so this file only compiles
    /// when `core::address::Address` IS `budlum_types::Address`. A second copy of
    /// the struct breaks the build here instead of drifting silently.
    #[test]
    fn node_address_is_the_shared_type() {
        fn identity(shared: budlum_types::Address) -> Address {
            shared
        }
        let shared = budlum_types::Address::from([7u8; 32]);
        assert_eq!(identity(shared).as_bytes(), &[7u8; 32]);
    }

    /// The output shape the node has always written must survive the move:
    /// lowercase hex, 64 characters, no prefix, and a refusal on a short string.
    ///
    /// The accepted *input* spellings are deliberately not pinned here. #43 owns
    /// `from_hex`'s input contract under BLG-151 (it makes `"0"`/`"0x0"` errors
    /// and adds `0X`); a move must not decide that finding either way.
    #[test]
    fn address_wire_shape_survives_the_move() {
        assert_eq!(Address::zero().to_hex(), "0".repeat(64));
        let addr = Address::from([0xabu8; 32]);
        assert_eq!(addr.to_hex(), "ab".repeat(32));
        assert_eq!(addr.to_hex().len(), 64);
        assert_eq!(Address::from_hex(&addr.to_hex()).ok(), Some(addr));
        assert!(Address::from_hex("ab").is_err());
    }
}
