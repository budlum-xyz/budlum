//! Ecosystem-compatible RPC gateways (directive 8.11, `BLG-249`).
//!
//! Each gateway serves read queries and admits signed foreign-envelope transactions
//! into the mempool without mutating consensus state outside block execution.
//!
//! | Gateway | Listener | Code | Package |
//! |---|---|---|---|
//! | Ethereum JSON-RPC | `127.0.0.1:18547` | `compat::ethereum` | WP-28 |
//! | Solana JSON-RPC | `127.0.0.1:18548` | `compat::solana` | WP-31 |
//!
//! The two share their listener and effect vocabulary
//! ([`ethereum::method_class::CompatListener`] and
//! [`ethereum::method_class::CompatEffect`]) so "what may a compatibility method
//! do" has one answer, not one per ecosystem.

pub mod ethereum;
pub mod solana;
