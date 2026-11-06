//! Ecosystem-compatible RPC gateways (`Section 8.11`, `BLG-249`).
//!
//! Each gateway serves read queries and admits signed foreign-envelope transactions
//! into the mempool without mutating consensus state outside block execution.

pub mod cosmos;
pub mod ethereum;
pub mod sui;
