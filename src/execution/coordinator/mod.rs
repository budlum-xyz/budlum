//! The Universal Execution Layer coordinator: account aliases, sparse Merkle
//! namespaces, BGU gas and EIP-1559 fee accounting, nested call-frame overlays
//! and worker supervision.

pub mod alias;
pub mod gas;
pub mod scheduler;
pub mod state;
