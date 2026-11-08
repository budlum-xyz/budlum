//! The node's post-quantum signature code, mounted by path (K-4).
//!
//! The operator key (section 7.9.6) signs with exactly the source the node
//! verifies with. `ctx`, `scheme` and `pq` have no dependency on the rest of
//! the node, and `crates/wallet-core` mounts the same three files the same
//! way, so their tests and the NIST vectors in `tests/vectors/pq` run here
//! too. A copy could drift from the verifier a node runs; one file cannot.

#[path = "../../../src/crypto/ctx.rs"]
pub mod ctx;

#[path = "../../../src/crypto/scheme.rs"]
pub mod scheme;

#[path = "../../../src/crypto/pq.rs"]
pub mod pq;
