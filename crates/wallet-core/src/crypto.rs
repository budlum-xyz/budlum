//! The node's cryptographic core, mounted into the wallet by path.
//!
//! `scheme`, `ctx`, `pq`, `composite`, `address_v3` and `key_derivation` have no dependency on the rest of the
//! node, so the wallet compiles the very same source files (and their tests,
//! and the NIST test vectors in `tests/vectors/pq`). A copy would be able to
//! drift from the verifier a node runs; one file cannot.

#[path = "../../../src/crypto/ctx.rs"]
pub mod ctx;

#[path = "../../../src/crypto/scheme.rs"]
pub mod scheme;

#[path = "../../../src/crypto/pq.rs"]
pub mod pq;

#[path = "../../../src/crypto/composite.rs"]
pub mod composite;

#[path = "../../../src/crypto/address_v3.rs"]
pub mod address_v3;

#[path = "../../../src/crypto/key_derivation.rs"]
pub mod key_derivation;
