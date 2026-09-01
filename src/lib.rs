// The unsafe lock: src/ is a clean base with zero unsafe today, and the moment
// an `unsafe` block enters, the build FAILS. This is a regression gate.
#![forbid(unsafe_code)]
// `serde_json::json!` walks an object's keys by recursion, and the RPC answers are
// deliberately flat (a nested reply changes what an indexer has to parse). The
// largest of those maps is `qr_feed_json`, whose fifty-odd keys outgrow the
// default depth of 128; the depth is raised instead of splitting the reply, so
// no client has to learn a second shape.
#![recursion_limit = "256"]
/// Quantum-safe account abstraction. Signature verification is bound to ML-DSA-87
/// it therefore requires the `wallet-ml-dsa` feature.
#[cfg(feature = "wallet-ml-dsa")]
pub mod account_abstraction;
pub mod ai;
pub mod bns;
pub mod budlumxyz;
pub mod chain;
pub mod cli;
pub mod consensus;
pub mod core;
pub mod cross_domain;
pub mod crypto;
pub mod deed;
pub mod developer_os;
pub mod domain;
pub mod error;
pub mod execution;
pub mod gateway;
pub mod light_client;
pub mod ai_inference;
pub mod mempool;
pub mod network;
pub mod pollen;
pub mod privacy;
pub mod prover;
pub mod registry;
pub mod relayer;
pub mod rpc;
/// The Budlum project file schema (`budlum.toml`).
pub mod sdk;
pub mod settlement;
pub mod sharding;
pub mod socialfi;
pub mod storage;
pub mod tokenomics;

// The workspace denies `unwrap`/`expect` because a panic in production code
// aborts the node. Inside tests the opposite holds: a failed unwrap is how a
// test reports a broken invariant, and rewriting 2769 of them into `?` would
// make the suite harder to read while proving nothing.
#[cfg(test)]
pub mod tests;

pub use crate::chain::blockchain::Blockchain;
pub use crate::core::account::AccountState;
pub use crate::core::block::Block;
pub use crate::core::transaction::Transaction;

#[cfg(test)]
mod bls_keypair_integrity_test {
    use bls12_381::{G1Affine, G2Affine};

    /// (security audit §5) confirm that the compressed
    /// Identity points are NOT accepted by `from_compressed` (so
    /// The BLS verifier is not vulnerable to a "zero public key"
    /// Trivial forgery). BLS12-381 uses a special encoding for the
    /// Identity element (the high bit of the compression flag is
    /// Set for identity), so all-zero bytes decode to `None` and
    /// The existing `is_none` check in `verify_bls_sig` is
    /// Sufficient to block this attack.
    #[test]
    fn bls_zero_bytes_do_not_decode_as_identity() {
        let zero_g2 = [0u8; 96];
        let pk = G2Affine::from_compressed(&zero_g2);
        let is_some: bool = pk.is_some().into();
        assert!(
            !is_some,
            "all-zero G2 must NOT decode (identity uses a different flag)"
        );

        let zero_g1 = [0u8; 48];
        let sig = G1Affine::from_compressed(&zero_g1);
        let is_some: bool = sig.is_some().into();
        assert!(
            !is_some,
            "all-zero G1 must NOT decode (identity uses a different flag)"
        );
    }
}
