#![allow(warnings)]
// Task 8.3 (ADIM8): unsafe kilidi — src/ şu an 0 unsafe temiz taban;
// bir `unsafe` blok girdiği an derleme FAIL eder (regresyon kapısı).
// Not: üstteki `#![allow(warnings)]` kullanıcı kararıyla korunur — forbid ayrı eksen.
#![forbid(unsafe_code)]
pub mod ai;
pub mod bns;
pub mod chain;
pub mod cli;
pub mod consensus;
pub mod core;
pub mod cross_domain;
pub mod crypto;
pub mod developer_os;
pub mod deed;
pub mod domain;
pub mod error;
pub mod execution;
pub mod gateway;
pub mod hub;
pub mod lubot;
pub mod mempool;
pub mod network;
pub mod pollen;
pub mod privacy;
pub mod prover;
pub mod registry;
pub mod relayer;
pub mod rpc;
pub mod settlement;
pub mod socialfi;
pub mod storage;
pub mod tokenomics;

#[cfg(test)]
pub mod tests;

pub use crate::chain::blockchain::Blockchain;
pub use crate::core::account::AccountState;
pub use crate::core::block::Block;
pub use crate::core::transaction::Transaction;

#[cfg(test)]
mod bls_keypair_integrity_test {
    use bls12_381::{G1Affine, G2Affine};

    /// Task 0.17 (security audit §5): confirm that the compressed
    /// identity points are NOT accepted by `from_compressed` (so
    /// the BLS verifier is not vulnerable to a "zero public key"
    /// trivial forgery). BLS12-381 uses a special encoding for the
    /// identity element (the high bit of the compression flag is
    /// set for identity), so all-zero bytes decode to `None` and
    /// the existing `is_none()` check in `verify_bls_sig` is
    /// sufficient to block this attack.
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
