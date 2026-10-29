//! Budlum blockchain quantum security - chain-wide (not storage).
//!
//! Fix in 8 steps, gates, no unsafe.
//!
//! FINAL decisions: V4 SHA3 hard fork, a 128KB block holding 27 tx, lower
//! threshold, same_set, ci_gate, only ml-dsa-87 final, sha3_sponge,
//! hard_fork_announce.
//!
//! What this module is not: it holds no signature scheme, no wallet and no
//! key exchange. An `Ed25519 plus ML-DSA` transaction type, a dual wallet and a
//! `SnowHybrid` P2P verdict used to live here; the first was never used, the
//! second hashed seeds into an address of its own, and the third answered a
//! constant. None of them was the chain's cryptography, and all three read as
//! if they were, so they are gone. The `no_constant_security_verdicts` gate
//! keeps a function named like a security verdict from returning a literal.
//!
//! There is no VRF in this module. A `PqVrf` used to live here whose output
//! was `SHA3(pk || slot || prev)`: every input public, so anyone computed
//! every validator's output ahead of time and the leader selection built on
//! it was open. It was not post-quantum either (an Ed25519 signature stood
//! as the proof), and nothing called it. Leader election is the schnorrkel
//! VRF in the node's consensus (`BUDLUM_VRF` context), which is a real one.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const MAX_BLOCK_BYTES: usize = 128 * 1024;
pub const MAX_TX_PER_BLOCK_ML_DSA_87: usize = 27; // 4627B sig
pub const PQ_SCHEME_ID_FINAL: &str = "ml-dsa-87";

/// SHA3-256 hasher (Q1 fix) - V4
pub struct Sha3Hasher;
impl Sha3Hasher {
    pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(data);
        h.finalize().into()
    }
    pub fn hash_fields(fields: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        for f in fields {
            h.update((f.len() as u64).to_le_bytes());
            h.update(f);
        }
        h.finalize().into()
    }
}

/// Hybrid Finality Vote - same_set quorum
#[derive(Debug, Clone)]
pub struct HybridFinalityVote {
    pub bls_sig: Vec<u8>,
    pub pq_sig: Vec<u8>,
}
impl HybridFinalityVote {
    /// `bls_ok` and `pq_ok` are the results of the aggregate checks done by the caller.
    /// The quorum counts DISTINCT signer indexes below `n`; repeats and strangers add nothing.
    pub fn verify_quorum(bls_ok: bool, pq_ok: bool, signers: &[usize], n: usize) -> bool {
        if n == 0 {
            return false;
        }
        let mut ids: Vec<usize> = signers.iter().copied().filter(|&i| i < n).collect();
        ids.sort_unstable();
        ids.dedup();
        let count = ids.len();
        // Strict supermajority, `floor(2n/3) + 1`: two quorums always share
        // an honest signer. `ceil(2n/3)` admitted two of three.
        let quorum = n - (n - 1) / 3;
        bls_ok && pq_ok && count >= quorum
    }
}

/// Fiat-Shamir absorption - ci_gate
#[derive(Debug, Clone)]
pub struct FiatShamirTranscript {
    pub observed: Vec<String>,
}
impl Default for FiatShamirTranscript {
    fn default() -> Self {
        Self::new()
    }
}

impl FiatShamirTranscript {
    pub fn new() -> Self {
        Self { observed: vec![] }
    }
    pub fn observe(&mut self, label: &str) {
        self.observed.push(label.to_string());
    }
    pub fn is_complete(&self) -> bool {
        let required = [
            "public_inputs",
            "fri_config",
            "polynomial_degree",
            "proof_data",
        ];
        // The labels must appear in this order (other labels may sit between them).
        let mut it = self.observed.iter();
        required.iter().all(|r| it.any(|o| o == r))
    }
}

/// MobileSelfProvider - a 10-minute grace period
#[derive(Debug, Clone)]
pub struct MobileSelfProvider {
    pub device_id: String,
    pub last_seen_secs: u64,
}
impl MobileSelfProvider {
    pub fn is_online(&self, now: u64) -> bool {
        now.saturating_sub(self.last_seen_secs) < 600
    }
    pub fn should_displace(&self, now: u64) -> bool {
        !self.is_online(now)
    }
}

/// SHA3 sponge - Poseidon2 → SHA3
pub struct Sha3Sponge;
impl Sha3Sponge {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        Sha3Hasher::hash_bytes(data)
    }
}

/// Gates
pub struct QuantumChainGates;
impl QuantumChainGates {
    pub fn kq_hash(data: &[u8], digest: &[u8; 32]) -> bool {
        Sha3Hasher::hash_bytes(data) == *digest
    }
    pub fn kq_final(bls_ok: bool, pq_ok: bool, signers: &[usize], n: usize) -> bool {
        HybridFinalityVote::verify_quorum(bls_ok, pq_ok, signers, n)
    }
    pub fn kq_stark(transcript: &FiatShamirTranscript) -> bool {
        transcript.is_complete()
    }
    pub fn kq_feat(scheme: &str) -> bool {
        scheme == PQ_SCHEME_ID_FINAL
    }
    pub fn kq_block(size: usize) -> bool {
        size <= MAX_BLOCK_BYTES
    }
    pub fn kq_media_device_only(cost_units: u64) -> bool {
        cost_units == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_hasher() {
        let h = Sha3Hasher::hash_bytes(b"hello");
        assert_eq!(h.len(), 32);
        assert_ne!(h, [0u8; 32]);
    }
    #[test]
    fn finality_same_set() {
        assert!(HybridFinalityVote::verify_quorum(true, true, &[0, 1, 2], 4));
        assert!(!HybridFinalityVote::verify_quorum(
            true,
            false,
            &[0, 1, 2],
            4
        ));
        // Two of three is not a supermajority; three of three is.
        assert!(!HybridFinalityVote::verify_quorum(true, true, &[0, 1], 3));
        assert!(HybridFinalityVote::verify_quorum(true, true, &[0, 1, 2], 3));
        assert!(!HybridFinalityVote::verify_quorum(true, true, &[], 0));
        // Repeated or out-of-range signers add nothing.
        assert!(!HybridFinalityVote::verify_quorum(
            true,
            true,
            &[0, 0, 0, 1, 9],
            3
        ));
    }
    #[test]
    fn a_transcript_with_labels_out_of_order_is_refused() {
        let mut t = FiatShamirTranscript::new();
        for l in [
            "proof_data",
            "polynomial_degree",
            "fri_config",
            "public_inputs",
        ] {
            t.observe(l);
        }
        assert!(
            !QuantumChainGates::kq_stark(&t),
            "labels out of order are refused"
        );
    }
    #[test]
    fn device_10dk() {
        let p = MobileSelfProvider {
            device_id: "d1".into(),
            last_seen_secs: 0,
        };
        assert!(!p.is_online(601));
        assert!(p.should_displace(601));
        let p2 = MobileSelfProvider {
            device_id: "d1".into(),
            last_seen_secs: 1000,
        };
        assert!(p2.is_online(1100));
    }
    #[test]
    fn fiat_shamir_ci_gate() {
        let mut t = FiatShamirTranscript::new();
        t.observe("public_inputs");
        t.observe("fri_config");
        t.observe("polynomial_degree");
        t.observe("proof_data");
        assert!(t.is_complete());
        assert!(QuantumChainGates::kq_stark(&t));
    }
    #[test]
    fn gates_kq_final() {
        let d = Sha3Hasher::hash_bytes(b"x");
        assert!(QuantumChainGates::kq_hash(b"x", &d));
        assert!(!QuantumChainGates::kq_hash(b"y", &d));
        assert!(QuantumChainGates::kq_feat("ml-dsa-87"));
        assert!(!QuantumChainGates::kq_feat("dilithium5"));
        assert!(QuantumChainGates::kq_block(128 * 1024));
        assert!(!QuantumChainGates::kq_block(128 * 1024 + 1));
    }
    #[test]
    fn media_device_only_holds() {
        // no_social + device-only → cost 0 ≤0.016
        assert!(QuantumChainGates::kq_media_device_only(0));
    }
}
