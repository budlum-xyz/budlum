//! Budlum blockchain quantum security - chain-wide (not storage).
//!
//! Fix in 8 steps, KQ-* gates, no unsafe.
//!
//! FINAL decisions: V4 SHA3 hard fork, a 128KB block holding 27 tx, lower
//! threshold, same_set, dual_required_new, snow_hybrid, ci_gate, only
//! ml-dsa-87 final, sha3_sponge, hard_fork_announce.
//!
//! K4 fix (2026-08-16): signature verification moved from a no-op to real
//! cryptography - ed25519 (RFC 8032) + ML-DSA-87 (FIPS 204).
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

/// Hybrid Tx: Ed25519 + ML-DSA-87 - 128KB block
/// K4 fix: the old verify only checked sizes (the signature was NOT verified).
/// It now really verifies the ed25519 signature plus the ML-DSA-87 (FIPS 204)
/// signature.
#[derive(Debug, Clone)]
pub struct HybridTx {
    pub ed_sig: [u8; 64],
    pub pq_sig: Vec<u8>, // 4627B ML-DSA-87
    pub pq_pub_hash: [u8; 32],
}
impl HybridTx {
    /// The commitment a transaction carries to its ML-DSA public key.
    fn pq_pub_hash_of(pq_pk: &[u8]) -> [u8; 32] {
        Sha3Hasher::hash_fields(&[b"BUD_PQ_PUB_HASH_V1", pq_pk])
    }
    pub fn verify(&self, msg: &[u8], ed_pk: &[u8], pq_pk: &[u8]) -> bool {
        use ed25519_dalek::{Signature as EdSig, VerifyingKey as EdVk};
        // 0) The PQ key must be the one this transaction commits to.
        if self.pq_pub_hash != Self::pq_pub_hash_of(pq_pk) {
            return false;
        }
        // 1) Verify the Ed25519 signature.
        let pk32: [u8; 32] = match ed_pk.try_into() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let vk = match EdVk::from_bytes(&pk32) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let ed_sig = match EdSig::from_slice(&self.ed_sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if vk.verify_strict(msg, &ed_sig).is_err() {
            return false;
        }
        // 2) Verify the ML-DSA-87 signature (FIPS 204).
        let enc_vk = match ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(pq_pk) {
            Ok(e) => e,
            Err(_) => return false,
        };
        let vk87 = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&enc_vk);
        let sig87 = match ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(&self.pq_sig[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        use ml_dsa::signature::Verifier as PqVerifier;
        vk87.verify(msg, &sig87).is_ok()
    }
    pub fn size_bytes(&self) -> usize {
        64 + self.pq_sig.len() + 32
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

/// Dual Wallet - dual_required_new, no address, SHA3(ed||pq) bud1...
#[derive(Debug, Clone)]
pub struct DualWallet {
    pub ed_seed: [u8; 32],
    pub pq_seed: [u8; 32],
}
impl DualWallet {
    pub fn from_bip39_seed(seed: &[u8; 64]) -> Self {
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&seed[0..32]);
        let mut h = Sha3_256::new();
        h.update(b"BUD_PQ_V1");
        h.update(seed);
        let pq: [u8; 32] = h.finalize().into();
        Self {
            ed_seed: ed,
            pq_seed: pq,
        }
    }
    /// The address commits to the PUBLIC keys, so a verifier holding the keys can recompute it.
    fn address_from_pubkeys(ed_pk: &[u8], pq_pk: &[u8]) -> [u8; 32] {
        Sha3Hasher::hash_fields(&[b"BUD_DUAL_ADDR_V1", ed_pk, pq_pk])
    }
    pub fn address(&self) -> [u8; 32] {
        let ed_pk = ed25519_dalek::SigningKey::from_bytes(&self.ed_seed).verifying_key();
        let pq_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&self.pq_seed.into());
        let pq_vk: &ml_dsa::VerifyingKey<ml_dsa::MlDsa87> = pq_sk.as_ref();
        let pq_pk: Vec<u8> = pq_vk.encode().into_iter().collect();
        Self::address_from_pubkeys(ed_pk.as_bytes(), &pq_pk)
    }
    pub fn has_dual(&self) -> bool {
        self.ed_seed != [0u8; 32] && self.pq_seed != [0u8; 32]
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

/// Snow hybrid X25519 + ML-KEM-768 - P2P
pub struct SnowHybrid;
impl SnowHybrid {
    /// No ML-KEM handshake exists in this tree (no ML-KEM crate is a dependency).
    pub fn handshake_ml_kem_ok() -> bool {
        false
    }
    pub fn is_quantum_resistant() -> bool {
        Self::handshake_ml_kem_ok()
    }
}

/// SHA3 sponge - Poseidon2 → SHA3
pub struct Sha3Sponge;
impl Sha3Sponge {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        Sha3Hasher::hash_bytes(data)
    }
}

/// Gates KQ-*
pub struct QuantumChainGates;
impl QuantumChainGates {
    pub fn kq_hash(data: &[u8], digest: &[u8; 32]) -> bool {
        Sha3Hasher::hash_bytes(data) == *digest
    }
    pub fn kq_tx(tx: &HybridTx, msg: &[u8], ed_pk: &[u8], pq_pk: &[u8]) -> bool {
        tx.verify(msg, ed_pk, pq_pk)
    }
    pub fn kq_final(bls_ok: bool, pq_ok: bool, signers: &[usize], n: usize) -> bool {
        HybridFinalityVote::verify_quorum(bls_ok, pq_ok, signers, n)
    }
    pub fn kq_wallet(wallet: &DualWallet) -> bool {
        wallet.has_dual()
    }
    pub fn kq_p2p() -> bool {
        SnowHybrid::handshake_ml_kem_ok()
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
    use ed25519_dalek::Signer as Ed25519Signer;
    #[test]
    fn sha3_hasher() {
        let h = Sha3Hasher::hash_bytes(b"hello");
        assert_eq!(h.len(), 32);
        assert_ne!(h, [0u8; 32]);
    }
    #[test]
    fn hybrid_tx_128kb() {
        use ml_dsa::signature::Signer as PqSigner;
        use ml_dsa::Generate as PqGenerate;
        use rand_core::OsRng; // ed25519-dalek: rand_core 0.6
                              // real keys + real signatures (ed25519 + ML-DSA-87)
        let ed_sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let ed_pk = ed_sk.verifying_key();
        let pq_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::generate(); // getrandom inside (FIPS 204)
        let pq_pk: &ml_dsa::VerifyingKey<ml_dsa::MlDsa87> = pq_sk.as_ref();
        let msg = b"budlum hybrid tx payload";
        let ed_sig: [u8; 64] = ed_sk.sign(msg).to_bytes();
        let pq_sig: Vec<u8> = pq_sk.sign(msg).encode().into_iter().collect();
        let pq_pk_bytes: Vec<u8> = pq_pk.encode().into_iter().collect();
        let tx = HybridTx {
            ed_sig,
            pq_sig: pq_sig.clone(),
            pq_pub_hash: HybridTx::pq_pub_hash_of(&pq_pk_bytes),
        };
        // the right input -> PASSES
        assert!(tx.verify(msg, ed_pk.as_bytes(), &pq_pk_bytes));
        // a changed message -> REFUSED (the signature really is checked)
        assert!(!tx.verify(b"tampered", ed_pk.as_bytes(), &pq_pk_bytes));
        // a wrong pq key -> REFUSED
        let other_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::generate();
        let other_pk: Vec<u8> = other_sk.as_ref().encode().into_iter().collect();
        assert!(!tx.verify(msg, ed_pk.as_bytes(), &other_pk));
        // a PQ key that does not match the committed hash -> REFUSED, even with a valid signature
        let other_sk2 = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::generate();
        let other_pk2: Vec<u8> = other_sk2.as_ref().encode().into_iter().collect();
        let other_sig: Vec<u8> = other_sk2.sign(msg).encode().into_iter().collect();
        let swapped = HybridTx {
            ed_sig,
            pq_sig: other_sig,
            pq_pub_hash: [0u8; 32],
        };
        assert!(
            !swapped.verify(msg, ed_pk.as_bytes(), &other_pk2),
            "a PQ key not bound by pq_pub_hash is REFUSED"
        );
        // a tampered pq_sig byte -> REFUSED (K38)
        let mut bad_pq = pq_sig.clone();
        let mid = bad_pq.len() / 2;
        bad_pq[mid] ^= 0x40;
        let bad_tx = HybridTx {
            ed_sig,
            pq_sig: bad_pq,
            pq_pub_hash: HybridTx::pq_pub_hash_of(&pq_pk_bytes),
        };
        assert!(
            !bad_tx.verify(msg, ed_pk.as_bytes(), &pq_pk_bytes),
            "a tampered PQ signature is REFUSED"
        );
        // a tampered ed_sig byte -> REFUSED
        let mut bad_ed = ed_sig;
        bad_ed[0] ^= 0x01;
        let bad_ed_tx = HybridTx {
            ed_sig: bad_ed,
            pq_sig: pq_sig.clone(),
            pq_pub_hash: HybridTx::pq_pub_hash_of(&pq_pk_bytes),
        };
        assert!(
            !bad_ed_tx.verify(msg, ed_pk.as_bytes(), &pq_pk_bytes),
            "a tampered Ed signature is REFUSED"
        );
        // boyut: 64 + 4627 + 32 = 4723; 27 tx = 127,521 B <= 128 KiB
        assert!(tx.size_bytes() < MAX_BLOCK_BYTES);
        let block_ok = QuantumChainGates::kq_block(tx.size_bytes() * 27);
        assert!(block_ok);
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
    fn the_p2p_gate_is_false_without_a_handshake() {
        assert!(!SnowHybrid::handshake_ml_kem_ok());
        assert!(!SnowHybrid::is_quantum_resistant());
        assert!(!QuantumChainGates::kq_p2p());
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
    fn dual_wallet_required() {
        let seed = [3u8; 64];
        let w = DualWallet::from_bip39_seed(&seed);
        assert!(w.has_dual());
        let addr = w.address();
        assert_ne!(addr, [0u8; 32]);
        // the address is a function of the public keys: a verifier can recompute it
        let ed_pk = ed25519_dalek::SigningKey::from_bytes(&w.ed_seed).verifying_key();
        let pq_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&w.pq_seed.into());
        let pq_vk: &ml_dsa::VerifyingKey<ml_dsa::MlDsa87> = pq_sk.as_ref();
        let pq_pk: Vec<u8> = pq_vk.encode().into_iter().collect();
        assert_eq!(
            addr,
            DualWallet::address_from_pubkeys(ed_pk.as_bytes(), &pq_pk)
        );
        // the old construction hashed the secret seeds; it must differ
        let mut old = Sha3_256::new();
        old.update(w.ed_seed);
        old.update(w.pq_seed);
        let old: [u8; 32] = old.finalize().into();
        assert_ne!(addr, old);
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
