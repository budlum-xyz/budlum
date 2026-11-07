//! Sui `TransactionData` + `Ed25519` intent-message foreign envelope decoder (,
//! `Section 8.6.2`, `ForeignScheme::SuiEd25519`).
//!
//! Enforces `Section 1.5` launch-closure on testnet `45261` until
//! `PROPOSED_SUI_ACTIVATION_HEIGHT` (`foreign_sui_is_closed_on_testnet`), verifies
//! `Ed25519` signatures (`0x00 || sig64 || pk32`) over `BLAKE2b-256([0, 0, 0] || tx_bytes)`,
//! and derives the 32-byte Sui address `BLAKE2b-256(0x00 || pk32)`.

use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::execution::coordinator::assets::BUDLUM_TESTNET_CHAIN_ID;

/// Proposed activation height for Sui foreign envelopes on testnet `45261` ().
///
/// Convenience: shared by Sui foreign-envelope policy and RPC read/submit hooks.
pub const PROPOSED_SUI_ACTIVATION_HEIGHT: u64 = 50_000;

/// Sui `Ed25519` signature scheme flag byte (`0x00`).
///
/// Convenience: used by Sui address derivation and signature parsers.
pub const SUI_ED25519_FLAG: u8 = 0x00;

/// Sui `TransactionData` intent prefix (`IntentScope::TransactionData = 0`, `V0 = 0`, `Sui = 0`).
const SUI_TX_INTENT_PREFIX: [u8; 3] = [0x00, 0x00, 0x00];

const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    let va = v.get(a).copied().unwrap_or(0);
    let vb = v.get(b).copied().unwrap_or(0);
    let va1 = va.wrapping_add(vb).wrapping_add(x);
    if let Some(s) = v.get_mut(a) {
        *s = va1;
    }
    let vd1 = (v.get(d).copied().unwrap_or(0) ^ va1).rotate_right(32);
    if let Some(s) = v.get_mut(d) {
        *s = vd1;
    }
    let vc1 = v.get(c).copied().unwrap_or(0).wrapping_add(vd1);
    if let Some(s) = v.get_mut(c) {
        *s = vc1;
    }
    let vb1 = (vb ^ vc1).rotate_right(24);
    if let Some(s) = v.get_mut(b) {
        *s = vb1;
    }
    let va2 = va1.wrapping_add(vb1).wrapping_add(y);
    if let Some(s) = v.get_mut(a) {
        *s = va2;
    }
    let vd2 = (vd1 ^ va2).rotate_right(16);
    if let Some(s) = v.get_mut(d) {
        *s = vd2;
    }
    let vc2 = vc1.wrapping_add(vd2);
    if let Some(s) = v.get_mut(c) {
        *s = vc2;
    }
    let vb2 = (vb1 ^ vc2).rotate_right(63);
    if let Some(s) = v.get_mut(b) {
        *s = vb2;
    }
}

/// Pure-Rust RFC 7693 unkeyed `BLAKE2b-256` (`32`-byte output).
///
/// Convenience: used by Sui address derivation, intent-message digests, and RPC object IDs.
#[must_use]
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut h = BLAKE2B_IV;
    if let Some(h0) = h.first_mut() {
        *h0 ^= 0x0101_0020;
    }
    let mut pos: usize = 0;
    let mut total: u128 = 0;
    loop {
        let rem = data.len().saturating_sub(pos);
        let (block, is_last) = if rem > 128 {
            let mut blk = [0u8; 128];
            if let Some(src) = data.get(pos..pos + 128) {
                blk.copy_from_slice(src);
            }
            pos = pos.saturating_add(128);
            total = total.saturating_add(128);
            (blk, false)
        } else {
            let mut blk = [0u8; 128];
            if let Some(src) = data.get(pos..) {
                if let Some(dst) = blk.get_mut(..src.len()) {
                    dst.copy_from_slice(src);
                }
                total = total.saturating_add(src.len() as u128);
            }
            (blk, true)
        };

        let mut m = [0u64; 16];
        for (idx, slot) in m.iter_mut().enumerate() {
            let off = idx * 8;
            if let Some(word_bytes) = block.get(off..off + 8) {
                if let Ok(arr) = <[u8; 8]>::try_from(word_bytes) {
                    *slot = u64::from_le_bytes(arr);
                }
            }
        }

        let mut v = [0u64; 16];
        if let Some(lo) = v.get_mut(..8) {
            lo.copy_from_slice(&h);
        }
        if let Some(hi) = v.get_mut(8..) {
            hi.copy_from_slice(&BLAKE2B_IV);
        }
        if let Some(v12) = v.get_mut(12) {
            *v12 ^= total as u64;
        }
        if let Some(v13) = v.get_mut(13) {
            *v13 ^= (total >> 64) as u64;
        }
        if is_last {
            if let Some(v14) = v.get_mut(14) {
                *v14 = !*v14;
            }
        }

        for round in 0..12usize {
            let Some(s) = BLAKE2B_SIGMA.get(round % 10) else {
                continue;
            };
            let mw = |si: usize| -> u64 {
                s.get(si).and_then(|&mi| m.get(mi)).copied().unwrap_or(0)
            };
            blake2b_g(&mut v, 0, 4, 8, 12, mw(0), mw(1));
            blake2b_g(&mut v, 1, 5, 9, 13, mw(2), mw(3));
            blake2b_g(&mut v, 2, 6, 10, 14, mw(4), mw(5));
            blake2b_g(&mut v, 3, 7, 11, 15, mw(6), mw(7));
            blake2b_g(&mut v, 0, 5, 10, 15, mw(8), mw(9));
            blake2b_g(&mut v, 1, 6, 11, 12, mw(10), mw(11));
            blake2b_g(&mut v, 2, 7, 8, 13, mw(12), mw(13));
            blake2b_g(&mut v, 3, 4, 9, 14, mw(14), mw(15));
        }

        for idx in 0..8usize {
            let vi = v.get(idx).copied().unwrap_or(0);
            let vi8 = v.get(idx + 8).copied().unwrap_or(0);
            if let Some(hi) = h.get_mut(idx) {
                *hi ^= vi ^ vi8;
            }
        }
        if is_last {
            break;
        }
    }

    let mut out = [0u8; 32];
    for idx in 0..4usize {
        let word = h.get(idx).copied().unwrap_or(0).to_le_bytes();
        let off = idx * 8;
        if let Some(dst) = out.get_mut(off..off + 8) {
            dst.copy_from_slice(&word);
        }
    }
    out
}

/// Derive a 32-byte Sui address from an `Ed25519` public key:
/// `BLAKE2b-256(0x00 || pubkey32)`.
///
/// Convenience: shared by Sui foreign-envelope recovery and wallet fixtures.
#[must_use]
pub fn sui_address_from_ed25519_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 33];
    if let Some((flag_slot, rest)) = preimage.split_at_mut_checked(1) {
        if let Some(b0) = flag_slot.first_mut() {
            *b0 = SUI_ED25519_FLAG;
        }
        rest.copy_from_slice(pubkey);
    }
    blake2b_256(&preimage)
}

/// Compute the 32-byte Sui `IntentMessage` digest signed by `Ed25519` wallets:
/// `BLAKE2b-256([0x00, 0x00, 0x00] || tx_data_bytes)`.
///
/// Convenience: shared by Sui foreign-envelope verification and test fixtures.
#[must_use]
pub fn sui_transaction_signing_digest(tx_data_bytes: &[u8]) -> [u8; 32] {
    let mut intent = Vec::with_capacity(3 + tx_data_bytes.len());
    intent.extend_from_slice(&SUI_TX_INTENT_PREFIX);
    intent.extend_from_slice(tx_data_bytes);
    blake2b_256(&intent)
}

/// Height-gated activation policy for Sui foreign envelopes (`Section 1.5`, ).
///
/// Convenience: passed to `decode_and_recover_sui_tx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiActivationPolicy {
    pub chain_id: u64,
    pub block_height: u64,
    pub activation_height: Option<u64>,
}

impl Default for SuiActivationPolicy {
    fn default() -> Self {
        Self::testnet_launch()
    }
}

impl SuiActivationPolicy {
    /// Launch posture on testnet `45261`: closed until `PROPOSED_SUI_ACTIVATION_HEIGHT`.
    ///
    /// Convenience: default launch policy for `Foreign::Sui`.
    #[must_use]
    pub const fn testnet_launch() -> Self {
        Self {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: 0,
            activation_height: Some(PROPOSED_SUI_ACTIVATION_HEIGHT),
        }
    }

    /// Returns `true` when Sui foreign envelopes are open at `(chain_id, block_height)`.
    ///
    /// Convenience: queried before decoding `Foreign::Sui` envelopes.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        if self.chain_id != BUDLUM_TESTNET_CHAIN_ID {
            return true;
        }
        match self.activation_height {
            Some(h) => self.block_height >= h,
            None => false,
        }
    }
}

/// Canonical Sui `TransactionData` V1 fields carried inside a signed Sui envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiTransactionData {
    pub sender: [u8; 32],
    pub nonce: u64,
    pub ptb_json: Vec<u8>,
    pub gas_budget: u64,
    pub gas_price_mist: u64,
    pub chain_id: u64,
}

/// Signed Sui foreign-envelope wire payload (`tx_data_bytes` + 97-byte `0x00 || sig64 || pk32`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSuiEnvelope {
    pub tx_data_bytes: Vec<u8>,
    pub sui_signature: Vec<u8>,
}

/// Verified Sui transaction recovered from [`SignedSuiEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSuiTx {
    pub sender_sui: [u8; 32],
    pub pubkey: [u8; 32],
    pub data: SuiTransactionData,
    pub tx_digest: [u8; 32],
}

/// Refusal reasons when decoding a Sui foreign envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiEnvelopeError {
    ClosedOnTestnet { height: u64, activation: Option<u64> },
    MalformedEnvelope(String),
    WrongChainId { expected: u64, actual: u64 },
    InvalidSignatureLength(usize),
    UnsupportedSignatureScheme(u8),
    InvalidPublicKey,
    BadSignature,
    SenderMismatch,
}

impl fmt::Display for SuiEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClosedOnTestnet { height, activation } => write!(
                f,
                "Foreign::Sui is closed on testnet at height {height} (activation: {activation:?})"
            ),
            Self::MalformedEnvelope(m) => write!(f, "malformed Sui envelope: {m}"),
            Self::WrongChainId { expected, actual } => {
                write!(f, "Sui chain_id mismatch: expected {expected}, got {actual}")
            }
            Self::InvalidSignatureLength(n) => {
                write!(f, "Sui Ed25519 signature must be 97 bytes, got {n}")
            }
            Self::UnsupportedSignatureScheme(s) => {
                write!(f, "unsupported Sui signature flag 0x{s:02x}")
            }
            Self::InvalidPublicKey => write!(f, "invalid Sui Ed25519 public key"),
            Self::BadSignature => write!(f, "Sui Ed25519 signature verification failed"),
            Self::SenderMismatch => write!(f, "Sui sender does not match derived BLAKE2b address"),
        }
    }
}

impl std::error::Error for SuiEnvelopeError {}

/// Decode and strictly verify a [`SignedSuiEnvelope`] under `policy` ().
///
/// Convenience: coordinator and `sui_executeTransactionBlock` admission verifier.
pub fn decode_and_recover_sui_tx(
    raw_envelope: &[u8],
    policy: SuiActivationPolicy,
) -> Result<DecodedSuiTx, SuiEnvelopeError> {
    if !policy.is_active() {
        return Err(SuiEnvelopeError::ClosedOnTestnet {
            height: policy.block_height,
            activation: policy.activation_height,
        });
    }
    let env: SignedSuiEnvelope = serde_json::from_slice(raw_envelope)
        .map_err(|e| SuiEnvelopeError::MalformedEnvelope(e.to_string()))?;
    let sig_len = env.sui_signature.len();
    if sig_len != 97 {
        return Err(SuiEnvelopeError::InvalidSignatureLength(sig_len));
    }
    let Some((flag_slice, rest96)) = env.sui_signature.split_at_checked(1) else {
        return Err(SuiEnvelopeError::InvalidSignatureLength(sig_len));
    };
    let flag = flag_slice.first().copied().unwrap_or(0xFF);
    if flag != SUI_ED25519_FLAG {
        return Err(SuiEnvelopeError::UnsupportedSignatureScheme(flag));
    }
    let Some((sig_slice, pk_slice)) = rest96.split_at_checked(64) else {
        return Err(SuiEnvelopeError::InvalidSignatureLength(sig_len));
    };
    let sig_arr: [u8; 64] = sig_slice
        .try_into()
        .map_err(|_| SuiEnvelopeError::InvalidSignatureLength(sig_len))?;
    let pk_arr: [u8; 32] = pk_slice.try_into().map_err(|_| SuiEnvelopeError::InvalidPublicKey)?;

    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| SuiEnvelopeError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(&sig_arr);
    let signing_digest = sui_transaction_signing_digest(&env.tx_data_bytes);
    vk.verify_strict(&signing_digest, &sig).map_err(|_| SuiEnvelopeError::BadSignature)?;

    let data: SuiTransactionData = serde_json::from_slice(&env.tx_data_bytes)
        .map_err(|e| SuiEnvelopeError::MalformedEnvelope(e.to_string()))?;
    if data.chain_id != policy.chain_id {
        return Err(SuiEnvelopeError::WrongChainId {
            expected: policy.chain_id,
            actual: data.chain_id,
        });
    }
    let derived_sender = sui_address_from_ed25519_pubkey(&pk_arr);
    if derived_sender != data.sender {
        return Err(SuiEnvelopeError::SenderMismatch);
    }

    let mut tx_pre = Vec::with_capacity(14 + env.tx_data_bytes.len());
    tx_pre.extend_from_slice(b"TransactionData::");
    tx_pre.extend_from_slice(&env.tx_data_bytes);
    let tx_digest = blake2b_256(&tx_pre);

    Ok(DecodedSuiTx {
        sender_sui: derived_sender,
        pubkey: pk_arr,
        data,
        tx_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn blake2b_256_matches_rfc7693_test_vectors() {
        assert_eq!(
            hex::encode(blake2b_256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        assert_eq!(
            hex::encode(blake2b_256(b"abc")),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
        let seq200: Vec<u8> = (0u8..200).collect();
        assert_eq!(
            hex::encode(blake2b_256(&seq200)),
            "63c3d97a9f8894d5e043a707b0fee7f7ec4c049a23bbf1079df20b4165f9e22d"
        );
    }

    /// Section 1.5 launch-closure gate: `foreign_sui_is_closed_on_testnet`.
    #[test]
    fn foreign_sui_is_closed_on_testnet() {
        assert_eq!(
            decode_and_recover_sui_tx(b"{}", SuiActivationPolicy::default()),
            Err(SuiEnvelopeError::ClosedOnTestnet {
                height: 0,
                activation: Some(PROPOSED_SUI_ACTIVATION_HEIGHT),
            })
        );
    }

    #[test]
    fn valid_sui_ed25519_envelope_recovers_blake2b_sender_once_activated() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sender = sui_address_from_ed25519_pubkey(&pk);
        let tx_data = SuiTransactionData {
            sender,
            nonce: 0,
            ptb_json: br#"{"commands":[]}"#.to_vec(),
            gas_budget: 100_000,
            gas_price_mist: 1_000,
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
        };
        let tx_bytes = serde_json::to_vec(&tx_data).unwrap();
        let digest = sui_transaction_signing_digest(&tx_bytes);
        let sig = sk.sign(&digest);
        let mut sui_sig = Vec::with_capacity(97);
        sui_sig.push(SUI_ED25519_FLAG);
        sui_sig.extend_from_slice(&sig.to_bytes());
        sui_sig.extend_from_slice(&pk);
        let raw = serde_json::to_vec(&SignedSuiEnvelope {
            tx_data_bytes: tx_bytes,
            sui_signature: sui_sig,
        })
        .unwrap();

        let active = SuiActivationPolicy {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            block_height: PROPOSED_SUI_ACTIVATION_HEIGHT,
            activation_height: Some(PROPOSED_SUI_ACTIVATION_HEIGHT),
        };
        let dec = decode_and_recover_sui_tx(&raw, active).unwrap();
        assert_eq!(dec.sender_sui, sender);
    }
}
