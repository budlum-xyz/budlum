//! Ethereum signature recovery for Graft claims by an externally owned
//! account (8.2 (b), D-14 option (b)): secp256k1 ECDSA
//! public key recovery written on the `k256` curve arithmetic already in the
//! tree, so no new dependency enters (K8).
//!
//! This is a combinator over audited curve arithmetic, not a new signature
//! scheme: `Q = r^-1 (s R - e G)`, with `R` decompressed from `r` and the
//! recovery bit. High-`s` signatures are refused (EIP-2), so one message and
//! one key have exactly one accepted signature.

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use sha3::{Digest, Keccak256};

/// Why a signature recovers no address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub enum RecoverError {
    #[error("the signature is not 65 bytes r || s || v")]
    Length,
    #[error("v is not 27, 28, 0 or 1")]
    RecoveryId,
    #[error("r or s is zero or not below the group order")]
    Range,
    #[error("s is in the upper half of the order (EIP-2)")]
    HighS,
    #[error("r is not the x coordinate of a curve point")]
    NoPoint,
}

/// The half order of secp256k1, big-endian: `s` must not exceed it.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// `keccak256("\x19Ethereum Signed Message:\n32" || hash)`: the EIP-191
/// personal-sign digest of a 32-byte message.
#[must_use]
pub fn eip191_digest(hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n32");
    hasher.update(hash);
    hasher.finalize().into()
}

/// The Ethereum address (20 bytes) whose key signed `digest`.
///
/// # Errors
///
/// [`RecoverError`] for a malformed, high-`s` or unrecoverable signature.
pub fn recover_address(digest: &[u8; 32], signature: &[u8]) -> Result<[u8; 20], RecoverError> {
    if signature.len() != 65 {
        return Err(RecoverError::Length);
    }
    let y_is_odd = match signature[64] {
        27 | 0 => false,
        28 | 1 => true,
        _ => return Err(RecoverError::RecoveryId),
    };
    let r_bytes = FieldBytes::try_from(&signature[..32]).map_err(|_| RecoverError::Length)?;
    let s_bytes = FieldBytes::try_from(&signature[32..64]).map_err(|_| RecoverError::Length)?;
    if signature[32..64] > HALF_ORDER[..] {
        return Err(RecoverError::HighS);
    }
    let r = Option::<Scalar>::from(Scalar::from_repr(r_bytes)).ok_or(RecoverError::Range)?;
    let s = Option::<Scalar>::from(Scalar::from_repr(s_bytes)).ok_or(RecoverError::Range)?;
    if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
        return Err(RecoverError::Range);
    }
    // r < n always reads as a field element too (n < p); the rare x in
    // [n, p) is not produced by an honest signer and is refused here.
    let big_r = Option::<AffinePoint>::from(AffinePoint::decompress(
        &r_bytes,
        k256::elliptic_curve::subtle::Choice::from(u8::from(y_is_odd)),
    ))
    .ok_or(RecoverError::NoPoint)?;
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*digest));
    let r_inv = Option::<Scalar>::from(r.invert()).ok_or(RecoverError::Range)?;
    let q = (ProjectivePoint::from(big_r) * s - ProjectivePoint::GENERATOR * e) * r_inv;
    let encoded = q.to_affine().to_sec1_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 {
        return Err(RecoverError::NoPoint);
    }
    let hash: [u8; 32] = Keccak256::digest(&bytes[1..]).into();
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A personal-sign vector made with Foundry's `cast wallet sign` over the
    /// 32 bytes 0x11..11 by the key whose address is 0x2c75..5c23.
    const SIGNATURE: &str = "3134afcb504290ed4fb6c1cb52415a0496b48591a0266c12090588bad7c5d1454b78db58ef88d8d2bd746a26a4a0186c264f4dff2fc7ee5de3a5c845cd3664eb1c";
    const SIGNER: &str = "2c7536e3605d9c16a7a3d7b1898e529396a65c23";

    #[test]
    fn a_personal_sign_signature_recovers_its_signer() {
        let signature = hex::decode(SIGNATURE).expect("hex");
        let digest = eip191_digest(&[0x11; 32]);
        let address = recover_address(&digest, &signature).expect("recovers");
        assert_eq!(hex::encode(address), SIGNER);
    }

    #[test]
    fn another_message_recovers_another_address_and_high_s_is_refused() {
        let signature = hex::decode(SIGNATURE).expect("hex");
        let other = recover_address(&eip191_digest(&[0x12; 32]), &signature);
        assert_ne!(other.map(hex::encode).ok().as_deref(), Some(SIGNER));
        let mut high = signature.clone();
        high[32] = 0xff;
        assert_eq!(
            recover_address(&eip191_digest(&[0x11; 32]), &high),
            Err(RecoverError::HighS)
        );
        assert_eq!(
            recover_address(&eip191_digest(&[0x11; 32]), &signature[..64]),
            Err(RecoverError::Length)
        );
    }
}
