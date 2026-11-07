//! Unlinkable B.U.D. 3.0 view grants (`IssueViewGrant`, `RevokeViewGrant`).
//! exposed for `Bud3Registry`, `Bud3RpcService`, and DataMarket grant issuance.
//!
//! Per Section 6.22.1 &  item 6:
//! * An on-chain [`GrantRow`] NEVER carries `content_id`, `issuer`, or `grantee`.
//! * It carries only:
//!   1. `grant_tag = H(BDLM_BUD3_GRANT_V1 || nft_id || grant_nonce)`,
//!   2. `one_time_pk` (the owner's per-grant ML-DSA-65 public key),
//!   3. `sealed_key_package` (HPKE X-Wing `0x647a` ciphertext addressed to the grantee),
//!   4. `expires_at_epoch`.
//! * Revocation and cryptographic-shredding burns authorize deletion by signing
//!   `grant_revoke_digest(grant_tag)` with `one_time_pk` under `ctx::STORAGE_V2`.
//!   Once revoked or shredded, the row and its HPKE key package are permanently
//!   deleted from chain state and never served again.

use crate::core::hash::hash_fields_bytes;
use crate::crypto::ctx::STORAGE_V2;
use crate::crypto::hpke::HpkeEnvelope;
use crate::crypto::pq::{validate_public_key, verify};
use crate::crypto::scheme::SchemeId;

/// Domain tag for unlinkable grant tags: `H(BDLM_BUD3_GRANT_V1 || nft_id || grant_nonce)`.
pub const GRANT_TAG_DOMAIN: &[u8] = b"BDLM_BUD3_GRANT_V1";

/// Domain tag for the one-time revocation / burn-shredding message digest.
pub const GRANT_REVOKE_DOMAIN: &[u8] = b"BDLM_BUD3_GRANT_REVOKE_V1";

/// Hard upper bound on a sealed HPKE key package stored in a grant row (4 KiB).
pub const MAX_SEALED_KEY_PACKAGE_BYTES: usize = 4096;

/// Compute the unlinkable 32-byte grant tag from `(nft_id, grant_nonce)`.
#[must_use]
pub fn compute_grant_tag(nft_id: &[u8; 32], grant_nonce: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[GRANT_TAG_DOMAIN, nft_id, grant_nonce])
}

/// Compute the domain-separated revocation/shredding digest signed by `one_time_pk`.
#[must_use]
pub fn grant_revoke_digest(grant_tag: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[GRANT_REVOKE_DOMAIN, grant_tag])
}

/// Seal a grant key package through the canonical B.U.D. 3.0 key-package codec.
pub fn seal_grant_key_package(
    recipient_hpke_pk: &[u8],
    grant_tag: &[u8; 32],
    object_commitment: &super::registry::ObjectKey,
    content_key: &super::content_id::ContentKey,
) -> Result<Vec<u8>, GrantBud3Error> {
    super::keys::seal_key_package(recipient_hpke_pk, grant_tag, object_commitment, content_key)
        .map_err(|_| GrantBud3Error::InvalidKeyPackage)
}

/// Open a grant key package through the canonical B.U.D. 3.0 key-package codec.
pub fn open_grant_key_package(
    recipient_kp: &crate::crypto::hpke::HpkeKeyPair,
    grant_tag: &[u8; 32],
    sealed: &[u8],
) -> Result<(super::registry::ObjectKey, super::content_id::ContentKey), GrantBud3Error> {
    super::keys::open_key_package(recipient_kp, grant_tag, sealed)
        .map_err(|_| GrantBud3Error::InvalidKeyPackage)
}

/// Unlinkable on-chain view-grant record. Contains zero content identifiers and
/// zero account addresses (`issuer` and `grantee` are absent by design).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantRow {
    /// `H(BDLM_BUD3_GRANT_V1 || nft_id || grant_nonce)`.
    pub grant_tag: [u8; 32],
    /// Owner's per-grant one-time ML-DSA-65 public key.
    pub one_time_pk: Vec<u8>,
    /// HPKE X-Wing (`0x647a`) envelope sealing `(object_commitment, content_key)`.
    pub sealed_key_package: Vec<u8>,
    /// Last epoch in which this grant remains active.
    pub expires_at_epoch: u64,
}

/// Errors refused when issuing or revoking a [`GrantRow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantBud3Error {
    /// `expires_at_epoch` is already in the past or equal to `current_epoch`.
    ExpiredGrant,
    /// `grant_tag` already exists or was previously revoked/shredded.
    DuplicateOrRevokedTag,
    /// `grant_tag` does not exist in active grants.
    UnknownGrant,
    /// `one_time_pk` is not a valid ML-DSA-65 public key.
    InvalidOneTimeKey,
    /// `sealed_key_package` is empty, exceeds [`MAX_SEALED_KEY_PACKAGE_BYTES`], or is not HPKE `0x647a`.
    InvalidKeyPackage,
    /// One-time ML-DSA-65 revocation signature failed verification.
    InvalidRevokeSignature,
}

impl GrantRow {
    /// Validate all structural and cryptographic invariants of a newly submitted
    /// `GrantRow` at `current_epoch` before state mutation.
    ///
    /// # Errors
    ///
    /// Returns [`GrantBud3Error`] if expiry, ML-DSA-65 key, or HPKE `0x647a`
    /// envelope checks fail.
    pub fn validate_for_issue(&self, current_epoch: u64) -> Result<(), GrantBud3Error> {
        if self.expires_at_epoch <= current_epoch {
            return Err(GrantBud3Error::ExpiredGrant);
        }
        if self.sealed_key_package.is_empty()
            || self.sealed_key_package.len() > MAX_SEALED_KEY_PACKAGE_BYTES
        {
            return Err(GrantBud3Error::InvalidKeyPackage);
        }
        validate_public_key(SchemeId::ML_DSA_65, &self.one_time_pk)
            .map_err(|_| GrantBud3Error::InvalidOneTimeKey)?;
        HpkeEnvelope::from_bytes(&self.sealed_key_package)
            .map_err(|_| GrantBud3Error::InvalidKeyPackage)?;
        Ok(())
    }

    /// Verify a revocation or burn-shredding authorization signed by `one_time_pk`.
    ///
    /// # Errors
    ///
    /// Returns [`GrantBud3Error::InvalidRevokeSignature`] if verification fails.
    pub fn verify_revocation(&self, one_time_signature: &[u8]) -> Result<(), GrantBud3Error> {
        let msg = grant_revoke_digest(&self.grant_tag);
        verify(
            SchemeId::ML_DSA_65,
            &self.one_time_pk,
            &msg,
            STORAGE_V2,
            one_time_signature,
        )
        .map_err(|_| GrantBud3Error::InvalidRevokeSignature)
    }
}

/// Construct and validate an unlinkable [`GrantRow`] for `(nft_id, grant_nonce)` at `current_epoch`.
/// Convenience: exposed for Data Market grant settlement and CLI grant issuance.
///
/// # Errors
///
/// Returns [`GrantBud3Error`] if expiry, ML-DSA-65 key, or HPKE `0x647a` validation fails.
pub fn build_grant_row(
    nft_id: &[u8; 32],
    grant_nonce: &[u8; 32],
    one_time_pk: Vec<u8>,
    sealed_key_package: Vec<u8>,
    expires_at_epoch: u64,
    current_epoch: u64,
) -> Result<GrantRow, GrantBud3Error> {
    let row = GrantRow {
        grant_tag: compute_grant_tag(nft_id, grant_nonce),
        one_time_pk,
        sealed_key_package,
        expires_at_epoch,
    };
    row.validate_for_issue(current_epoch)?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::super::keys::{
        derive_grant_one_time_keypair, derive_object_content_key, seal_key_package,
        sign_with_grant_one_time_key,
    };
    use super::*;
    use crate::crypto::hpke::HpkeKeyPair;

    #[test]
    fn grant_rows_are_unlinkable_and_verify_one_time_revocation() {
        let seed = [0x44u8; 32];
        let nft = [0x10u8; 32];
        let nonce_1 = [0x01u8; 32];
        let nonce_2 = [0x02u8; 32];

        let tag_1 = compute_grant_tag(&nft, &nonce_1);
        let tag_2 = compute_grant_tag(&nft, &nonce_2);
        assert_ne!(tag_1, tag_2);

        let (otk_seed_1, otk_pk_1) = derive_grant_one_time_keypair(&seed, &nft, &nonce_1).unwrap();
        let (_, otk_pk_2) = derive_grant_one_time_keypair(&seed, &nft, &nonce_2).unwrap();
        assert_ne!(otk_pk_1, otk_pk_2);

        let grantee = HpkeKeyPair::from_seed(&[0x88u8; 32]).unwrap();
        let ck = derive_object_content_key(&seed, 1);
        let pkg = seal_key_package(grantee.public_key(), &tag_1, &[0xabu8; 32], &ck).unwrap();

        let row = GrantRow {
            grant_tag: tag_1,
            one_time_pk: otk_pk_1,
            sealed_key_package: pkg,
            expires_at_epoch: 50,
        };
        row.validate_for_issue(10).unwrap();
        assert_eq!(
            row.validate_for_issue(50),
            Err(GrantBud3Error::ExpiredGrant)
        );

        let sig = sign_with_grant_one_time_key(&otk_seed_1, &grant_revoke_digest(&tag_1)).unwrap();
        row.verify_revocation(&sig).unwrap();

        let wrong_sig =
            sign_with_grant_one_time_key(&otk_seed_1, &grant_revoke_digest(&tag_2)).unwrap();
        assert_eq!(
            row.verify_revocation(&wrong_sig),
            Err(GrantBud3Error::InvalidRevokeSignature)
        );
    }
}
