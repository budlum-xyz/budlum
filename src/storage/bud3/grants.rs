//! Unlinkable B.U.D. 3.0 view grants (`bud3::grants`, Section 6.22.1 & WP-23).
//!
//! exposed for: `Bud3Registry`, SocialFi burn-shredding, and Data Market grant settlement.

use super::content_id::ContentKey;
use super::registry::ObjectKey;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::ctx::STORAGE_V2;
use crate::crypto::hpke::{HpkeEnvelope, HpkeKeyPair};
use crate::crypto::pq::{validate_public_key, verify};
use crate::crypto::scheme::SchemeId;
use serde::{Deserialize, Serialize};

/// Domain tag for unlinkable grant tags: `H(BDLM_BUD3_GRANT_V1 || nft_id || grant_nonce)`.
pub const GRANT_TAG_DOMAIN: &[u8] = b"BDLM_BUD3_GRANT_V1";
/// Domain tag for one-time revocation / burn-shredding digest.
pub const GRANT_REVOKE_DOMAIN: &[u8] = b"BDLM_BUD3_GRANT_REVOKE_V1";
/// Domain tag for HPKE key-package `info` binding.
pub const GRANT_KEY_INFO_DOMAIN: &[u8] = b"BDLM_BUD3_GRANT_KEY_INFO_V1";
/// Hard upper bound on a sealed HPKE key package stored in a grant row (4 KiB).
pub const MAX_SEALED_KEY_PACKAGE_BYTES: usize = 4096;

/// Compute the unlinkable 32-byte grant tag from `(nft_id, grant_nonce)`.
///
/// exposed for: Data Market and CLI grant builders (`WP-23`, `WP-39`).
#[must_use]
pub fn compute_grant_tag(nft_id: &[u8; 32], grant_nonce: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[GRANT_TAG_DOMAIN, nft_id, grant_nonce])
}

/// Compute the domain-separated revocation/shredding digest signed by `one_time_pk`.
///
/// exposed for: grant revocation and SocialFi NFT burn shredding (`WP-23`).
#[must_use]
pub fn grant_revoke_digest(grant_tag: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[GRANT_REVOKE_DOMAIN, grant_tag])
}

/// Seal `(object_commitment, content_key)` to `recipient_hpke_pk` under X-Wing (`0x647a`).
///
/// exposed for: Data Market grant settlement and CLI grant builders (`WP-23`).
pub fn seal_grant_key_package(
    recipient_hpke_pk: &[u8],
    grant_tag: &[u8; 32],
    object_commitment: &ObjectKey,
    content_key: &ContentKey,
) -> Result<Vec<u8>, GrantBud3Error> {
    let mut pt = Vec::with_capacity(64);
    pt.extend_from_slice(object_commitment);
    pt.extend_from_slice(&content_key.0);
    let env = HpkeEnvelope::seal(
        recipient_hpke_pk,
        GRANT_KEY_INFO_DOMAIN,
        grant_tag,
        &pt,
    )
    .map_err(|_| GrantBud3Error::InvalidKeyPackage)?;
    Ok(env.to_bytes())
}

/// Open a sealed key package using the grantee's `HpkeKeyPair`.
///
/// exposed for: Data Market buyers and `bud3::view` clients (`WP-23`).
pub fn open_grant_key_package(
    recipient_kp: &HpkeKeyPair,
    grant_tag: &[u8; 32],
    sealed: &[u8],
) -> Result<(ObjectKey, ContentKey), GrantBud3Error> {
    let env = HpkeEnvelope::from_bytes(sealed).map_err(|_| GrantBud3Error::InvalidKeyPackage)?;
    let pt = recipient_kp
        .open(&env, GRANT_KEY_INFO_DOMAIN, grant_tag)
        .map_err(|_| GrantBud3Error::InvalidKeyPackage)?;
    let (Some(obj_s), Some(ck_s)) = (pt.get(0..32), pt.get(32..64)) else {
        return Err(GrantBud3Error::InvalidKeyPackage);
    };
    let obj: [u8; 32] = obj_s
        .try_into()
        .map_err(|_| GrantBud3Error::InvalidKeyPackage)?;
    let ck_arr: [u8; 32] = ck_s
        .try_into()
        .map_err(|_| GrantBud3Error::InvalidKeyPackage)?;
    Ok((obj, ContentKey(ck_arr)))
}

/// Authorization shredding an active grant during NFT burn (`BLG-109`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantShredAuth {
    pub grant_tag: [u8; 32],
    pub one_time_signature: Vec<u8>,
}

/// Unlinkable on-chain view-grant record (`issuer` and `grantee` absent by design).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRow {
    pub grant_tag: [u8; 32],
    pub one_time_pk: Vec<u8>,
    pub sealed_key_package: Vec<u8>,
    pub expires_at_epoch: u64,
}

/// Errors refused when issuing or revoking a [`GrantRow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantBud3Error {
    ExpiredGrant,
    DuplicateOrRevokedTag,
    UnknownGrant,
    InvalidOneTimeKey,
    InvalidKeyPackage,
    InvalidRevokeSignature,
}

impl GrantRow {
    /// Validate structural and cryptographic invariants at `current_epoch`.
    ///
    /// exposed for: `Bud3Registry::issue_grant` and `build_grant_row` (`WP-23`).
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
    /// exposed for: `Bud3Registry::revoke_grant` (`WP-23`).
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

/// Construct and validate an unlinkable [`GrantRow`] for `(nft_id, grant_nonce)`.
///
/// exposed for: Data Market grant settlement (`WP-23`).
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
