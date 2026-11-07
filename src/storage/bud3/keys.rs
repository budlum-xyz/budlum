//! WIRING: unwired - B.U.D. 3.0 client key derivation and X-Wing key packages await wallet/RPC upload door.
//! Per-object key derivation, client-side same-owner sealed deduplication, and
//! HPKE X-Wing (`0x647a`) key packages for B.U.D. 3.0 view grants.
//!
//! Per Section 6.8.1.3 & Section 6.21.5:
//! * Content keys are derived deterministically per object from the wallet seed
//!   (or supplied from fresh randomness).
//! * Same-owner sealed deduplication maps `HMAC-SHA-256(owner_dedup_key, content)`
//!   to `ObjectKey` strictly on the owner's client; the index is never written in
//!   plaintext on chain, and its backup can be stored as an ordinary sealed BOF-1
//!   object.
//! * Grant key packages seal `(object_commitment, content_key)` to the grantee's
//!   HPKE X-Wing (`0x647a`, ML-KEM-768 + X25519, HKDF-SHA256, ChaCha20-Poly1305)
//!   public key, bound via AAD to the unlinkable `grant_tag`.

use super::bof1::Object;
use super::content_id::{ContentId, ContentKey};
use super::meter::Meter;
use super::registry::ObjectKey;
use super::seal::{open_sealed_object, seal_object, SealBud3Error, SEAL_SALT_LEN};
use crate::core::hash::hash_fields_bytes;
use crate::crypto::ctx::STORAGE_V2;
use crate::crypto::hpke::{HpkeEnvelope, HpkeError, HpkeKeyPair};
use crate::crypto::pq::{ml_dsa_public_key, ml_dsa_sign, PqError};
use crate::crypto::scheme::SchemeId;
use std::collections::BTreeMap;

/// Tag deriving per-object 32-byte `ContentKey`s from a wallet seed.
pub const OBJ_KEY_TAG: &[u8] = b"BDLM_BUD3_OBJ_KEY_V1";

/// Tag deriving the client-side same-owner sealed deduplication key.
pub const OWNER_DEDUP_TAG: &[u8] = b"BDLM_BUD3_OWNER_DEDUP_V1";

/// Tag deriving the one-time ML-DSA-65 grant control seed for `(nft_id, grant_nonce)`.
pub const GRANT_OTK_TAG: &[u8] = b"BDLM_BUD3_GRANT_OTK_V1";

/// HPKE `info` label binding B.U.D. 3.0 key packages.
pub const KEYPKG_INFO_TAG: &[u8] = b"BDLM_BUD3_KEYPKG_INFO_V1";

/// Plaintext length inside a B.U.D. 3.0 HPKE key package (`32`-byte object commitment + `32`-byte `ContentKey`).
pub const KEYPKG_PLAINTEXT_LEN: usize = 64;

/// Errors sealing, opening, or signing key packages and one-time grant controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPkgBud3Error {
    /// HPKE X-Wing envelope error.
    Hpke(HpkeError),
    /// Post-quantum signature error.
    Pq(PqError),
    /// Opened key-package plaintext did not match expected 64-byte layout.
    BadPlaintextLen(usize),
    /// Backup seal/open error.
    Backup(SealBud3Error),
    /// Malformed serialized client dedup index backup.
    MalformedBackup,
}

impl From<HpkeError> for KeyPkgBud3Error {
    fn from(e: HpkeError) -> Self {
        Self::Hpke(e)
    }
}

impl From<PqError> for KeyPkgBud3Error {
    fn from(e: PqError) -> Self {
        Self::Pq(e)
    }
}

impl From<SealBud3Error> for KeyPkgBud3Error {
    fn from(e: SealBud3Error) -> Self {
        Self::Backup(e)
    }
}

/// Derive a deterministic per-object [`ContentKey`] from `wallet_seed` and `object_index`.
/// WIRING: deterministic per-object ContentKey derivation exposed for wallet sealed uploads.
#[must_use]
pub fn derive_object_content_key(wallet_seed: &[u8; 32], object_index: u64) -> ContentKey {
    ContentKey(hash_fields_bytes(&[
        OBJ_KEY_TAG,
        wallet_seed,
        &object_index.to_le_bytes(),
    ]))
}

/// Convenience: wrap 32 fresh random bytes as a [`ContentKey`].
#[must_use]
pub const fn content_key_from_random(random_bytes: [u8; 32]) -> ContentKey {
    ContentKey(random_bytes)
}

/// Derive the one-time ML-DSA-65 seed and public key used by the owner to
/// revoke or shred a single unlinkable view grant.
///
/// # Errors
///
/// Returns [`KeyPkgBud3Error::Pq`] if ML-DSA-65 key derivation fails.
pub fn derive_grant_one_time_keypair(
    wallet_seed: &[u8; 32],
    nft_id: &[u8; 32],
    grant_nonce: &[u8; 32],
) -> Result<([u8; 32], Vec<u8>), KeyPkgBud3Error> {
    let seed = hash_fields_bytes(&[GRANT_OTK_TAG, wallet_seed, nft_id, grant_nonce]);
    let pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed)?;
    Ok((seed, pk))
}

/// Sign `message` under the owner's one-time ML-DSA-65 grant seed using
/// `ctx::STORAGE_V2`.
///
/// # Errors
///
/// Returns [`KeyPkgBud3Error::Pq`] if signing fails.
/// WIRING: one-time ML-DSA-65 grant revocation signer exposed for SocialDelete shredding.
pub fn sign_with_grant_one_time_key(
    one_time_seed: &[u8; 32],
    message: &[u8],
) -> Result<Vec<u8>, KeyPkgBud3Error> {
    Ok(ml_dsa_sign(
        SchemeId::ML_DSA_65,
        one_time_seed,
        message,
        STORAGE_V2,
        &[0u8; 32],
    )?)
}

/// Seal `(object, content_key)` to `grantee_hpke_public` (`1,216`-byte X-Wing
/// `0x647a` key), binding `grant_tag` into HPKE AAD so the package cannot be
/// transplanted across grant rows.
///
/// # Errors
///
/// Returns [`KeyPkgBud3Error::Hpke`] if `grantee_hpke_public` is invalid or sealing fails.
/// WIRING: X-Wing HPKE key-package sealer exposed for unlinkable view-grant issuance.
pub fn seal_key_package(
    grantee_hpke_public: &[u8],
    grant_tag: &[u8; 32],
    object: &ObjectKey,
    content_key: &ContentKey,
) -> Result<Vec<u8>, KeyPkgBud3Error> {
    let mut pt = [0u8; KEYPKG_PLAINTEXT_LEN];
    if let Some(first) = pt.get_mut(..32) {
        first.copy_from_slice(object);
    }
    if let Some(second) = pt.get_mut(32..64) {
        second.copy_from_slice(&content_key.0);
    }
    let env = HpkeEnvelope::seal(grantee_hpke_public, KEYPKG_INFO_TAG, grant_tag, &pt)?;
    Ok(env.to_bytes())
}

/// Attempt to open `sealed_package` with `grantee_kp` and `grant_tag`.
/// Grantee wallets scan active grant rows and invoke this helper; envelopes for
/// other recipients return `Err(KeyPkgBud3Error::Hpke(HpkeError::Open))`.
///
/// # Errors
///
/// Returns [`KeyPkgBud3Error`] if the suite is not X-Wing `0x647a`, the recipient
/// key or `grant_tag` does not match, or the plaintext length is not 64 bytes.
/// WIRING: X-Wing HPKE key-package opener exposed for grantee sealed views.
pub fn open_key_package(
    grantee_kp: &HpkeKeyPair,
    grant_tag: &[u8; 32],
    sealed_package: &[u8],
) -> Result<(ObjectKey, ContentKey), KeyPkgBud3Error> {
    let env = HpkeEnvelope::from_bytes(sealed_package)?;
    let pt = grantee_kp.open(KEYPKG_INFO_TAG, grant_tag, &env)?;
    if pt.len() != KEYPKG_PLAINTEXT_LEN {
        return Err(KeyPkgBud3Error::BadPlaintextLen(pt.len()));
    }
    let mut obj = [0u8; 32];
    obj.copy_from_slice(
        pt.get(..32)
            .ok_or(KeyPkgBud3Error::BadPlaintextLen(pt.len()))?,
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(
        pt.get(32..64)
            .ok_or(KeyPkgBud3Error::BadPlaintextLen(pt.len()))?,
    );
    Ok((obj, ContentKey(key)))
}

/// Client-local same-owner sealed deduplication index (Section 6.8.1.3).
/// Never published on chain in plaintext.
#[derive(Clone, Default)]
pub struct ClientSealedDedupIndex {
    dedup_key: [u8; 32],
    entries: BTreeMap<[u8; 32], ObjectKey>,
}

impl ClientSealedDedupIndex {
    /// Derive the owner's private deduplication index from `wallet_seed`.
    #[must_use]
    pub fn from_wallet_seed(wallet_seed: &[u8; 32]) -> Self {
        Self {
            dedup_key: hash_fields_bytes(&[OWNER_DEDUP_TAG, wallet_seed]),
            entries: BTreeMap::new(),
        }
    }

    /// Compute the keyed HMAC-SHA-256 content tag locally on the client.
    #[must_use]
    pub fn content_tag(&self, content: &[u8]) -> [u8; 32] {
        ContentId::sealed(&ContentKey(self.dedup_key), content).digest
    }

    /// Look up whether the owner already holds a live sealed object for `content`.
    #[must_use]
    pub fn lookup(&self, content: &[u8]) -> Option<ObjectKey> {
        self.entries.get(&self.content_tag(content)).copied()
    }

    /// Record a newly uploaded sealed object in the owner's local index.
    pub fn record(&mut self, content: &[u8], object: ObjectKey) {
        self.entries.insert(self.content_tag(content), object);
    }

    /// Convenience: export an encrypted BOF-1 sealed backup object of this client index.
    ///
    /// # Errors
    ///
    /// Returns [`KeyPkgBud3Error`] if sealing fails.
    pub fn export_sealed_backup(
        &self,
        backup_salt: [u8; SEAL_SALT_LEN],
    ) -> Result<Object, KeyPkgBud3Error> {
        let mut raw = Vec::with_capacity(self.entries.len().saturating_mul(64).saturating_add(8));
        raw.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for (tag, obj) in &self.entries {
            raw.extend_from_slice(tag);
            raw.extend_from_slice(obj);
        }
        let backup_key = ContentKey(self.dedup_key);
        Ok(seal_object(&raw, &backup_key, backup_salt)?)
    }

    /// Convenience: restore entries from an encrypted BOF-1 sealed backup object.
    ///
    /// # Errors
    ///
    /// Returns [`KeyPkgBud3Error`] if decryption fails or the backup payload is malformed.
    pub fn import_sealed_backup(
        wallet_seed: &[u8; 32],
        backup_object: &Object,
        meter: &mut Meter,
    ) -> Result<Self, KeyPkgBud3Error> {
        let mut idx = Self::from_wallet_seed(wallet_seed);
        let backup_key = ContentKey(idx.dedup_key);
        let raw = open_sealed_object(backup_object, &backup_key, meter)?;
        let count_bytes = raw.get(..8).ok_or(KeyPkgBud3Error::MalformedBackup)?;
        let mut count_arr = [0u8; 8];
        count_arr.copy_from_slice(count_bytes);
        let count = usize::try_from(u64::from_le_bytes(count_arr))
            .map_err(|_| KeyPkgBud3Error::MalformedBackup)?;
        let body = raw.get(8..).ok_or(KeyPkgBud3Error::MalformedBackup)?;
        if body.len() != count.saturating_mul(64) {
            return Err(KeyPkgBud3Error::MalformedBackup);
        }
        for pair in body.chunks_exact(64) {
            let mut tag = [0u8; 32];
            tag.copy_from_slice(pair.get(..32).ok_or(KeyPkgBud3Error::MalformedBackup)?);
            let mut obj = [0u8; 32];
            obj.copy_from_slice(pair.get(32..64).ok_or(KeyPkgBud3Error::MalformedBackup)?);
            idx.entries.insert(tag, obj);
        }
        Ok(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_xwing_key_package_seals_and_scans_across_grantees() {
        let wallet_seed = [0x11u8; 32];
        let obj_key = [0x99u8; 32];
        let content_key = derive_object_content_key(&wallet_seed, 7);
        let grant_tag = [0x55u8; 32];

        let alice = HpkeKeyPair::from_seed(&[0x21u8; 32]).unwrap();
        let bob = HpkeKeyPair::from_seed(&[0x22u8; 32]).unwrap();

        let pkg =
            seal_key_package(alice.public_key(), &grant_tag, &obj_key, &content_key).unwrap();
        // Bob scans the grant capsule and cannot open it.
        assert!(open_key_package(&bob, &grant_tag, &pkg).is_err());
        // Wrong grant_tag AAD also fails for Alice.
        assert!(open_key_package(&alice, &[0x56u8; 32], &pkg).is_err());
        // Alice opens her capsule and recovers both the object commitment and ContentKey.
        let (got_obj, got_ck) = open_key_package(&alice, &grant_tag, &pkg).unwrap();
        assert_eq!(got_obj, obj_key);
        assert_eq!(got_ck, content_key);
    }

    #[test]
    fn client_sealed_dedup_index_round_trips_through_sealed_backup() {
        let seed = [0x33u8; 32];
        let mut idx = ClientSealedDedupIndex::from_wallet_seed(&seed);
        idx.record(b"photo-1", [0xa1u8; 32]);
        assert_eq!(idx.lookup(b"photo-1"), Some([0xa1u8; 32]));
        assert_eq!(idx.lookup(b"photo-2"), None);

        let backup = idx.export_sealed_backup([0x77u8; SEAL_SALT_LEN]).unwrap();
        assert_eq!(backup.header.content_len, 0);
        let mut m = Meter::for_object(1 << 20);
        let restored = ClientSealedDedupIndex::import_sealed_backup(&seed, &backup, &mut m).unwrap();
        assert_eq!(restored.lookup(b"photo-1"), Some([0xa1u8; 32]));
    }
}
