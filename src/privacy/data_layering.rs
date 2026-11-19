//! WIRING: unwired - default-private tier classifier awaits consensus transaction integration.
//! Default-private `K1 / K2 / K3 / K4` cryptographic data-layering, post-quantum
//! selective disclosure, and off-chain anchor registry.
//!
//! Layers:
//! - `K1Public`: world-readable payload verified against its original commitment.
//! - `K2Pseudonymous`: salted hiding commitment paired with an unlinkable stealth
//!   owner tag (no raw account address or plaintext on chain).
//! - `K3Confidential` (the mandatory default): salted hiding commitment plus a
//!   bounded set of unlinkable view-grant tags; zero plaintext on chain.
//! - `K4OffChainAnchored`: zero payload on chain; binds only canonical `SHA3-256`
//!   content digest, exact byte length, and storage-locator commitment (B.U.D. 3.0,
//!   IPFS, Arweave, or sovereign storage).
//!
//! Honest immutability rule: controlled transitions run strictly toward greater
//! disclosure (`K3 -> K2 -> K1`, `K4 -> K1` digest-verified reveal) under an
//! ML-DSA-65 owner signature with a monotonic per-record nonce and an exact
//! hiding-commitment opening check (preventing bait-and-switch reveals). Any
//! attempt to move `K1Public` back to `K2/K3/K4` fails closed with
//! `IrreversiblePublicExposure` because replicated public block history cannot
//! honestly be un-published.
//!
//! Convenience: exposed for wallet privacy profiles, Data Market selective
//! disclosure, audit portals, and RPC state-commitment verification.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

use crate::crypto::ctx::PRIVATE_TRANSFER_V1;
use crate::crypto::pq::{validate_public_key, verify_in};
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};

/// Domain tag for hiding commitments `C(record_id, salt, digest, byte_len)`.
pub const DOMAIN_PRIVACY_LAYER_COMMIT: &[u8] = b"BDLM_PRIVACY_LAYER_COMMIT_V1";

/// Domain tag for unlinkable `K2` stealth owner tags.
pub const DOMAIN_PRIVACY_LAYER_STEALTH: &[u8] = b"BDLM_PRIVACY_LAYER_STEALTH_V1";

/// Domain tag for ML-DSA-65 owner layer-transition authorizations.
pub const DOMAIN_PRIVACY_LAYER_TRANSITION: &[u8] = b"BDLM_PRIVACY_LAYER_TRANSITION_V1";

/// Domain tag for `DataLayerRegistry::state_root`.
pub const DOMAIN_PRIVACY_LAYER_ROOT: &[u8] = b"BDLM_PRIVACY_LAYER_ROOT_V1";

/// Maximum layered records held in one registry before fail-closed refusal.
pub const MAX_LAYERED_RECORDS: usize = 16_384;

/// Maximum unlinkable view-grant tags attached to a single `K3` record.
pub const MAX_LAYER_GRANTS_PER_RECORD: usize = 64;

/// Maximum plaintext byte size accepted when opening a record into `K1Public`.
pub const MAX_PUBLIC_OPENING_BYTES: usize = 8_192;

fn update_lp_sha3(h: &mut Sha3_256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    h.update(len.to_le_bytes());
    h.update(bytes);
}

/// Canonical four-tier data-privacy classification (`K3Confidential` by default).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DataPrivacyLayer {
    /// World-readable consensus data with verified commitment opening.
    K1Public = 1,
    /// Salted commitment plus unlinkable stealth owner tag; zero plaintext.
    K2Pseudonymous = 2,
    /// Default tier: sealed hiding commitment + selective grants; zero plaintext.
    #[default]
    K3Confidential = 3,
    /// Off-chain payload anchored purely by `(content_digest, byte_len, locator_hash)`.
    K4OffChainAnchored = 4,
}

impl DataPrivacyLayer {
    /// Numeric code used in canonical hash preimages.
    ///
    /// Convenience: exposed for external signing helpers.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Whether a controlled transition `self -> target` preserves honest
    /// cryptographic privacy boundaries.
    ///
    /// Convenience: exposed for wallet transition preflight checks.
    #[must_use]
    pub const fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::K3Confidential, Self::K2Pseudonymous | Self::K1Public)
                | (
                    Self::K2Pseudonymous | Self::K4OffChainAnchored,
                    Self::K1Public
                )
        )
    }
}

/// Compute a hiding commitment binding `(record_id, blind_salt, plaintext_digest, byte_len)`.
///
/// Convenience: exposed for client-side `K3Confidential` sealing and `K1` opening.
#[must_use]
pub fn compute_layer_commitment(
    record_id: &[u8; 32],
    blind_salt: &[u8; 32],
    plaintext_digest: &[u8; 32],
    byte_len: u64,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    update_lp_sha3(&mut h, DOMAIN_PRIVACY_LAYER_COMMIT);
    h.update(record_id);
    h.update(blind_salt);
    h.update(plaintext_digest);
    h.update(byte_len.to_le_bytes());
    h.finalize().into()
}

/// Derive an unlinkable `K2Pseudonymous` stealth tag from an owner key digest and salt.
///
/// Convenience: exposed for client-side pseudonymous handle generation.
#[must_use]
pub fn derive_stealth_owner_tag(owner_pk_digest: &[u8; 32], stealth_salt: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    update_lp_sha3(&mut h, DOMAIN_PRIVACY_LAYER_STEALTH);
    h.update(owner_pk_digest);
    h.update(stealth_salt);
    h.finalize().into()
}

/// Canonical ML-DSA-65 signing digest authorizing a layer transition or grant.
///
/// Convenience: exposed for client-side ML-DSA-65 authorization signing.
#[must_use]
pub fn layer_transition_digest(
    chain_id: u64,
    record_id: &[u8; 32],
    transition_nonce: u64,
    from_layer: DataPrivacyLayer,
    to_layer: DataPrivacyLayer,
    action_binding: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    update_lp_sha3(&mut h, DOMAIN_PRIVACY_LAYER_TRANSITION);
    h.update(chain_id.to_le_bytes());
    h.update(record_id);
    h.update(transition_nonce.to_le_bytes());
    h.update([from_layer.code(), to_layer.code()]);
    h.update(action_binding);
    h.finalize().into()
}

/// On-chain metadata for a layered record (plaintext exists ONLY after verified `K1` reveal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayeredDataRecord {
    /// Stable 32-byte record identifier.
    pub record_id: [u8; 32],
    /// Current privacy classification.
    pub layer: DataPrivacyLayer,
    /// Canonical hiding commitment (`K1/K2/K3`) or content `SHA3-256` (`K4`).
    pub commitment: [u8; 32],
    /// Declared exact byte length of the underlying payload.
    pub declared_byte_len: u64,
    /// `SHA3-256` fingerprint of the owner's ML-DSA-65 public key (never raw address).
    pub owner_pk_digest: [u8; 32],
    /// Optional unlinkable stealth handle populated in `K2Pseudonymous`.
    pub stealth_tag: Option<[u8; 32]>,
    /// Optional off-chain storage locator commitment (B.U.D. 3.0 / IPFS / Arweave) for `K4`.
    pub offchain_locator_hash: Option<[u8; 32]>,
    /// Bounded set of active selective view-grant tags for `K3Confidential`.
    pub active_grant_tags: BTreeSet<[u8; 32]>,
    /// Verified public bytes populated strictly upon authorized `K1Public` declassification.
    pub disclosed_plaintext: Option<Vec<u8>>,
    /// Monotonic replay-protection counter incremented on every authorized mutation.
    pub transition_nonce: u64,
}

/// Post-quantum owner signature packet authenticating a transition or grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerOwnerAuth {
    /// Expected chain ID (replay-bound).
    pub chain_id: u64,
    /// Expected current `transition_nonce` of the target record.
    pub nonce: u64,
    /// Owner ML-DSA-65 public key (must hash to `record.owner_pk_digest`).
    pub owner_ml_dsa_65_pk: Vec<u8>,
    /// Owner ML-DSA-65 signature over `layer_transition_digest` under `PRIVATE_TRANSFER_V1`.
    pub signature: Vec<u8>,
}

/// Refusals enforced by `DataLayerRegistry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataLayerError {
    /// Zero `chain_id`, `record_id`, `commitment`, `grant_tag`, or `locator_hash`.
    ZeroParameter(&'static str),
    /// Malformed or mismatched owner ML-DSA-65 key.
    InvalidOwnerKey,
    /// ML-DSA-65 transition/grant authorization signature failed verification.
    InvalidOwnerSignature,
    /// `record_id` already exists in the registry.
    DuplicateRecord,
    /// `record_id` not found in the registry.
    UnknownRecord,
    /// Registry full (`MAX_LAYERED_RECORDS`).
    RegistryFull { max: usize },
    /// Per-record selective view-grant ceiling reached.
    GrantLimitReached { max: usize },
    /// Duplicate grant tag on the same record.
    DuplicateGrantTag,
    /// Replayed or out-of-order transition nonce or foreign chain ID.
    ReplayOrChainMismatch,
    /// Attempted to move `K1Public` back to a hidden layer.
    IrreversiblePublicExposure,
    /// Forbidden layer transition pair.
    ForbiddenTransition {
        from: DataPrivacyLayer,
        to: DataPrivacyLayer,
    },
    /// Revealed plaintext exceeding `MAX_PUBLIC_OPENING_BYTES` or mismatched length.
    InvalidOpeningLength,
    /// Revealed plaintext + salt failed to reproduce the committed digest (bait-and-switch).
    CommitmentOpeningMismatch,
}

/// Deterministic `K1 / K2 / K3 / K4` data-layering state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataLayerRegistry {
    chain_id: u64,
    #[serde(with = "crate::core::map_keys")]
    records: BTreeMap<[u8; 32], LayeredDataRecord>,
}

impl DataLayerRegistry {
    /// Construct an empty `DataLayerRegistry` bound to `chain_id`.
    ///
    /// Convenience: exposed for privacy state initialization.
    pub fn new(chain_id: u64) -> Result<Self, DataLayerError> {
        if chain_id == 0 {
            return Err(DataLayerError::ZeroParameter("chain_id"));
        }
        Ok(Self {
            chain_id,
            records: BTreeMap::new(),
        })
    }

    /// Number of stored layered records.
    ///
    /// Convenience: exposed for privacy telemetry callers.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Fetch an immutable view of `record_id`.
    ///
    /// Convenience: exposed for RPC and wallet queries.
    #[must_use]
    pub fn record(&self, record_id: &[u8; 32]) -> Option<&LayeredDataRecord> {
        self.records.get(record_id)
    }

    /// Register a new record in the mandatory default `K3Confidential` layer.
    /// Zero plaintext enters chain state.
    ///
    /// Convenience: exposed for default-private data creation.
    pub fn register_confidential_default(
        &mut self,
        record_id: [u8; 32],
        commitment: [u8; 32],
        declared_byte_len: u64,
        owner_ml_dsa_65_pk: &[u8],
    ) -> Result<&LayeredDataRecord, DataLayerError> {
        if record_id == [0u8; 32] {
            return Err(DataLayerError::ZeroParameter("record_id"));
        }
        if commitment == [0u8; 32] {
            return Err(DataLayerError::ZeroParameter("commitment"));
        }
        let owner_pk_digest = hash_valid_owner_pk(owner_ml_dsa_65_pk)?;
        self.ensure_insertable(&record_id)?;
        self.records.insert(
            record_id,
            LayeredDataRecord {
                record_id,
                layer: DataPrivacyLayer::default(), // K3Confidential
                commitment,
                declared_byte_len,
                owner_pk_digest,
                stealth_tag: None,
                offchain_locator_hash: None,
                active_grant_tags: BTreeSet::new(),
                disclosed_plaintext: None,
                transition_nonce: 0,
            },
        );
        self.records
            .get(&record_id)
            .ok_or(DataLayerError::UnknownRecord)
    }

    /// Register a zero-payload `K4OffChainAnchored` record binding a canonical
    /// `SHA3-256` content digest, exact byte size, and locator commitment.
    ///
    /// Convenience: exposed for B.U.D. 3.0 / IPFS / Arweave off-chain anchors.
    pub fn register_offchain_anchor(
        &mut self,
        record_id: [u8; 32],
        content_sha3_256: [u8; 32],
        declared_byte_len: u64,
        locator_hash: [u8; 32],
        owner_ml_dsa_65_pk: &[u8],
    ) -> Result<&LayeredDataRecord, DataLayerError> {
        if record_id == [0u8; 32] {
            return Err(DataLayerError::ZeroParameter("record_id"));
        }
        if content_sha3_256 == [0u8; 32] {
            return Err(DataLayerError::ZeroParameter("content_sha3_256"));
        }
        if locator_hash == [0u8; 32] {
            return Err(DataLayerError::ZeroParameter("locator_hash"));
        }
        if declared_byte_len == 0 {
            return Err(DataLayerError::ZeroParameter("declared_byte_len"));
        }
        let owner_pk_digest = hash_valid_owner_pk(owner_ml_dsa_65_pk)?;
        self.ensure_insertable(&record_id)?;
        self.records.insert(
            record_id,
            LayeredDataRecord {
                record_id,
                layer: DataPrivacyLayer::K4OffChainAnchored,
                commitment: content_sha3_256,
                declared_byte_len,
                owner_pk_digest,
                stealth_tag: None,
                offchain_locator_hash: Some(locator_hash),
                active_grant_tags: BTreeSet::new(),
                disclosed_plaintext: None,
                transition_nonce: 0,
            },
        );
        self.records
            .get(&record_id)
            .ok_or(DataLayerError::UnknownRecord)
    }

    /// Attach an unlinkable selective view-grant tag to a `K3Confidential` record
    /// under ML-DSA-65 owner authorization, without exposing plaintext.
    ///
    /// Convenience: exposed for selective auditor/counterparty disclosure.
    pub fn issue_confidential_grant(
        &mut self,
        record_id: &[u8; 32],
        grant_tag: [u8; 32],
        auth: &LayerOwnerAuth,
    ) -> Result<(), DataLayerError> {
        if grant_tag == [0u8; 32] {
            return Err(DataLayerError::ZeroParameter("grant_tag"));
        }
        let rec = self
            .records
            .get(record_id)
            .ok_or(DataLayerError::UnknownRecord)?;
        if rec.layer != DataPrivacyLayer::K3Confidential {
            return Err(DataLayerError::ForbiddenTransition {
                from: rec.layer,
                to: DataPrivacyLayer::K3Confidential,
            });
        }
        if rec.active_grant_tags.contains(&grant_tag) {
            return Err(DataLayerError::DuplicateGrantTag);
        }
        if rec.active_grant_tags.len() >= MAX_LAYER_GRANTS_PER_RECORD {
            return Err(DataLayerError::GrantLimitReached {
                max: MAX_LAYER_GRANTS_PER_RECORD,
            });
        }
        verify_owner_auth(
            self.chain_id,
            rec,
            DataPrivacyLayer::K3Confidential,
            &grant_tag,
            auth,
        )?;
        if let Some(rec_mut) = self.records.get_mut(record_id) {
            rec_mut.active_grant_tags.insert(grant_tag);
            rec_mut.transition_nonce = rec_mut.transition_nonce.saturating_add(1);
        }
        Ok(())
    }

    /// Transition a `K3Confidential` record to `K2Pseudonymous` by attaching an
    /// owner-authorized unlinkable `stealth_tag` while keeping plaintext hidden.
    ///
    /// Convenience: exposed for pseudonymous marketplace/reputation revelation.
    pub fn transition_to_pseudonymous(
        &mut self,
        record_id: &[u8; 32],
        stealth_salt: &[u8; 32],
        auth: &LayerOwnerAuth,
    ) -> Result<[u8; 32], DataLayerError> {
        if *stealth_salt == [0u8; 32] {
            return Err(DataLayerError::ZeroParameter("stealth_salt"));
        }
        let rec = self
            .records
            .get(record_id)
            .ok_or(DataLayerError::UnknownRecord)?;
        if rec.layer == DataPrivacyLayer::K1Public {
            return Err(DataLayerError::IrreversiblePublicExposure);
        }
        if !rec
            .layer
            .can_transition_to(DataPrivacyLayer::K2Pseudonymous)
        {
            return Err(DataLayerError::ForbiddenTransition {
                from: rec.layer,
                to: DataPrivacyLayer::K2Pseudonymous,
            });
        }
        let stealth_tag = derive_stealth_owner_tag(&rec.owner_pk_digest, stealth_salt);
        verify_owner_auth(
            self.chain_id,
            rec,
            DataPrivacyLayer::K2Pseudonymous,
            &stealth_tag,
            auth,
        )?;
        if let Some(rec_mut) = self.records.get_mut(record_id) {
            rec_mut.layer = DataPrivacyLayer::K2Pseudonymous;
            rec_mut.stealth_tag = Some(stealth_tag);
            rec_mut.transition_nonce = rec_mut.transition_nonce.saturating_add(1);
        }
        Ok(stealth_tag)
    }

    /// Selectively declassify a `K3Confidential`, `K2Pseudonymous`, or
    /// `K4OffChainAnchored` record into `K1Public`, verifying both the owner's
    /// ML-DSA-65 signature and the exact cryptographic commitment opening so a
    /// dishonest owner can never reveal substituted plaintext.
    ///
    /// Convenience: exposed for regulatory/dispute/public-good declassification.
    pub fn declassify_to_public(
        &mut self,
        record_id: &[u8; 32],
        plaintext: Vec<u8>,
        blind_salt: Option<&[u8; 32]>,
        auth: &LayerOwnerAuth,
    ) -> Result<(), DataLayerError> {
        if plaintext.len() > MAX_PUBLIC_OPENING_BYTES {
            return Err(DataLayerError::InvalidOpeningLength);
        }
        self.check_transition_allowed(record_id, DataPrivacyLayer::K1Public)?;
        let rec = self
            .records
            .get(record_id)
            .ok_or(DataLayerError::UnknownRecord)?;
        let actual_len = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
        if actual_len != rec.declared_byte_len {
            return Err(DataLayerError::InvalidOpeningLength);
        }
        let plaintext_digest: [u8; 32] = Sha3_256::digest(&plaintext).into();
        let expected_commitment = match rec.layer {
            DataPrivacyLayer::K4OffChainAnchored => plaintext_digest,
            DataPrivacyLayer::K3Confidential | DataPrivacyLayer::K2Pseudonymous => {
                let salt = blind_salt.ok_or(DataLayerError::CommitmentOpeningMismatch)?;
                compute_layer_commitment(record_id, salt, &plaintext_digest, actual_len)
            }
            DataPrivacyLayer::K1Public => return Err(DataLayerError::IrreversiblePublicExposure),
        };
        if !bool::from(expected_commitment.ct_eq(&rec.commitment)) {
            return Err(DataLayerError::CommitmentOpeningMismatch);
        }
        verify_owner_auth(
            self.chain_id,
            rec,
            DataPrivacyLayer::K1Public,
            &plaintext_digest,
            auth,
        )?;
        if let Some(rec_mut) = self.records.get_mut(record_id) {
            rec_mut.layer = DataPrivacyLayer::K1Public;
            rec_mut.disclosed_plaintext = Some(plaintext);
            rec_mut.transition_nonce = rec_mut.transition_nonce.saturating_add(1);
        }
        Ok(())
    }

    /// Validate whether `record_id` may move to `target`; explicitly rejects any
    /// attempt to move `K1Public` back into `K2/K3/K4`.
    ///
    /// Convenience: exposed for RPC preflight checks and policy auditing.
    pub fn check_transition_allowed(
        &self,
        record_id: &[u8; 32],
        target: DataPrivacyLayer,
    ) -> Result<(), DataLayerError> {
        let rec = self
            .records
            .get(record_id)
            .ok_or(DataLayerError::UnknownRecord)?;
        if rec.layer == DataPrivacyLayer::K1Public && target != DataPrivacyLayer::K1Public {
            return Err(DataLayerError::IrreversiblePublicExposure);
        }
        if !rec.layer.can_transition_to(target) {
            return Err(DataLayerError::ForbiddenTransition {
                from: rec.layer,
                to: target,
            });
        }
        Ok(())
    }

    /// Deterministic length-prefixed `SHA3-256` commitment over the registry.
    ///
    /// Convenience: exposed for privacy subtree state-root anchoring.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        update_lp_sha3(&mut h, DOMAIN_PRIVACY_LAYER_ROOT);
        h.update(self.chain_id.to_le_bytes());
        h.update((self.records.len() as u64).to_le_bytes());
        for (id, r) in &self.records {
            h.update(id);
            h.update([r.layer.code()]);
            h.update(r.commitment);
            h.update(r.declared_byte_len.to_le_bytes());
            h.update(r.owner_pk_digest);
            h.update([u8::from(r.stealth_tag.is_some())]);
            h.update(r.stealth_tag.unwrap_or([0u8; 32]));
            h.update([u8::from(r.offchain_locator_hash.is_some())]);
            h.update(r.offchain_locator_hash.unwrap_or([0u8; 32]));
            h.update((r.active_grant_tags.len() as u64).to_le_bytes());
            for tag in &r.active_grant_tags {
                h.update(tag);
            }
            h.update([u8::from(r.disclosed_plaintext.is_some())]);
            if let Some(ref pt) = r.disclosed_plaintext {
                update_lp_sha3(&mut h, pt);
            }
            h.update(r.transition_nonce.to_le_bytes());
        }
        h.finalize().into()
    }

    fn ensure_insertable(&self, record_id: &[u8; 32]) -> Result<(), DataLayerError> {
        if self.records.contains_key(record_id) {
            return Err(DataLayerError::DuplicateRecord);
        }
        if self.records.len() >= MAX_LAYERED_RECORDS {
            return Err(DataLayerError::RegistryFull {
                max: MAX_LAYERED_RECORDS,
            });
        }
        Ok(())
    }
}

fn hash_valid_owner_pk(pk: &[u8]) -> Result<[u8; 32], DataLayerError> {
    validate_public_key(SchemeId::ML_DSA_65, pk).map_err(|_| DataLayerError::InvalidOwnerKey)?;
    Ok(Sha3_256::digest(pk).into())
}

fn verify_owner_auth(
    expected_chain_id: u64,
    rec: &LayeredDataRecord,
    target_layer: DataPrivacyLayer,
    action_binding: &[u8; 32],
    auth: &LayerOwnerAuth,
) -> Result<(), DataLayerError> {
    if auth.chain_id != expected_chain_id || auth.nonce != rec.transition_nonce {
        return Err(DataLayerError::ReplayOrChainMismatch);
    }
    let pk_digest = hash_valid_owner_pk(&auth.owner_ml_dsa_65_pk)?;
    if !bool::from(pk_digest.ct_eq(&rec.owner_pk_digest)) {
        return Err(DataLayerError::InvalidOwnerKey);
    }
    let digest = layer_transition_digest(
        expected_chain_id,
        &rec.record_id,
        rec.transition_nonce,
        rec.layer,
        target_layer,
        action_binding,
    );
    let registry = SchemeStatusRegistry::genesis();
    verify_in(
        &registry,
        SchemeId::ML_DSA_65,
        &auth.owner_ml_dsa_65_pk,
        &digest,
        PRIVATE_TRANSFER_V1,
        &auth.signature,
    )
    .map_err(|_| DataLayerError::InvalidOwnerSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::{ml_dsa_public_key, ml_dsa_sign};

    const CHAIN_ID: u64 = 45_261;

    fn sign_auth(
        seed: &[u8; 32],
        pk: &[u8],
        chain_id: u64,
        record_id: &[u8; 32],
        nonce: u64,
        from: DataPrivacyLayer,
        to: DataPrivacyLayer,
        binding: &[u8; 32],
    ) -> LayerOwnerAuth {
        let digest = layer_transition_digest(chain_id, record_id, nonce, from, to, binding);
        let sig = ml_dsa_sign(
            SchemeId::ML_DSA_65,
            seed,
            &digest,
            PRIVATE_TRANSFER_V1,
            &[0u8; 32],
        )
        .unwrap();
        LayerOwnerAuth {
            chain_id,
            nonce,
            owner_ml_dsa_65_pk: pk.to_vec(),
            signature: sig,
        }
    }

    #[test]
    fn k3_default_private_grants_k2_stealth_k1_verified_reveal_and_irreversibility() {
        let seed = [0x42u8; 32];
        let pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).unwrap();
        let other_seed = [0x99u8; 32];
        let other_pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &other_seed).unwrap();

        let mut reg = DataLayerRegistry::new(CHAIN_ID).unwrap();
        let record_id = [0x11; 32];
        let salt = [0x22; 32];
        let secret = b"medical-genome-summary:patient-zero-knowledge";
        let secret_digest: [u8; 32] = Sha3_256::digest(secret).into();
        let commitment =
            compute_layer_commitment(&record_id, &salt, &secret_digest, secret.len() as u64);

        // 1. Default registration enters K3Confidential with ZERO plaintext on chain.
        let created = reg
            .register_confidential_default(record_id, commitment, secret.len() as u64, &pk)
            .unwrap();
        assert_eq!(created.layer, DataPrivacyLayer::K3Confidential);
        assert!(created.disclosed_plaintext.is_none());
        assert!(created.stealth_tag.is_none());

        // 2. Owner issues selective view-grant in K3; attacker key is refused.
        let grant_tag = [0x55; 32];
        let bad_auth = sign_auth(
            &other_seed,
            &other_pk,
            CHAIN_ID,
            &record_id,
            0,
            DataPrivacyLayer::K3Confidential,
            DataPrivacyLayer::K3Confidential,
            &grant_tag,
        );
        assert_eq!(
            reg.issue_confidential_grant(&record_id, grant_tag, &bad_auth),
            Err(DataLayerError::InvalidOwnerKey)
        );
        let grant_auth = sign_auth(
            &seed,
            &pk,
            CHAIN_ID,
            &record_id,
            0,
            DataPrivacyLayer::K3Confidential,
            DataPrivacyLayer::K3Confidential,
            &grant_tag,
        );
        reg.issue_confidential_grant(&record_id, grant_tag, &grant_auth)
            .unwrap();
        // Replay of nonce 0 is refused.
        assert_eq!(
            reg.issue_confidential_grant(&record_id, [0x56; 32], &grant_auth),
            Err(DataLayerError::ReplayOrChainMismatch)
        );

        // 3. Controlled transition K3 -> K2 attaches unlinkable stealth handle, still zero plaintext.
        let stealth_salt = [0x33; 32];
        let pk_digest: [u8; 32] = Sha3_256::digest(&pk).into();
        let expected_stealth = derive_stealth_owner_tag(&pk_digest, &stealth_salt);
        let k2_auth = sign_auth(
            &seed,
            &pk,
            CHAIN_ID,
            &record_id,
            1,
            DataPrivacyLayer::K3Confidential,
            DataPrivacyLayer::K2Pseudonymous,
            &expected_stealth,
        );
        let tag = reg
            .transition_to_pseudonymous(&record_id, &stealth_salt, &k2_auth)
            .unwrap();
        assert_eq!(tag, expected_stealth);
        assert!(reg
            .record(&record_id)
            .unwrap()
            .disclosed_plaintext
            .is_none());

        // 4. Bait-and-switch reveal (wrong plaintext of exact same length) fails closed!
        let fake = vec![b'X'; secret.len()];
        let fake_digest: [u8; 32] = Sha3_256::digest(&fake).into();
        let fake_auth = sign_auth(
            &seed,
            &pk,
            CHAIN_ID,
            &record_id,
            2,
            DataPrivacyLayer::K2Pseudonymous,
            DataPrivacyLayer::K1Public,
            &fake_digest,
        );
        assert_eq!(
            reg.declassify_to_public(&record_id, fake, Some(&salt), &fake_auth),
            Err(DataLayerError::CommitmentOpeningMismatch)
        );

        // 5. Honest K2 -> K1 declassification succeeds and verifies commitment.
        let k1_auth = sign_auth(
            &seed,
            &pk,
            CHAIN_ID,
            &record_id,
            2,
            DataPrivacyLayer::K2Pseudonymous,
            DataPrivacyLayer::K1Public,
            &secret_digest,
        );
        reg.declassify_to_public(&record_id, secret.to_vec(), Some(&salt), &k1_auth)
            .unwrap();
        assert_eq!(
            reg.record(&record_id)
                .unwrap()
                .disclosed_plaintext
                .as_deref(),
            Some(secret.as_slice())
        );

        // 6. K1 -> K3 "re-hiding" is refused honestly (public block history is immutable).
        assert_eq!(
            reg.check_transition_allowed(&record_id, DataPrivacyLayer::K3Confidential),
            Err(DataLayerError::IrreversiblePublicExposure)
        );
    }

    #[test]
    fn k4_offchain_anchor_stores_zero_payload_and_verifies_exact_sha3_reveal() {
        let seed = [0x77u8; 32];
        let pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).unwrap();
        let mut reg = DataLayerRegistry::new(CHAIN_ID).unwrap();
        let root_empty = reg.state_root();

        let record_id = [0x81; 32];
        let offchain_blob = b"bud3://dataset-epoch-19-verified-weights";
        let digest: [u8; 32] = Sha3_256::digest(offchain_blob).into();
        let locator = [0x82; 32];
        let rec = reg
            .register_offchain_anchor(record_id, digest, offchain_blob.len() as u64, locator, &pk)
            .unwrap();
        assert_eq!(rec.layer, DataPrivacyLayer::K4OffChainAnchored);
        assert_eq!(rec.offchain_locator_hash, Some(locator));
        assert!(rec.disclosed_plaintext.is_none());
        assert_ne!(reg.state_root(), root_empty);

        let auth = sign_auth(
            &seed,
            &pk,
            CHAIN_ID,
            &record_id,
            0,
            DataPrivacyLayer::K4OffChainAnchored,
            DataPrivacyLayer::K1Public,
            &digest,
        );
        reg.declassify_to_public(&record_id, offchain_blob.to_vec(), None, &auth)
            .unwrap();
        assert_eq!(
            reg.record(&record_id).unwrap().layer,
            DataPrivacyLayer::K1Public
        );
    }
}
