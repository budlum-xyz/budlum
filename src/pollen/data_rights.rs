//! Pollen Data Rights — AccessGrant v2 primitives (ARENA4 ADIM 1).
//!
//! Kullanıcı metaforu: veri tomurcuğu kullanıcıya aittir; satılan şey tomurcuğun
//! kendisi değil, o tomurcuğun polenidir. Bu modül bu nedenle `DataAsset` +
//! `AccessGrant` + AI input-ref gate üçlüsünü tanımlar.
//!
//! Güvenlik kuralı: Pollen/B.U.D. verisine işaret eden AI input_ref, geçerli
//! AccessGrant olmadan kabul edilemez. DAO/admin override yoktur.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{AssetId, GrantId, Signature64};

/// AI input_ref prefix'i. Bu prefix ile başlayan payload'lar Pollen data-ref
/// sayılır ve strict AccessGrant kontrolünden geçmek zorundadır.
pub const POLLEN_AI_INPUT_REF_PREFIX: &[u8] = b"BDLM_POLLEN_AI_INPUT_REF_V1";

/// DataAsset lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataAssetStatus {
    Active,
    Revoked,
}

impl Default for DataAssetStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Kullanıcının satılabilir veri varlığı. Varlık satılmaz; erişim poleni
/// AccessGrant ile satılır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAsset {
    pub asset_id: AssetId,
    pub owner: Address,
    pub manifest_id: ContentId,
    pub metadata_commitment: [u8; 32],
    pub encrypted: bool,
    #[serde(default)]
    pub status: DataAssetStatus,
}

impl DataAsset {
    pub fn new(
        owner: Address,
        manifest_id: ContentId,
        metadata_commitment: [u8; 32],
        encrypted: bool,
    ) -> Self {
        let asset_id = Self::derive_id(&owner, &manifest_id, &metadata_commitment);
        Self {
            asset_id,
            owner,
            manifest_id,
            metadata_commitment,
            encrypted,
            status: DataAssetStatus::Active,
        }
    }

    pub fn derive_id(
        owner: &Address,
        manifest_id: &ContentId,
        metadata_commitment: &[u8; 32],
    ) -> AssetId {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_DATA_ASSET_V1");
        hasher.update(owner.as_bytes());
        hasher.update(manifest_id.0);
        hasher.update(metadata_commitment);
        AssetId(hasher.finalize().into())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.asset_id == AssetId::zero() {
            return Err("DataAsset asset_id cannot be zero".into());
        }
        if self.owner == Address::zero() {
            return Err("DataAsset owner cannot be zero".into());
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.status == DataAssetStatus::Active
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_DATA_ASSET_LEAF_V1");
        hasher.update(self.asset_id.0);
        hasher.update(self.owner.as_bytes());
        hasher.update(self.manifest_id.0);
        hasher.update(self.metadata_commitment);
        hasher.update([u8::from(self.encrypted)]);
        hasher.update([match self.status {
            DataAssetStatus::Active => 1,
            DataAssetStatus::Revoked => 2,
        }]);
        hasher.finalize().into()
    }
}

/// AccessGrant lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessGrantStatus {
    Active,
    Revoked,
}

impl Default for AccessGrantStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Owner-imzalı veri erişim izni. `grantee`, veri polenini satın alan AI ajanı
/// veya kullanıcıdır. `max_reads` on-chain okuma tüketim sınırıdır.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessGrant {
    pub grant_id: GrantId,
    pub asset_id: AssetId,
    pub owner: Address,
    pub grantee: Address,
    pub payer: Address,
    pub price_paid: u64,
    pub issued_at_block: u64,
    pub expires_at_block: u64,
    pub max_reads: u32,
    #[serde(default)]
    pub reads_used: u32,
    pub purpose_hash: [u8; 32],
    #[serde(default)]
    pub status: AccessGrantStatus,
    pub owner_signature: Signature64,
}

impl AccessGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        asset_id: AssetId,
        owner: Address,
        grantee: Address,
        payer: Address,
        price_paid: u64,
        issued_at_block: u64,
        expires_at_block: u64,
        max_reads: u32,
        purpose_hash: [u8; 32],
    ) -> Self {
        let grant_id = Self::derive_id(
            &asset_id,
            &owner,
            &grantee,
            &payer,
            price_paid,
            issued_at_block,
            expires_at_block,
            max_reads,
            &purpose_hash,
        );
        Self {
            grant_id,
            asset_id,
            owner,
            grantee,
            payer,
            price_paid,
            issued_at_block,
            expires_at_block,
            max_reads,
            reads_used: 0,
            purpose_hash,
            status: AccessGrantStatus::Active,
            owner_signature: Signature64::SENTINEL,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive_id(
        asset_id: &AssetId,
        owner: &Address,
        grantee: &Address,
        payer: &Address,
        price_paid: u64,
        issued_at_block: u64,
        expires_at_block: u64,
        max_reads: u32,
        purpose_hash: &[u8; 32],
    ) -> GrantId {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_ACCESS_GRANT_V1");
        hasher.update(asset_id.0);
        hasher.update(owner.as_bytes());
        hasher.update(grantee.as_bytes());
        hasher.update(payer.as_bytes());
        hasher.update(price_paid.to_le_bytes());
        hasher.update(issued_at_block.to_le_bytes());
        hasher.update(expires_at_block.to_le_bytes());
        hasher.update(max_reads.to_le_bytes());
        hasher.update(purpose_hash);
        AssetId(hasher.finalize().into())
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.grant_id == GrantId::zero() {
            return Err("AccessGrant grant_id cannot be zero".into());
        }
        if self.asset_id == AssetId::zero() {
            return Err("AccessGrant asset_id cannot be zero".into());
        }
        if self.owner == Address::zero()
            || self.grantee == Address::zero()
            || self.payer == Address::zero()
        {
            return Err("AccessGrant addresses cannot be zero".into());
        }
        if self.expires_at_block <= self.issued_at_block {
            return Err("AccessGrant expires_at_block must be after issued_at_block".into());
        }
        if self.max_reads == 0 {
            return Err("AccessGrant max_reads must be >= 1".into());
        }
        if self.owner_signature.is_sentinel() {
            return Err("AccessGrant owner_signature sentinel is invalid".into());
        }
        let expected = Self::derive_id(
            &self.asset_id,
            &self.owner,
            &self.grantee,
            &self.payer,
            self.price_paid,
            self.issued_at_block,
            self.expires_at_block,
            self.max_reads,
            &self.purpose_hash,
        );
        if self.grant_id != expected {
            return Err("AccessGrant grant_id does not match canonical preimage".into());
        }
        Ok(())
    }

    pub fn is_active_for(&self, grantee: &Address, current_block: u64) -> bool {
        self.status == AccessGrantStatus::Active
            && &self.grantee == grantee
            && current_block <= self.expires_at_block
            && self.reads_used < self.max_reads
    }

    pub fn record_read(&mut self) -> Result<(), String> {
        if self.reads_used >= self.max_reads {
            return Err("AccessGrant read limit exhausted".into());
        }
        self.reads_used = self.reads_used.saturating_add(1);
        Ok(())
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_ACCESS_GRANT_LEAF_V1");
        hasher.update(self.grant_id.0);
        hasher.update(self.asset_id.0);
        hasher.update(self.owner.as_bytes());
        hasher.update(self.grantee.as_bytes());
        hasher.update(self.payer.as_bytes());
        hasher.update(self.price_paid.to_le_bytes());
        hasher.update(self.issued_at_block.to_le_bytes());
        hasher.update(self.expires_at_block.to_le_bytes());
        hasher.update(self.max_reads.to_le_bytes());
        hasher.update(self.reads_used.to_le_bytes());
        hasher.update(self.purpose_hash);
        hasher.update([match self.status {
            AccessGrantStatus::Active => 1,
            AccessGrantStatus::Revoked => 2,
        }]);
        hasher.update(self.owner_signature.as_bytes());
        hasher.finalize().into()
    }
}

/// Canonical reference embedded in `AiInferenceRequest.input_ref` when the
/// request wants to read a Pollen/B.U.D. DataAsset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiDataInputRef {
    pub asset_id: AssetId,
    pub grant_id: GrantId,
}

impl AiDataInputRef {
    pub const ENCODED_LEN: usize = POLLEN_AI_INPUT_REF_PREFIX.len() + 32 + 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(POLLEN_AI_INPUT_REF_PREFIX);
        out.extend_from_slice(&self.asset_id.0);
        out.extend_from_slice(&self.grant_id.0);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, String> {
        if !bytes.starts_with(POLLEN_AI_INPUT_REF_PREFIX) {
            return Ok(None);
        }
        if bytes.len() != Self::ENCODED_LEN {
            return Err(format!(
                "Malformed Pollen AI input_ref: expected {} bytes, got {}",
                Self::ENCODED_LEN,
                bytes.len()
            ));
        }
        let mut asset = [0u8; 32];
        let mut grant = [0u8; 32];
        let offset = POLLEN_AI_INPUT_REF_PREFIX.len();
        asset.copy_from_slice(&bytes[offset..offset + 32]);
        grant.copy_from_slice(&bytes[offset + 32..offset + 64]);
        Ok(Some(Self {
            asset_id: AssetId(asset),
            grant_id: AssetId(grant),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    #[test]
    fn data_asset_id_is_deterministic() {
        let cid = ContentId::of(b"bud-data");
        let asset = DataAsset::new(addr(1), cid, [9u8; 32], true);
        assert_eq!(
            asset.asset_id,
            DataAsset::derive_id(&addr(1), &cid, &[9u8; 32])
        );
        assert!(asset.validate().is_ok());
    }

    #[test]
    fn access_grant_sentinel_signature_rejected() {
        let grant = AccessGrant::new_unsigned(
            AssetId::from([3u8; 32]),
            addr(1),
            addr(2),
            addr(2),
            10,
            1,
            10,
            1,
            [7u8; 32],
        );
        assert!(grant.validate_shape().unwrap_err().contains("sentinel"));
    }

    #[test]
    fn ai_data_input_ref_roundtrip_and_malformed() {
        let reference = AiDataInputRef {
            asset_id: AssetId::from([4u8; 32]),
            grant_id: GrantId::from([5u8; 32]),
        };
        let encoded = reference.encode();
        assert_eq!(AiDataInputRef::decode(&encoded).unwrap(), Some(reference));
        assert_eq!(AiDataInputRef::decode(b"plain prompt").unwrap(), None);
        let mut malformed = POLLEN_AI_INPUT_REF_PREFIX.to_vec();
        malformed.push(1);
        assert!(AiDataInputRef::decode(&malformed).is_err());
    }
}
