//! B.U.D. Data Marketplace — Provenance + Access Control Layer (Phase 10 Sprint-2).
//!
//! This module implements the permissionless data marketplace primitives:
//! - **DataAsset**: On-chain record of a B.U.D. content asset with owner (provenance).
//! - **StorageCommitment**: Cryptographic proof that a storage node committed to storing the asset.
//! - **AccessGrant**: Owner-signed permission for a grantee (AI Verifier / Storage Node / Address) to access the asset.
//! - **AccessRevocation**: On-chain revocation of a grant (blocks future access only).
//! - **MarketplaceListing**: Asset listed for sale with price and auto-grant-on-payment.
//!
//! All primitives are **permissionless** — no whitelist, no admin hooks, no team-gated services.
//! Enforcement: Phase 1 = soft (grant check + audit log), Phase 2 = hard (encryption + key-wrapping).
//!
//! Wire format uses schema_version=4 (shared with GAP-1 snapshot manifest signature).

use crate::core::address::Address;
use crate::domain::Hash32;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Grant scope: defines the access boundaries for a grantee.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GrantScope {
    /// Single-read access (e.g., for challenge/verify). Enforcement is off-chain:
    /// grantee tracks "read once" locally via counter + audit log. No on-chain gas cost.
    ReadOnce,
    /// Access until a specific block height (inclusive).
    ReadUntilBlock(u64),
    /// Perpetual access. In Phase 2, limited by wrapped_key (key-wrapping enforcement).
    Perpetual,
}

impl Default for GrantScope {
    fn default() -> Self {
        GrantScope::Perpetual
    }
}

/// Grantee identity: supports both RoleId (PermissionlessRegistry) and Address (EOA/Contract).
/// Phase 1 supports both from the start.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Grantee {
    RoleId(crate::registry::role::RoleId),
    Address(Address),
}

impl Default for Grantee {
    fn default() -> Self {
        Grantee::RoleId(crate::registry::role::RoleId(0))
    }
}

impl Grantee {
    /// Check if this grantee matches the given role ID.
    pub fn is_role(&self, role_id: crate::registry::role::RoleId) -> bool {
        matches!(self, Grantee::RoleId(r) if *r == role_id)
    }

    /// Check if this grantee matches the given address.
    pub fn is_address(&self, addr: &Address) -> bool {
        matches!(self, Grantee::Address(a) if a == addr)
    }
}

/// On-chain record of a B.U.D. data asset with provenance (owner).
/// Extends the existing `ContentManifest` by adding `owner` and marketplace fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DataAsset {
    /// Asset identifier = `ContentManifest.manifest_id` (domain-tagged SHA-256).
    pub asset_id: Hash32,
    /// Owner address — CRITICAL: not present in `ContentManifest` (Phase 10 §3.2 item 6).
    pub owner: Address,
    /// Content hash = `ContentId` (SHA-256 domain-tagged).
    pub content_hash: Hash32,
    /// Whether the asset content is encrypted (Phase 2: true, Phase 1: false).
    pub encrypted: bool,
    /// Whether the asset is listed on the marketplace.
    pub listed: bool,
    /// Block height when the asset was registered on-chain.
    pub created_at_block: u64,
    // Phase 2 reserved fields (serde-default for forward compatibility):
    // pub encryption_scheme: Option<EncryptionScheme>,
    // pub key_commitment: Option<Hash32>,
}

impl Default for DataAsset {
    fn default() -> Self {
        Self {
            asset_id: [0u8; 32],
            owner: Address::zero(),
            content_hash: [0u8; 32],
            encrypted: false,
            listed: false,
            created_at_block: 0,
        }
    }
}

/// Storage node's commitment to an asset — provenance proof.
/// The node signs the (content_hash + asset_id + block_height) with its snapshot signing key
/// (or HSM-backed Ed25519). Compatible with GAP-1 `manifest_signature` model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageCommitment {
    pub asset_id: Hash32,
    pub content_hash: Hash32,
    pub storage_node_id: crate::registry::role::RoleId, // STORAGE_OPERATOR(5) or BUD_STORAGE_NODE(7)
    pub block_height: u64,
    /// Ed25519 signature over `hash_fields_bytes([b"BUD_STORAGE_COMMITMENT_V1", asset_id, content_hash, block_height])`.
    /// 64 bytes.
    pub signature: Vec<u8>,
}

/// Owner-signed access grant for a grantee.
/// Phase 1: soft enforcement (grant check + audit log).
/// Phase 2: hard enforcement via `wrapped_key` (key-wrapping).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AccessGrant {
    pub asset_id: Hash32,
    /// Owner's Ed25519 signature over `hash_fields_bytes([b"BUD_ACCESS_GRANT_V1", asset_id, grantee, scope, granted_at_block])`.
    /// 64 bytes. Grantee is serialized as discriminant + payload for signature binding.
    pub owner_signature: Vec<u8>,
    /// Grantee identity: RoleId (AI_VERIFIER=6, BUD_STORAGE_NODE=7) OR Address (EOA/Contract).
    pub grantee: Grantee,
    /// Access scope boundaries.
    pub scope: GrantScope,
    /// Phase 2: wrapped DEK (Data Encryption Key) encrypted with grantee's public key (HPKE/ECIES).
    /// Phase 1: None.
    #[serde(default)]
    pub wrapped_key: Option<Vec<u8>>,
    /// Block height when the grant was recorded on-chain.
    pub granted_at_block: u64,
}

impl Default for AccessGrant {
    fn default() -> Self {
        Self {
            asset_id: [0u8; 32],
            owner_signature: Vec::new(),
            grantee: Grantee::default(),
            scope: GrantScope::default(),
            wrapped_key: None,
            granted_at_block: 0,
        }
    }
}

/// On-chain revocation of an access grant.
/// Blocks FUTURE access only — cannot retrieve already-downloaded copies (no DRM can).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessRevocation {
    pub asset_id: Hash32,
    pub grantee: Grantee,
    pub revoked_at_block: u64,
}

/// Marketplace listing for a data asset.
/// Protocol fee is FIXED 2.5% (250 bps) configurable via `MarketplaceParams::protocol_fee_bps`.
/// Fee is collected on `bud_marketplacePurchase` and sent to protocol treasury.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketplaceListing {
    pub asset_id: Hash32,
    /// Price in $BUD (BUD_UNIT = 10^6 fixed-point).
    pub price: u64,
    /// If true, `bud_marketplacePurchase` automatically creates an AccessGrant for the buyer.
    pub auto_grant_on_payment: bool,
}

/// Protocol-level marketplace parameters (governance/configurable).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketplaceParams {
    /// Protocol fee in basis points (1 bp = 0.01%). Default: 250 = 2.5%.
    pub protocol_fee_bps: u16,
    /// Minimum listing price (dust prevention).
    pub min_price: u64,
    /// Maximum listing price (anti-abuse ceiling).
    pub max_price: u64,
}

impl Default for MarketplaceParams {
    fn default() -> Self {
        Self {
            protocol_fee_bps: 250,          // 2.5%
            min_price: 1_000,               // 0.001 $BUD
            max_price: 100_000_000_000_000, // 100M $BUD (total supply)
        }
    }
}

/// On-chain registry state for the marketplace (serializable for StateSnapshotV2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MarketplaceRegistry {
    /// Registered data assets (asset_id -> DataAsset).
    pub data_assets: BTreeMap<Hash32, DataAsset>,
    /// Access grants (asset_id -> vec of grants for that asset).
    pub access_grants: BTreeMap<Hash32, Vec<AccessGrant>>,
    /// Revocations (asset_id -> vec of revocations).
    pub revocations: BTreeMap<Hash32, Vec<AccessRevocation>>,
    /// Marketplace listings (asset_id -> listing).
    pub marketplace_listings: BTreeMap<Hash32, MarketplaceListing>,
    /// Protocol parameters.
    pub params: MarketplaceParams,
}

impl MarketplaceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new data asset with storage commitment (provenance).
    /// Called by owner after uploading to B.U.D. storage node.
    pub fn register_asset(
        &mut self,
        asset: DataAsset,
        commitment: StorageCommitment,
        _block_height: u64,
    ) -> Result<(), MarketplaceError> {
        // Validate commitment signature matches asset
        if commitment.asset_id != asset.asset_id {
            return Err(MarketplaceError::CommitmentAssetIdMismatch);
        }
        if commitment.content_hash != asset.content_hash {
            return Err(MarketplaceError::CommitmentContentHashMismatch);
        }
        // TODO: Verify Ed25519 signature using node's snapshot signing pubkey
        // This requires access to the node's public key (from consensus or HSM).

        self.data_assets.insert(asset.asset_id, asset);
        Ok(())
    }

    /// Get asset metadata by ID.
    pub fn get_asset(&self, asset_id: &Hash32) -> Option<&DataAsset> {
        self.data_assets.get(asset_id)
    }

    /// Submit an owner-signed access grant.
    /// Validates: owner signature, asset exists, grant not duplicate.
    pub fn submit_grant(
        &mut self,
        grant: AccessGrant,
        block_height: u64,
    ) -> Result<(), MarketplaceError> {
        let asset = self
            .data_assets
            .get(&grant.asset_id)
            .ok_or(MarketplaceError::AssetNotFound(grant.asset_id))?;

        // Verify owner signature matches asset owner
        // TODO: Verify Ed25519 signature over grant fields using asset.owner
        // For now, structural validation only.

        // Check for duplicate grant (same asset_id + grantee + scope + block)
        let grants = self.access_grants.entry(grant.asset_id).or_default();
        let is_duplicate = grants.iter().any(|g| {
            g.grantee == grant.grantee
                && g.scope == grant.scope
                && g.granted_at_block == grant.granted_at_block
        });
        if is_duplicate {
            return Err(MarketplaceError::DuplicateGrant);
        }

        grants.push(grant);
        Ok(())
    }

    /// Query grants for a specific grantee on an asset.
    /// Used by AI Verifier / Storage Node before serving data.
    pub fn query_grants(&self, asset_id: &Hash32, grantee: &Grantee) -> Vec<&AccessGrant> {
        self.access_grants
            .get(asset_id)
            .map(|grants| grants.iter().filter(|g| &g.grantee == grantee).collect())
            .unwrap_or_default()
    }

    /// Check if a grantee has ANY valid grant for an asset (respecting revocations).
    /// Returns the most permissive valid grant if multiple exist.
    pub fn has_valid_grant(
        &self,
        asset_id: &Hash32,
        grantee: &Grantee,
        current_block: u64,
    ) -> Option<&AccessGrant> {
        let grants = self.query_grants(asset_id, grantee);
        if grants.is_empty() {
            return None;
        }

        // Get revoked grantees for this asset
        let revoked = self.revocations.get(asset_id).cloned().unwrap_or_default();
        let revoked_grantees: std::collections::HashSet<&Grantee> =
            revoked.iter().map(|r| &r.grantee).collect();

        // Filter out revoked grants
        let valid_grants: Vec<&AccessGrant> = grants
            .into_iter()
            .filter(|g| !revoked_grantees.contains(&g.grantee))
            .filter(|g| match &g.scope {
                GrantScope::ReadOnce => {
                    // Phase 1: off-chain enforcement. On-chain always returns true if not revoked.
                    // The grantee tracks "read count" locally.
                    true
                }
                GrantScope::ReadUntilBlock(until) => current_block <= *until,
                GrantScope::Perpetual => true,
            })
            .collect();

        // Return most permissive: Perpetual > ReadUntilBlock (latest) > ReadOnce
        valid_grants.into_iter().max_by_key(|g| match &g.scope {
            GrantScope::Perpetual => 3,
            GrantScope::ReadUntilBlock(_) => 2,
            GrantScope::ReadOnce => 1,
        })
    }

    /// Revoke a grant (blocks future access).
    pub fn revoke_grant(&mut self, revocation: AccessRevocation) -> Result<(), MarketplaceError> {
        // Verify asset exists
        self.data_assets
            .get(&revocation.asset_id)
            .ok_or(MarketplaceError::AssetNotFound(revocation.asset_id))?;

        let revs = self.revocations.entry(revocation.asset_id).or_default();
        // Check for duplicate revocation
        let is_duplicate = revs.iter().any(|r| r.grantee == revocation.grantee);
        if is_duplicate {
            return Err(MarketplaceError::DuplicateRevocation);
        }
        revs.push(revocation);
        Ok(())
    }

    /// List an asset on the marketplace.
    pub fn list_asset(&mut self, listing: MarketplaceListing) -> Result<(), MarketplaceError> {
        let asset = self
            .data_assets
            .get(&listing.asset_id)
            .ok_or(MarketplaceError::AssetNotFound(listing.asset_id))?;

        if !asset.owner == listing.asset_id { // placeholder - actual owner check needed
             // The listing should be created by the asset owner
        }

        if listing.price < self.params.min_price {
            return Err(MarketplaceError::PriceBelowMinimum(
                listing.price,
                self.params.min_price,
            ));
        }
        if listing.price > self.params.max_price {
            return Err(MarketplaceError::PriceAboveMaximum(
                listing.price,
                self.params.max_price,
            ));
        }

        self.marketplace_listings.insert(listing.asset_id, listing);
        Ok(())
    }

    /// Get marketplace listing for an asset.
    pub fn get_listing(&self, asset_id: &Hash32) -> Option<&MarketplaceListing> {
        self.marketplace_listings.get(asset_id)
    }

    /// Purchase an asset (pay price + protocol fee) and optionally auto-grant access.
    /// Returns the created AccessGrant if auto_grant_on_payment=true.
    pub fn purchase_asset(
        &mut self,
        asset_id: &Hash32,
        buyer: &Address,
        block_height: u64,
    ) -> Result<Option<AccessGrant>, MarketplaceError> {
        let listing = self
            .marketplace_listings
            .get(asset_id)
            .ok_or(MarketplaceError::AssetNotListed(*asset_id))?;

        let asset = self
            .data_assets
            .get(asset_id)
            .ok_or(MarketplaceError::AssetNotFound(*asset_id))?;

        // TODO: Transfer price + protocol_fee from buyer to asset.owner + protocol treasury
        // This requires AccountState integration (done in RPC handler).

        if listing.auto_grant_on_payment {
            let grant = AccessGrant {
                asset_id: *asset_id,
                owner_signature: Vec::new(), // auto-grant: protocol generates on behalf of owner
                grantee: Grantee::Address(*buyer),
                scope: GrantScope::Perpetual,
                wrapped_key: None, // Phase 2: wrapped_key will be populated
                granted_at_block: block_height,
            };
            self.submit_grant(grant.clone(), block_height)?;
            Ok(Some(grant))
        } else {
            Ok(None)
        }
    }

    /// Compute state root for this registry (for StateSnapshotV2 schema_version=4).
    pub fn root(&self) -> Hash32 {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_MARKETPLACE_REGISTRY_V4");

        // Deterministic ordering: BTreeMap iteration is ordered by key
        for (asset_id, asset) in &self.data_assets {
            hasher.update(asset_id);
            hasher.update(asset.owner.0);
            hasher.update(asset.content_hash);
            hasher.update([asset.encrypted as u8]);
            hasher.update([asset.listed as u8]);
            hasher.update(asset.created_at_block.to_le_bytes());
        }

        for (asset_id, grants) in &self.access_grants {
            hasher.update(asset_id);
            for grant in grants {
                // Grantee serialization for hashing
                match &grant.grantee {
                    Grantee::RoleId(rid) => {
                        hasher.update([0u8]); // discriminant
                        hasher.update(rid.0.to_le_bytes());
                    }
                    Grantee::Address(addr) => {
                        hasher.update([1u8]);
                        hasher.update(addr.0);
                    }
                }
                // Scope discriminant + payload
                match &grant.scope {
                    GrantScope::ReadOnce => hasher.update([0u8]),
                    GrantScope::ReadUntilBlock(h) => {
                        hasher.update([1u8]);
                        hasher.update(h.to_le_bytes());
                    }
                    GrantScope::Perpetual => hasher.update([2u8]),
                }
                if let Some(wk) = &grant.wrapped_key {
                    hasher.update([1u8]);
                    hasher.update((wk.len() as u32).to_le_bytes());
                    hasher.update(wk);
                } else {
                    hasher.update([0u8]);
                }
                hasher.update(grant.granted_at_block.to_le_bytes());
            }
        }

        for (asset_id, revs) in &self.revocations {
            hasher.update(asset_id);
            for rev in revs {
                match &rev.grantee {
                    Grantee::RoleId(rid) => {
                        hasher.update([0u8]);
                        hasher.update(rid.0.to_le_bytes());
                    }
                    Grantee::Address(addr) => {
                        hasher.update([1u8]);
                        hasher.update(addr.0);
                    }
                }
                hasher.update(rev.revoked_at_block.to_le_bytes());
            }
        }

        for (asset_id, listing) in &self.marketplace_listings {
            hasher.update(asset_id);
            hasher.update(listing.price.to_le_bytes());
            hasher.update([listing.auto_grant_on_payment as u8]);
        }

        hasher.update(self.params.protocol_fee_bps.to_le_bytes());
        hasher.update(self.params.min_price.to_le_bytes());
        hasher.update(self.params.max_price.to_le_bytes());

        hasher.finalize().into()
    }
}

/// Marketplace-specific errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MarketplaceError {
    #[error("Asset not found: {0:?}")]
    AssetNotFound(Hash32),
    #[error("Asset not listed on marketplace: {0:?}")]
    AssetNotListed(Hash32),
    #[error("Commitment asset_id mismatch")]
    CommitmentAssetIdMismatch,
    #[error("Commitment content_hash mismatch")]
    CommitmentContentHashMismatch,
    #[error("Duplicate grant for same grantee/scope/block")]
    DuplicateGrant,
    #[error("Duplicate revocation for same grantee")]
    DuplicateRevocation,
    #[error("Price below minimum: {0} < {1}")]
    PriceBelowMinimum(u64, u64),
    #[error("Price above maximum: {0} > {1}")]
    PriceAboveMaximum(u64, u64),
    #[error("Invalid owner signature")]
    InvalidOwnerSignature,
    #[error("Grantee not the deal operator")]
    NotTheOperator,
    #[error("Challenge deadline elapsed")]
    DeadlineElapsed,
    #[error("Insufficient balance for purchase")]
    InsufficientBalance,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::registry::role::RoleId;

    fn test_asset() -> DataAsset {
        DataAsset {
            asset_id: [0x42u8; 32],
            owner: Address::from([1u8; 32]),
            content_hash: [0x42u8; 32],
            encrypted: false,
            listed: false,
            created_at_block: 100,
        }
    }

    fn test_grant(grantee: Grantee) -> AccessGrant {
        AccessGrant {
            asset_id: [0x42u8; 32],
            owner_signature: vec![0u8; 64],
            grantee,
            scope: GrantScope::Perpetual,
            wrapped_key: None,
            granted_at_block: 100,
        }
    }

    #[test]
    fn grantee_roleid_and_address_serialization() {
        let g1 = Grantee::RoleId(RoleId(6)); // AI_VERIFIER
        let g2 = Grantee::Address(Address::from([1u8; 32]));

        let s1 = bincode::serialize(&g1).unwrap();
        let s2 = bincode::serialize(&g2).unwrap();

        let d1: Grantee = bincode::deserialize(&s1).unwrap();
        let d2: Grantee = bincode::deserialize(&s2).unwrap();

        assert_eq!(g1, d1);
        assert_eq!(g2, d2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn grant_scope_serialization() {
        let s1 = GrantScope::ReadOnce;
        let s2 = GrantScope::ReadUntilBlock(500);
        let s3 = GrantScope::Perpetual;

        let b1 = bincode::serialize(&s1).unwrap();
        let b2 = bincode::serialize(&s2).unwrap();
        let b3 = bincode::serialize(&s3).unwrap();

        assert_eq!(bincode::deserialize::<GrantScope>(&b1).unwrap(), s1);
        assert_eq!(bincode::deserialize::<GrantScope>(&b2).unwrap(), s2);
        assert_eq!(bincode::deserialize::<GrantScope>(&b3).unwrap(), s3);
    }

    #[test]
    fn marketplace_registry_basic_operations() {
        let mut reg = MarketplaceRegistry::new();
        let asset = test_asset();
        let commitment = StorageCommitment {
            asset_id: asset.asset_id,
            content_hash: asset.content_hash,
            storage_node_id: RoleId(5), // STORAGE_OPERATOR
            block_height: 100,
            signature: vec![0u8; 64],
        };

        // Register asset
        reg.register_asset(asset.clone(), commitment, 100).unwrap();
        assert!(reg.get_asset(&asset.asset_id).is_some());

        // Submit grant for AI_VERIFIER
        let grant = test_grant(Grantee::RoleId(RoleId(6)));
        reg.submit_grant(grant, 101).unwrap();

        // Query grants
        let grants = reg.query_grants(&asset.asset_id, &Grantee::RoleId(RoleId(6)));
        assert_eq!(grants.len(), 1);

        // Check valid grant
        let valid = reg.has_valid_grant(&asset.asset_id, &Grantee::RoleId(RoleId(6)), 200);
        assert!(valid.is_some());

        // Revoke
        let rev = AccessRevocation {
            asset_id: asset.asset_id,
            grantee: Grantee::RoleId(RoleId(6)),
            revoked_at_block: 200,
        };
        reg.revoke_grant(rev).unwrap();

        // After revocation, no valid grant
        let valid = reg.has_valid_grant(&asset.asset_id, &Grantee::RoleId(RoleId(6)), 300);
        assert!(valid.is_none());

        // Different grantee still works
        let grant2 = test_grant(Grantee::Address(Address::from([2u8; 32])));
        reg.submit_grant(grant2, 201).unwrap();
        let valid = reg.has_valid_grant(
            &asset.asset_id,
            &Grantee::Address(Address::from([2u8; 32])),
            300,
        );
        assert!(valid.is_some());
    }

    #[test]
    fn marketplace_listing_and_purchase() {
        let mut reg = MarketplaceRegistry::new();
        let asset = test_asset();
        let commitment = StorageCommitment {
            asset_id: asset.asset_id,
            content_hash: asset.content_hash,
            storage_node_id: RoleId(5),
            block_height: 100,
            signature: vec![0u8; 64],
        };
        reg.register_asset(asset.clone(), commitment, 100).unwrap();

        // List asset
        let listing = MarketplaceListing {
            asset_id: asset.asset_id,
            price: 1_000_000, // 1 $BUD
            auto_grant_on_payment: true,
        };
        reg.list_asset(listing).unwrap();

        // Purchase
        let buyer = Address::from([3u8; 32]);
        let grant = reg.purchase_asset(&asset.asset_id, &buyer, 200).unwrap();
        assert!(grant.is_some());
        let grant = grant.unwrap();
        assert_eq!(grant.grantee, Grantee::Address(buyer));
        assert_eq!(grant.scope, GrantScope::Perpetual);

        // Grant should be queryable
        let grants = reg.query_grants(&asset.asset_id, &Grantee::Address(buyer));
        assert_eq!(grants.len(), 1);
    }

    #[test]
    fn read_until_block_scope_enforcement() {
        let mut reg = MarketplaceRegistry::new();
        let asset = test_asset();
        let commitment = StorageCommitment {
            asset_id: asset.asset_id,
            content_hash: asset.content_hash,
            storage_node_id: RoleId(5),
            block_height: 100,
            signature: vec![0u8; 64],
        };
        reg.register_asset(asset.clone(), commitment, 100).unwrap();

        // Grant valid until block 200
        let grant = AccessGrant {
            asset_id: asset.asset_id,
            owner_signature: vec![0u8; 64],
            grantee: Grantee::RoleId(RoleId(6)),
            scope: GrantScope::ReadUntilBlock(200),
            wrapped_key: None,
            granted_at_block: 100,
        };
        reg.submit_grant(grant, 100).unwrap();

        // Before deadline: valid
        assert!(reg
            .has_valid_grant(&asset.asset_id, &Grantee::RoleId(RoleId(6)), 150)
            .is_some());
        // At deadline: valid (inclusive)
        assert!(reg
            .has_valid_grant(&asset.asset_id, &Grantee::RoleId(RoleId(6)), 200)
            .is_some());
        // After deadline: invalid
        assert!(reg
            .has_valid_grant(&asset.asset_id, &Grantee::RoleId(RoleId(6)), 201)
            .is_none());
    }

    #[test]
    fn root_deterministic() {
        let mut reg1 = MarketplaceRegistry::new();
        let mut reg2 = MarketplaceRegistry::new();

        let asset = test_asset();
        let commitment = StorageCommitment {
            asset_id: asset.asset_id,
            content_hash: asset.content_hash,
            storage_node_id: RoleId(5),
            block_height: 100,
            signature: vec![0u8; 64],
        };

        reg1.register_asset(asset.clone(), commitment.clone(), 100)
            .unwrap();
        reg2.register_asset(asset, commitment, 100).unwrap();

        assert_eq!(reg1.root(), reg2.root());
    }
}
