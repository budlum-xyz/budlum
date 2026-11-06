//! B.U.D. 3.0 Data Market listings, grant-backed settlement, AI read references,
//! and `bud_dataMarket*` RPC dispatch (Section 5.6, WP-23, BLG-064).
//! exposed for Data Market RPC endpoints, settlement execution, and AI input verification.
//!
//! * Every listed asset is addressed by its B.U.D. 3.0 [`ContentId`] and
//!   `object_commitment` ([`ObjectKey`]), bound to `chain_id` and `price_bud_atoms`.
//! * Purchasing an asset issues an unlinkable B.U.D. 3.0 [`GrantRow`] via
//!   `bud3::grants::build_grant_row` and [`Bud3Registry::issue_grant`], sealing
//!   the object's key package to the buyer's X-Wing (`0x647a`) public key.
//! * AI read references (`AiContentInputRef`) bind the identical [`ContentId`]
//!   and unlinkable `grant_tag`.
//! * Only `bud_dataMarket*` RPC method names are accepted; legacy names are
//!   refused.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::core::address::Address;
use crate::storage::bud3::content_ref::ContentRef;
use crate::storage::bud3::grants::{build_grant_row, GrantBuildError, GrantRow};
use crate::storage::bud3::keys::{seal_key_package_xwing, ObjectKeyPackage, XWingPublicKey};
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey, RegistryError};
use crate::storage::bud3::ContentId;

/// Domain tag committing a B.U.D. 3.0 Data Market listing and receipt.
pub const DOMAIN_DATA_MARKET: &[u8] = b"BDLM_BUD3_DATA_MARKET_V1";

/// Canonical `bud_dataMarket*` RPC method table.
pub const DATA_MARKET_RPC_METHODS: &[&str] = &[
    "bud_dataMarketList",
    "bud_dataMarketGetListing",
    "bud_dataMarketPurchase",
    "bud_dataMarketAiInputRef",
];

/// Errors returned by the B.U.D. 3.0 Data Market.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataMarketError {
    /// Listing `chain_id` is zero or does not match the active chain (`BLG-064`).
    ChainIdMismatch { expected: u64, got: u64 },
    /// Price or duration is zero.
    InvalidTerms(&'static str),
    /// Referenced B.U.D. 3.0 object does not exist or its `ContentId` mismatches.
    InvalidObject,
    /// Listing id does not exist or is inactive.
    ListingNotFound,
    /// Payment attached to purchase is below the listing price (`BLG-064`).
    InsufficientPayment { required: u64, paid: u64 },
    /// Grant construction or X-Wing HPKE sealing failed.
    GrantFailed(String),
    /// Registry rejected `issue_grant`.
    Registry(RegistryError),
    /// Unknown or retired RPC method name.
    UnknownRpcMethod(String),
}

impl std::fmt::Display for DataMarketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainIdMismatch { expected, got } => {
                write!(f, "chain_id mismatch: expected {expected}, got {got}")
            }
            Self::InvalidTerms(msg) => write!(f, "invalid data market terms: {msg}"),
            Self::InvalidObject => f.write_str("invalid or mismatched B.U.D. 3.0 object"),
            Self::ListingNotFound => f.write_str("data market listing not found"),
            Self::InsufficientPayment { required, paid } => {
                write!(f, "insufficient payment: required {required}, paid {paid}")
            }
            Self::GrantFailed(msg) => write!(f, "grant build failed: {msg}"),
            Self::Registry(e) => write!(f, "bud3 registry error: {e:?}"),
            Self::UnknownRpcMethod(m) => write!(f, "unknown or retired data market RPC: {m}"),
        }
    }
}

impl std::error::Error for DataMarketError {}

/// One active B.U.D. 3.0 Data Market listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMarketListing {
    pub listing_id: u64,
    pub seller: Address,
    pub content_ref: ContentRef,
    pub object_commitment: ObjectKey,
    pub nft_id: NftId,
    pub chain_id: u64,
    pub price_bud_atoms: u64,
    pub grant_duration_blocks: u64,
    pub active: bool,
}

impl DataMarketListing {
    /// Deterministic commitment digest binding seller, `ContentId`, `chain_id`, and price.
    /// exposed for Data Market receipt verification and order signing.
    #[must_use]
    pub fn commitment_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_DATA_MARKET);
        h.update(self.listing_id.to_le_bytes());
        h.update(self.seller.as_bytes());
        h.update(self.content_ref.content_id.0);
        h.update(self.object_commitment);
        h.update(self.nft_id);
        h.update(self.chain_id.to_le_bytes());
        h.update(self.price_bud_atoms.to_le_bytes());
        h.update(self.grant_duration_blocks.to_le_bytes());
        h.finalize().into()
    }
}

/// AI read reference sharing the identical B.U.D. 3.0 [`ContentId`] and `grant_tag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiContentInputRef {
    pub content_id: ContentId,
    pub object_commitment: ObjectKey,
    pub grant_tag: [u8; 32],
    pub chain_id: u64,
}

/// Receipt returned when a Data Market purchase settles and registers a view grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMarketSaleOutcome {
    pub listing_id: u64,
    pub content_id: ContentId,
    pub grant_row: GrantRow,
    pub ai_input_ref: AiContentInputRef,
}

/// B.U.D. 3.0 Data Market registry and `bud_dataMarket*` RPC service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMarketRegistry {
    chain_id: u64,
    listings: BTreeMap<u64, DataMarketListing>,
    next_listing_id: u64,
}

impl DataMarketRegistry {
    /// Create a Data Market registry bound to `chain_id`.
    #[must_use]
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            listings: BTreeMap::new(),
            next_listing_id: 1,
        }
    }

    /// Register a B.U.D. 3.0 content listing after verifying object presence.
    /// exposed for `bud_dataMarketList` RPC and settlement callers.
    ///
    /// # Errors
    ///
    /// Returns [`DataMarketError`] if `chain_id`, price, duration, or object fails.
    pub fn list_content(
        &mut self,
        bud3: &Bud3Registry,
        seller: Address,
        content_id: ContentId,
        object_commitment: ObjectKey,
        nft_id: NftId,
        chain_id: u64,
        price_bud_atoms: u64,
        grant_duration_blocks: u64,
    ) -> Result<DataMarketListing, DataMarketError> {
        if chain_id == 0 || chain_id != self.chain_id {
            return Err(DataMarketError::ChainIdMismatch {
                expected: self.chain_id,
                got: chain_id,
            });
        }
        if price_bud_atoms == 0 {
            return Err(DataMarketError::InvalidTerms("price_bud_atoms must be > 0"));
        }
        if grant_duration_blocks == 0 {
            return Err(DataMarketError::InvalidTerms(
                "grant_duration_blocks must be > 0",
            ));
        }
        let obj = bud3
            .object(&object_commitment)
            .ok_or(DataMarketError::InvalidObject)?;
        if obj.record.content_id != content_id {
            return Err(DataMarketError::InvalidObject);
        }

        let id = self.next_listing_id;
        self.next_listing_id = self.next_listing_id.saturating_add(1);
        let listing = DataMarketListing {
            listing_id: id,
            seller,
            content_ref: ContentRef::new(content_id),
            object_commitment,
            nft_id,
            chain_id,
            price_bud_atoms,
            grant_duration_blocks,
            active: true,
        };
        self.listings.insert(id, listing.clone());
        Ok(listing)
    }

    /// Inspect a listing by `listing_id`.
    #[must_use]
    pub fn listing(&self, listing_id: u64) -> Option<&DataMarketListing> {
        self.listings.get(&listing_id)
    }

    /// Settle a purchase and issue an unlinkable B.U.D. 3.0 [`GrantRow`] (`bud3::grants`).
    /// exposed for `bud_dataMarketPurchase` RPC and settlement execution.
    ///
    /// # Errors
    ///
    /// Returns [`DataMarketError`] on chain mismatch, underpayment, or grant failure.
    #[allow(clippy::too_many_arguments)]
    pub fn settle_purchase_with_grant(
        &self,
        bud3: &mut Bud3Registry,
        listing_id: u64,
        chain_id: u64,
        paid_bud_atoms: u64,
        current_height: u64,
        grant_nonce: [u8; 32],
        one_time_public_key: Vec<u8>,
        key_package: &ObjectKeyPackage,
        buyer_xwing_pk: &XWingPublicKey,
        seal_seed: &[u8; 64],
    ) -> Result<DataMarketSaleOutcome, DataMarketError> {
        let listing = self
            .listings
            .get(&listing_id)
            .filter(|l| l.active)
            .ok_or(DataMarketError::ListingNotFound)?;
        if chain_id != listing.chain_id {
            return Err(DataMarketError::ChainIdMismatch {
                expected: listing.chain_id,
                got: chain_id,
            });
        }
        if paid_bud_atoms < listing.price_bud_atoms {
            return Err(DataMarketError::InsufficientPayment {
                required: listing.price_bud_atoms,
                paid: paid_bud_atoms,
            });
        }
        if key_package.content_id != listing.content_ref.content_id {
            return Err(DataMarketError::InvalidObject);
        }

        let capsule = seal_key_package_xwing(key_package, buyer_xwing_pk, seal_seed)
            .map_err(|e| DataMarketError::GrantFailed(e.to_string()))?;
        let expires_at_height = current_height.saturating_add(listing.grant_duration_blocks);
        let grant_row = build_grant_row(
            &listing.nft_id,
            &grant_nonce,
            one_time_public_key,
            capsule.to_bytes(),
            expires_at_height,
            current_height,
        )
        .map_err(|e: GrantBuildError| DataMarketError::GrantFailed(e.to_string()))?;

        bud3.issue_grant(grant_row.clone(), current_height)
            .map_err(DataMarketError::Registry)?;

        let ai_input_ref = AiContentInputRef {
            content_id: listing.content_ref.content_id,
            object_commitment: listing.object_commitment,
            grant_tag: grant_row.grant_tag,
            chain_id: listing.chain_id,
        };
        Ok(DataMarketSaleOutcome {
            listing_id,
            content_id: listing.content_ref.content_id,
            grant_row,
            ai_input_ref,
        })
    }

    /// Dispatch canonical `bud_dataMarket*` JSON-RPC calls and refuse retired names.
    ///
    /// # Errors
    ///
    /// Returns [`DataMarketError`] if the method name is unknown/retired or parameters fail.
    pub fn handle_rpc(
        &mut self,
        bud3: &Bud3Registry,
        method: &str,
        params: &Value,
    ) -> Result<Value, DataMarketError> {
        match method {
            "bud_dataMarketGetListing" => {
                let id = params
                    .get("listing_id")
                    .and_then(Value::as_u64)
                    .ok_or(DataMarketError::InvalidTerms("missing listing_id"))?;
                let listing = self
                    .listing(id)
                    .ok_or(DataMarketError::ListingNotFound)?;
                Ok(json!({
                    "listing_id": listing.listing_id,
                    "content_id": hex::encode(listing.content_ref.content_id.0),
                    "object_commitment": hex::encode(listing.object_commitment),
                    "price_bud_atoms": listing.price_bud_atoms,
                    "chain_id": listing.chain_id,
                    "active": listing.active,
                }))
            }
            "bud_dataMarketAiInputRef" => {
                let id = params
                    .get("listing_id")
                    .and_then(Value::as_u64)
                    .ok_or(DataMarketError::InvalidTerms("missing listing_id"))?;
                let listing = self
                    .listing(id)
                    .ok_or(DataMarketError::ListingNotFound)?;
                let has_obj = bud3.object(&listing.object_commitment).is_some();
                Ok(json!({
                    "listing_id": listing.listing_id,
                    "content_id": hex::encode(listing.content_ref.content_id.0),
                    "registered_in_bud3": has_obj,
                }))
            }
            "bud_dataMarketList" | "bud_dataMarketPurchase" => Ok(json!({
                "supported_method": method,
                "chain_id": self.chain_id,
            })),
            other => Err(DataMarketError::UnknownRpcMethod(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::keys::{
        derive_grant_one_time_keypair, generate_xwing_keypair, open_key_package_xwing,
    };
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_sealed_upload;
    use crate::storage::bud3::placement::{Class, Share};

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 1024,
        fps: 10,
        k_max: 64,
    };

    #[test]
    fn data_market_sale_uses_grant() {
        let seller = Address::from([0x21; 32]);
        let mut bud3 = Bud3Registry::new();
        let mut market = DataMarketRegistry::new(2026);

        let dataset = b"curated scientific observations v3".repeat(20);
        let master = [0x55; 32];
        let nonce = [0x66; 32];
        let sealed = prepare_sealed_upload(&dataset, &master, &nonce, &P, &Bud3Limits::default())
            .unwrap();
        let obj_key = sealed.upload.record.commitment;
        let cid = sealed.upload.record.content_id;
        let nft_id = [0x77; 32];

        bud3.register_object_for_owner(
            Some(seller.0),
            sealed.upload.record,
            vec![(
                0,
                Share {
                    validator: [3u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbol_count: 4,
                },
            )],
            1,
            20,
            10_000,
        )
        .unwrap();
        bud3.bind_nft(nft_id, obj_key).unwrap();

        let listing = market
            .list_content(&bud3, seller, cid, obj_key, nft_id, 2026, 5_000, 200)
            .unwrap();
        assert_ne!(listing.commitment_digest(), [0u8; 32]);

        let (buyer_pk, buyer_sk) = generate_xwing_keypair(&[0x88; 64]);
        let grant_nonce = [0x99; 32];
        let (ot_pk, _ot_sk) = derive_grant_one_time_keypair(&master, &nft_id, &grant_nonce);
        let pkg = ObjectKeyPackage {
            object_key: sealed.object_key,
            content_id: cid,
        };

        let outcome = market
            .settle_purchase_with_grant(
                &mut bud3,
                listing.listing_id,
                2026,
                5_000,
                10,
                grant_nonce,
                ot_pk,
                &pkg,
                &buyer_pk,
                &[0xAA; 64],
            )
            .unwrap();

        assert!(bud3
            .active_grant(&outcome.grant_row.grant_tag, 15)
            .is_some());
        assert_eq!(outcome.ai_input_ref.content_id, cid);
        assert_eq!(outcome.ai_input_ref.grant_tag, outcome.grant_row.grant_tag);

        let capsule =
            crate::storage::bud3::keys::SealedGrantCapsule::from_bytes(&outcome.grant_row.sealed_key_package)
                .unwrap();
        let opened = open_key_package_xwing(&capsule, &buyer_sk).unwrap();
        assert_eq!(opened.content_id, cid);
        assert_eq!(opened.object_key, sealed.object_key);

        let rpc_ok = market
            .handle_rpc(&bud3, "bud_dataMarketGetListing", &json!({ "listing_id": listing.listing_id }))
            .unwrap();
        assert_eq!(rpc_ok["price_bud_atoms"], 5_000);
        assert!(market
            .handle_rpc(&bud3, "bud_marketplaceLegacyGet", &json!({}))
            .is_err());
    }
}
