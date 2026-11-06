//! B.U.D. 3.0 Data Market listings, grant-backed settlement, AI read references,
//! and `bud_dataMarket*` RPC dispatch (Section 5.6, WP-23, BLG-064).
//! exposed for Data Market RPC endpoints, settlement execution, and AI input verification.
//!
//! * Every listed asset is addressed by its B.U.D. 3.0 [`ContentId`] and
//!   `object_commitment` ([`ObjectKey`]), bound to `chain_id` and `price_bud_atoms`.
//! * Purchasing an asset issues an unlinkable B.U.D. 3.0 [`GrantRow`] via
//!   [`build_grant_row`] and [`Bud3Registry::issue_view_grant`], sealing
//!   `(object_commitment, content_key)` to the buyer's X-Wing (`0x647a`) public key.
//! * AI read references (`AiContentInputRef`) bind the identical [`ContentId`]
//!   and unlinkable `grant_tag`.
//! * Only `bud_dataMarket*` RPC method names are accepted; legacy names are
//!   refused.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_id::{ContentId, ContentKey};
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::grants::{build_grant_row, compute_grant_tag, GrantBud3Error, GrantRow};
use crate::storage::bud3::keys::{seal_key_package, KeyPkgBud3Error};
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey, RegistryError};

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
    /// Invalid `ContentRef`.
    InvalidContentRef(ContentRefError),
    /// Listing id does not exist or is inactive.
    ListingNotFound,
    /// Payment attached to purchase is below the listing price (`BLG-064`).
    InsufficientPayment { required: u64, paid: u64 },
    /// X-Wing HPKE sealing failed.
    KeyPackage(KeyPkgBud3Error),
    /// Grant row structural validation failed.
    Grant(GrantBud3Error),
    /// Registry rejected `issue_view_grant`.
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
            Self::InvalidContentRef(e) => write!(f, "invalid ContentRef: {e:?}"),
            Self::ListingNotFound => f.write_str("data market listing not found"),
            Self::InsufficientPayment { required, paid } => {
                write!(f, "insufficient payment: required {required}, paid {paid}")
            }
            Self::KeyPackage(e) => write!(f, "grant key package failed: {e:?}"),
            Self::Grant(e) => write!(f, "grant build failed: {e:?}"),
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
    pub grant_duration_epochs: u64,
    pub active: bool,
}

impl DataMarketListing {
    /// Deterministic commitment digest binding seller, `ContentId`, `chain_id`, and price.
    /// exposed for Data Market receipt verification and order signing.
    #[must_use]
    pub fn commitment_digest(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            DOMAIN_DATA_MARKET,
            &self.listing_id.to_le_bytes(),
            self.seller.as_bytes(),
            &self.content_ref.content_id.digest,
            &self.content_ref.content_id.len.to_le_bytes(),
            &self.object_commitment,
            &self.nft_id,
            &self.chain_id.to_le_bytes(),
            &self.price_bud_atoms.to_le_bytes(),
            &self.grant_duration_epochs.to_le_bytes(),
        ])
    }
}

/// Cryptographic parameters supplied when settling a Data Market purchase into a [`GrantRow`].
pub struct PurchaseGrantSpec<'a> {
    pub grant_nonce: [u8; 32],
    pub one_time_pk: Vec<u8>,
    pub content_key: &'a ContentKey,
    pub buyer_hpke_public: &'a [u8],
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
        target: (ContentId, ObjectKey, NftId),
        terms: (u64, u64, u64),
    ) -> Result<DataMarketListing, DataMarketError> {
        let (content_id, object_commitment, nft_id) = target;
        let (chain_id, price_bud_atoms, grant_duration_epochs) = terms;
        if chain_id == 0 || chain_id != self.chain_id {
            return Err(DataMarketError::ChainIdMismatch {
                expected: self.chain_id,
                got: chain_id,
            });
        }
        if price_bud_atoms == 0 {
            return Err(DataMarketError::InvalidTerms("price_bud_atoms must be > 0"));
        }
        if grant_duration_epochs == 0 {
            return Err(DataMarketError::InvalidTerms(
                "grant_duration_epochs must be > 0",
            ));
        }
        let obj = bud3
            .object(&object_commitment)
            .ok_or(DataMarketError::InvalidObject)?;
        if obj.record.content_id != content_id {
            return Err(DataMarketError::InvalidObject);
        }

        let content_ref = ContentRef::new(content_id, object_commitment, Some(nft_id))
            .map_err(DataMarketError::InvalidContentRef)?;
        let id = self.next_listing_id;
        self.next_listing_id = self.next_listing_id.saturating_add(1);
        let listing = DataMarketListing {
            listing_id: id,
            seller,
            content_ref,
            object_commitment,
            nft_id,
            chain_id,
            price_bud_atoms,
            grant_duration_epochs,
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
    pub fn settle_purchase_with_grant(
        &self,
        bud3: &mut Bud3Registry,
        listing_id: u64,
        payment: (u64, u64, u64),
        grant_spec: PurchaseGrantSpec<'_>,
    ) -> Result<DataMarketSaleOutcome, DataMarketError> {
        let (chain_id, paid_bud_atoms, current_epoch) = payment;
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

        let grant_tag = compute_grant_tag(&listing.nft_id, &grant_spec.grant_nonce);
        let sealed_pkg = seal_key_package(
            grant_spec.buyer_hpke_public,
            &grant_tag,
            &listing.object_commitment,
            grant_spec.content_key,
        )
        .map_err(DataMarketError::KeyPackage)?;

        let expires_at_epoch = current_epoch.saturating_add(listing.grant_duration_epochs);
        let grant_row = build_grant_row(
            &listing.nft_id,
            &grant_spec.grant_nonce,
            grant_spec.one_time_pk,
            sealed_pkg,
            expires_at_epoch,
            current_epoch,
        )
        .map_err(DataMarketError::Grant)?;

        bud3.issue_view_grant(grant_row.clone(), current_epoch)
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
    /// exposed for `bud_dataMarket*` JSON-RPC server dispatch.
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
                let listing = self.listing(id).ok_or(DataMarketError::ListingNotFound)?;
                Ok(json!({
                    "listing_id": listing.listing_id,
                    "content_digest": hex::encode(listing.content_ref.content_id.digest),
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
                let listing = self.listing(id).ok_or(DataMarketError::ListingNotFound)?;
                let has_obj = bud3.object(&listing.object_commitment).is_some();
                Ok(json!({
                    "listing_id": listing.listing_id,
                    "content_digest": hex::encode(listing.content_ref.content_id.digest),
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
    use crate::crypto::hpke::HpkeKeyPair;
    use crate::storage::bud3::keys::{
        derive_grant_one_time_keypair, derive_object_content_key, open_key_package,
    };
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_sealed_upload;
    use crate::storage::bud3::placement::{Class, Share};

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    #[test]
    fn data_market_sale_uses_grant() {
        let seller = Address([0x21; 32]);
        let mut bud3 = Bud3Registry::default();
        let mut market = DataMarketRegistry::new(2026);

        let dataset = b"curated scientific observations v3".repeat(6);
        let master = [0x55; 32];
        let content_key = derive_object_content_key(&master, 0);
        let salt = [0x66; crate::storage::bud3::seal::SEAL_SALT_LEN];
        let up = prepare_sealed_upload(
            &dataset,
            &content_key,
            salt,
            &P,
            &Bud3Limits::default(),
            12,
        )
        .unwrap();
        let obj_key = up.record.commitment;
        let cid = up.record.content_id;
        let nft_id = [0x77; 32];

        bud3.register_object(
            seller.0,
            up.record,
            vec![(
                0,
                Share {
                    validator: [3u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 12,
                },
            )],
            1,
            20,
        )
        .unwrap();
        bud3.bind_nft(nft_id, seller.0, &obj_key).unwrap();

        let listing = market
            .list_content(&bud3, seller, (cid, obj_key, nft_id), (2026, 5_000, 200))
            .unwrap();
        assert_ne!(listing.commitment_digest(), [0u8; 32]);

        let buyer_kp = HpkeKeyPair::from_seed(&[0x88; 32]);
        let grant_nonce = [0x99; 32];
        let (_ot_seed, ot_pk) =
            derive_grant_one_time_keypair(&master, &nft_id, &grant_nonce).unwrap();

        let outcome = market
            .settle_purchase_with_grant(
                &mut bud3,
                listing.listing_id,
                (2026, 5_000, 10),
                PurchaseGrantSpec {
                    grant_nonce,
                    one_time_pk: ot_pk,
                    content_key: &content_key,
                    buyer_hpke_public: buyer_kp.public_key(),
                },
            )
            .unwrap();

        assert!(bud3.grant_row(&outcome.grant_row.grant_tag).is_some());
        assert_eq!(outcome.ai_input_ref.content_id, cid);
        assert_eq!(outcome.ai_input_ref.grant_tag, outcome.grant_row.grant_tag);

        let (opened_obj, opened_key) = open_key_package(
            &buyer_kp,
            &outcome.grant_row.grant_tag,
            &outcome.grant_row.sealed_key_package,
        )
        .unwrap();
        assert_eq!(opened_obj, obj_key);
        assert_eq!(opened_key, content_key);

        let rpc_ok = market
            .handle_rpc(
                &bud3,
                "bud_dataMarketGetListing",
                &json!({ "listing_id": listing.listing_id }),
            )
            .unwrap();
        assert_eq!(rpc_ok["price_bud_atoms"], 5_000);
        assert!(market
            .handle_rpc(&bud3, "bud_marketplaceLegacyGet", &json!({}))
            .is_err());
    }
}
