//! B.U.D. 3.0 Data Market (, Section 5.6, ).
//!
//! Sales bind a B.U.D. 3.0 [`ContentId`] and [`ContentRef`], verify post-quantum
//! ML-DSA-87 buyer authorization bound to `(chain_id, listing_id, content_id, price_atoms)`,
//! settle payment atomically, and issue unlinkable access through `bud3::grants`.
//!
//! exposed for: Data Market `bud_dataMarket*` RPC handlers and block execution ().

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::crypto::ctx::STORAGE_V2;
use crate::crypto::pq::{validate_public_key, verify};
use crate::crypto::scheme::SchemeId;
use crate::storage::bud3::content_id::{ContentId, ContentKey};
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::grants::{
    build_grant_row, compute_grant_tag, seal_grant_key_package, GrantBud3Error, GrantRow,
};
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey, RegistryError};

/// Domain tag binding a Data Market purchase authorization ().
pub const DOMAIN_DATA_MARKET_PURCHASE: &[u8] = b"BDLM_BUD3_DATA_MARKET_PURCHASE_V1";

/// Canonical `bud_dataMarket*` JSON-RPC method names ( item 3).
pub const DATA_MARKET_RPC_METHODS: &[&str] = &[
    "bud_dataMarketGetListing",
    "bud_dataMarketGetDataAssets",
    "bud_dataMarketGetAccessGrants",
    "bud_dataMarketGetSaleAuthorizations",
    "bud_dataMarketGetPurchaseReceipts",
    "bud_dataMarketBuildAiInputRef",
    "bud_dataMarketPrepareSaleAuthorization",
    "bud_dataMarketPreparePurchase",
    "bud_dataMarketPurchase",
];

/// Errors refused by the B.U.D. 3.0 Data Market.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataMarketError {
    ZeroSellerOrPrice,
    UnknownObject,
    ContentIdMismatch,
    InvalidContentRef(ContentRefError),
    UnknownListing,
    InactiveListing,
    ChainIdMismatch { signed: u64, expected: u64 },
    InvalidBuyerSignature,
    PaymentFailed(String),
    ReplayedPurchase,
    Grant(GrantBud3Error),
    Registry(RegistryError),
}

/// On-chain listing of a B.U.D. 3.0 data object in the Data Market.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMarketListing {
    pub listing_id: [u8; 32],
    pub seller: Address,
    pub content_ref: ContentRef,
    pub nft_id: NftId,
    pub price_atoms: u64,
    pub grant_duration_epochs: u64,
    pub active: bool,
}

/// Post-quantum V5 (ML-DSA-87) buyer purchase authorization ().
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurchaseAuthorizationV5 {
    pub chain_id: u64,
    pub listing_id: [u8; 32],
    pub content_id: ContentId,
    pub price_atoms: u64,
    pub buyer: Address,
    pub buyer_ml_dsa_87_pk: Vec<u8>,
    pub buyer_signature: Vec<u8>,
    pub buyer_hpke_pk: Vec<u8>,
}

impl PurchaseAuthorizationV5 {
    /// Domain-separated digest binding `chain_id`, `listing_id`, `content_id`, and `price_atoms`.
    ///
    /// exposed for: wallet/CLI `bud_dataMarketPreparePurchase` signing ().
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            DOMAIN_DATA_MARKET_PURCHASE,
            &self.chain_id.to_le_bytes(),
            &self.listing_id,
            &self.content_id.digest,
            &self.content_id.len.to_le_bytes(),
            &self.price_atoms.to_le_bytes(),
            self.buyer.as_bytes(),
            &self.buyer_hpke_pk,
        ])
    }

    /// Verify the ML-DSA-87 signature and chain/price bindings ().
    ///
    /// exposed for: `DataMarketRegistry::settle_purchase_with_grant` ().
    pub fn verify_pq(&self, expected_chain_id: u64) -> Result<(), DataMarketError> {
        if self.chain_id != expected_chain_id {
            return Err(DataMarketError::ChainIdMismatch {
                signed: self.chain_id,
                expected: expected_chain_id,
            });
        }
        validate_public_key(SchemeId::ML_DSA_87, &self.buyer_ml_dsa_87_pk)
            .map_err(|_| DataMarketError::InvalidBuyerSignature)?;
        let digest = self.signing_digest();
        verify(
            SchemeId::ML_DSA_87,
            &self.buyer_ml_dsa_87_pk,
            &digest,
            STORAGE_V2,
            &self.buyer_signature,
        )
        .map_err(|_| DataMarketError::InvalidBuyerSignature)
    }
}

/// Grant-issuance material supplied by the seller when settling a Data Market sale.
#[derive(Debug, Clone)]
pub struct SellerGrantBundle {
    pub grant_nonce: [u8; 32],
    pub one_time_ml_dsa_65_pk: Vec<u8>,
    pub content_key: ContentKey,
}

/// Receipt emitted after settling payment and issuing a `bud3::grants` access grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMarketPurchaseReceipt {
    pub listing_id: [u8; 32],
    pub content_id: ContentId,
    pub grant_tag: [u8; 32],
    pub price_paid_atoms: u64,
    pub expires_at_epoch: u64,
}

/// B.U.D. 3.0 Data Market registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataMarketRegistry {
    listings: BTreeMap<[u8; 32], DataMarketListing>,
    receipts: Vec<DataMarketPurchaseReceipt>,
    #[serde(default)]
    consumed_purchases: BTreeSet<([u8; 32], Address)>,
}

impl DataMarketRegistry {
    /// Create an empty Data Market registry.
    ///
    /// exposed for: Data Market state initialization ().
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a B.U.D. 3.0 object listing in the Data Market.
    ///
    /// exposed for: Data Market listing creation ().
    pub fn create_listing(
        &mut self,
        bud3: &Bud3Registry,
        seller: Address,
        target: (ContentId, ObjectKey, NftId),
        price_atoms: u64,
        grant_duration_epochs: u64,
    ) -> Result<DataMarketListing, DataMarketError> {
        if seller == Address::zero() || price_atoms == 0 || grant_duration_epochs == 0 {
            return Err(DataMarketError::ZeroSellerOrPrice);
        }
        let (content_id, object_commitment, nft_id) = target;
        let obj = bud3
            .object(&object_commitment)
            .ok_or(DataMarketError::UnknownObject)?;
        if obj.record.content_id != content_id {
            return Err(DataMarketError::ContentIdMismatch);
        }
        let content_ref = ContentRef::new(content_id, object_commitment, Some(nft_id))
            .map_err(DataMarketError::InvalidContentRef)?;
        let listing_id = hash_fields_bytes(&[
            DOMAIN_DATA_MARKET_PURCHASE,
            b"listing",
            seller.as_bytes(),
            &content_id.digest,
            &object_commitment,
            &nft_id,
        ]);
        let listing = DataMarketListing {
            listing_id,
            seller,
            content_ref,
            nft_id,
            price_atoms,
            grant_duration_epochs,
            active: true,
        };
        self.listings.insert(listing_id, listing.clone());
        Ok(listing)
    }

    /// Look up a listing by `listing_id`.
    ///
    /// exposed for: `bud_dataMarketGetListing` ().
    #[must_use]
    pub fn listing(&self, id: &[u8; 32]) -> Option<&DataMarketListing> {
        self.listings.get(id)
    }

    /// Atomically verify V5 PQ authorization, transfer `price_atoms` from buyer to seller,
    /// and issue an unlinkable `bud3::grants` [`GrantRow`] ( item 3, , `G-4`).
    ///
    /// exposed for: `bud_dataMarketPurchase` settlement ().
    pub fn settle_purchase_with_grant(
        &mut self,
        accounts: &mut AccountState,
        bud3: &mut Bud3Registry,
        expected_chain_id: u64,
        auth: &PurchaseAuthorizationV5,
        seller_grant: &SellerGrantBundle,
        current_epoch: u64,
    ) -> Result<(DataMarketPurchaseReceipt, GrantRow), DataMarketError> {
        let _ = DATA_MARKET_RPC_METHODS;
        auth.verify_pq(expected_chain_id)?;
        let listing = self
            .listings
            .get(&auth.listing_id)
            .cloned()
            .ok_or(DataMarketError::UnknownListing)?;
        if !listing.active {
            return Err(DataMarketError::InactiveListing);
        }
        let purchase_key = (auth.listing_id, auth.buyer);
        if self.consumed_purchases.contains(&purchase_key) {
            return Err(DataMarketError::ReplayedPurchase);
        }
        if auth.content_id != listing.content_ref.content_id
            || auth.price_atoms != listing.price_atoms
        {
            return Err(DataMarketError::ContentIdMismatch);
        }

        let grant_tag = compute_grant_tag(&listing.nft_id, &seller_grant.grant_nonce);
        let sealed_pkg = seal_grant_key_package(
            &auth.buyer_hpke_pk,
            &grant_tag,
            &listing.content_ref.object_commitment,
            &seller_grant.content_key,
        )
        .map_err(DataMarketError::Grant)?;
        let expires_at_epoch = current_epoch.saturating_add(listing.grant_duration_epochs);
        let row = build_grant_row(
            &listing.nft_id,
            &seller_grant.grant_nonce,
            seller_grant.one_time_ml_dsa_65_pk.clone(),
            sealed_pkg,
            expires_at_epoch,
            current_epoch,
        )
        .map_err(DataMarketError::Grant)?;

        // Validate every grant-issuance condition BEFORE debiting the buyer.
        bud3.validate_view_grant(&row, current_epoch)
            .map_err(DataMarketError::Registry)?;

        accounts
            .transfer(&auth.buyer, &listing.seller, listing.price_atoms)
            .map_err(|e| DataMarketError::PaymentFailed(e.to_string()))?;
        bud3.issue_grant(row.clone(), current_epoch)
            .map_err(DataMarketError::Registry)?;
        self.consumed_purchases.insert(purchase_key);

        let receipt = DataMarketPurchaseReceipt {
            listing_id: listing.listing_id,
            content_id: listing.content_ref.content_id,
            grant_tag: row.grant_tag,
            price_paid_atoms: listing.price_atoms,
            expires_at_epoch,
        };
        self.receipts.push(receipt.clone());
        Ok((receipt, row))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hpke::HpkeKeyPair;
    use crate::crypto::pq::{ml_dsa_public_key, ml_dsa_sign};
    use crate::storage::bud3::grants::open_grant_key_package;
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
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
        let seller = Address([0x41; 32]);
        let buyer = Address([0x42; 32]);
        let mut accounts = AccountState::new();
        accounts.credit_account(&buyer, 500);

        let mut bud3 = Bud3Registry::default();
        let dataset = b"curated medical sensor telemetry v3".repeat(8);
        let up = prepare_public_upload(&dataset, &P, &Bud3Limits::default(), 8).expect("upload");
        let cid = up.record.content_id;
        let obj_key = up.record.commitment;
        bud3.register_object(
            seller.0,
            up.record,
            vec![(
                0,
                Share {
                    validator: [3u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 8,
                },
            )],
            1,
            40,
        )
        .expect("register");
        let nft_id = [0x99u8; 32];
        bud3.bind_nft(nft_id, seller.0, &obj_key).expect("bind nft");

        let mut market = DataMarketRegistry::new();
        let listing = market
            .create_listing(&bud3, seller, (cid, obj_key, nft_id), 25, 10)
            .expect("listing");

        let buyer_pq_seed = [0x51u8; 32];
        let buyer_pq_pk = ml_dsa_public_key(SchemeId::ML_DSA_87, &buyer_pq_seed).expect("pk87");
        let buyer_hpke = HpkeKeyPair::from_seed(&[0x52u8; 32]).expect("hpke");

        let mut auth = PurchaseAuthorizationV5 {
            chain_id: 45_261,
            listing_id: listing.listing_id,
            content_id: cid,
            price_atoms: 25,
            buyer,
            buyer_ml_dsa_87_pk: buyer_pq_pk,
            buyer_signature: Vec::new(),
            buyer_hpke_pk: buyer_hpke.public_key().to_vec(),
        };
        auth.buyer_signature = ml_dsa_sign(
            SchemeId::ML_DSA_87,
            &buyer_pq_seed,
            &auth.signing_digest(),
            STORAGE_V2,
            &[0u8; 32],
        )
        .expect("sign87");

        // Wrong chain_id must be refused with zero balance mutation (, `G-4`).
        let mut wrong_chain = auth.clone();
        wrong_chain.chain_id = 1;
        assert!(market
            .settle_purchase_with_grant(
                &mut accounts,
                &mut bud3,
                45_261,
                &wrong_chain,
                &SellerGrantBundle {
                    grant_nonce: [0x61; 32],
                    one_time_ml_dsa_65_pk: Vec::new(),
                    content_key: ContentKey([0x77; 32]),
                },
                2,
            )
            .is_err());
        assert_eq!(accounts.get_balance(&buyer), 500);

        let otk_seed = [0x62u8; 32];
        let otk_pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &otk_seed).expect("pk65");
        let ck = ContentKey([0x77u8; 32]);
        let (rcpt, row) = market
            .settle_purchase_with_grant(
                &mut accounts,
                &mut bud3,
                45_261,
                &auth,
                &SellerGrantBundle {
                    grant_nonce: [0x61; 32],
                    one_time_ml_dsa_65_pk: otk_pk.clone(),
                    content_key: ck.clone(),
                },
                2,
            )
            .expect("settle purchase with bud3::grants");

        assert_eq!(accounts.get_balance(&buyer), 475);
        assert_eq!(accounts.get_balance(&seller), 25);
        assert!(bud3.active_grant(&rcpt.grant_tag, 3).is_some());

        let (opened_obj, opened_ck) =
            open_grant_key_package(&buyer_hpke, &row.grant_tag, &row.sealed_key_package)
                .expect("buyer opens HPKE grant package");
        assert_eq!(opened_obj, obj_key);
        assert_eq!(opened_ck, ck);
        assert!(bud3.active_grant(&rcpt.grant_tag, 3).is_some());
        assert!(bud3
            .active_grant(&rcpt.grant_tag, rcpt.expires_at_epoch)
            .is_none());

        let buyer_balance = accounts.get_balance(&buyer);
        let seller_balance = accounts.get_balance(&seller);
        let replay = market.settle_purchase_with_grant(
            &mut accounts,
            &mut bud3,
            45_261,
            &auth,
            &SellerGrantBundle {
                grant_nonce: [0x61; 32],
                one_time_ml_dsa_65_pk: otk_pk,
                content_key: ck,
            },
            3,
        );
        assert_eq!(replay, Err(DataMarketError::ReplayedPurchase));
        assert_eq!(accounts.get_balance(&buyer), buyer_balance);
        assert_eq!(accounts.get_balance(&seller), seller_balance);
    }
}
