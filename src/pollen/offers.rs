//! Phase 5 §5.5 AI Data Marketplace — satıcı-teklifi (DataOffer) ekonomisi.
//!
//! ARENA4 ADIM 1: Data Rights/Pollen sertleştirmesi bu geçiş registry'sine
//! `DataAsset` ve `AccessGrant` map'lerini ekler. Kural: AI, Pollen/B.U.D.
//! veri referansını geçerli grant olmadan okuyamaz.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{
    AccessGrant, AiDataInputRef, AssetId, DataAsset, DataAssetStatus, EncryptionPolicy, GrantId,
    SaleAuthorization, SaleAuthorizationId,
};

/// Phase 5 §5.5: AI Data Marketplace — Economic layer for user-to-AI data sales.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataOffer {
    pub id: u64,
    pub seller: Address,
    pub cid: ContentId,
    pub price: u64, // Price in $BUD
    pub active: bool,
}

/// Receipt for an authorization-backed pollen purchase. This is not a LUM/DeFi
/// settlement: `payment_commitment` binds the buyer-side payment proof for a
/// future adapter while the DataAsset ownership remains with `seller`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollenPurchaseReceipt {
    pub receipt_id: GrantId,
    pub authorization_id: SaleAuthorizationId,
    pub asset_id: AssetId,
    pub seller: Address,
    pub buyer: Address,
    pub grantee: Address,
    pub price_paid: u64,
    pub grant_id: GrantId,
    pub purchased_at_block: u64,
    pub grant_expires_at_block: u64,
    pub max_reads: u32,
    pub terms_hash: [u8; 32],
    pub payment_commitment: [u8; 32],
}

impl PollenPurchaseReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_id: SaleAuthorizationId,
        asset_id: AssetId,
        seller: Address,
        buyer: Address,
        grantee: Address,
        price_paid: u64,
        grant_id: GrantId,
        purchased_at_block: u64,
        grant_expires_at_block: u64,
        max_reads: u32,
        terms_hash: [u8; 32],
        payment_commitment: [u8; 32],
    ) -> Self {
        let receipt_id = Self::derive_id(
            authorization_id,
            asset_id,
            seller,
            buyer,
            grantee,
            price_paid,
            grant_id,
            purchased_at_block,
            grant_expires_at_block,
            max_reads,
            terms_hash,
            payment_commitment,
        );
        Self {
            receipt_id,
            authorization_id,
            asset_id,
            seller,
            buyer,
            grantee,
            price_paid,
            grant_id,
            purchased_at_block,
            grant_expires_at_block,
            max_reads,
            terms_hash,
            payment_commitment,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive_id(
        authorization_id: SaleAuthorizationId,
        asset_id: AssetId,
        seller: Address,
        buyer: Address,
        grantee: Address,
        price_paid: u64,
        grant_id: GrantId,
        purchased_at_block: u64,
        grant_expires_at_block: u64,
        max_reads: u32,
        terms_hash: [u8; 32],
        payment_commitment: [u8; 32],
    ) -> GrantId {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_PURCHASE_RECEIPT_V1");
        hasher.update(authorization_id.0);
        hasher.update(asset_id.0);
        hasher.update(seller.as_bytes());
        hasher.update(buyer.as_bytes());
        hasher.update(grantee.as_bytes());
        hasher.update(price_paid.to_le_bytes());
        hasher.update(grant_id.0);
        hasher.update(purchased_at_block.to_le_bytes());
        hasher.update(grant_expires_at_block.to_le_bytes());
        hasher.update(max_reads.to_le_bytes());
        hasher.update(terms_hash);
        hasher.update(payment_commitment);
        AssetId(hasher.finalize().into())
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.receipt_id == GrantId::zero() {
            return Err("PollenPurchaseReceipt receipt_id cannot be zero".into());
        }
        if self.authorization_id == SaleAuthorizationId::zero() {
            return Err("PollenPurchaseReceipt authorization_id cannot be zero".into());
        }
        if self.asset_id == AssetId::zero() || self.grant_id == GrantId::zero() {
            return Err("PollenPurchaseReceipt asset/grant id cannot be zero".into());
        }
        if self.seller == Address::zero()
            || self.buyer == Address::zero()
            || self.grantee == Address::zero()
        {
            return Err("PollenPurchaseReceipt addresses cannot be zero".into());
        }
        if self.price_paid == 0 {
            return Err("PollenPurchaseReceipt price_paid must be >= 1".into());
        }
        if self.grant_expires_at_block <= self.purchased_at_block {
            return Err("PollenPurchaseReceipt grant expiry must be after purchase".into());
        }
        if self.max_reads == 0 {
            return Err("PollenPurchaseReceipt max_reads must be >= 1".into());
        }
        if self.payment_commitment == [0u8; 32] {
            return Err("PollenPurchaseReceipt payment_commitment cannot be zero".into());
        }
        let expected = Self::derive_id(
            self.authorization_id,
            self.asset_id,
            self.seller,
            self.buyer,
            self.grantee,
            self.price_paid,
            self.grant_id,
            self.purchased_at_block,
            self.grant_expires_at_block,
            self.max_reads,
            self.terms_hash,
            self.payment_commitment,
        );
        if self.receipt_id != expected {
            return Err("PollenPurchaseReceipt id does not match canonical preimage".into());
        }
        Ok(())
    }

    pub fn calculate_leaf(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_PURCHASE_RECEIPT_LEAF_V1");
        hasher.update(self.receipt_id.0);
        hasher.update(self.authorization_id.0);
        hasher.update(self.asset_id.0);
        hasher.update(self.seller.as_bytes());
        hasher.update(self.buyer.as_bytes());
        hasher.update(self.grantee.as_bytes());
        hasher.update(self.price_paid.to_le_bytes());
        hasher.update(self.grant_id.0);
        hasher.update(self.purchased_at_block.to_le_bytes());
        hasher.update(self.grant_expires_at_block.to_le_bytes());
        hasher.update(self.max_reads.to_le_bytes());
        hasher.update(self.terms_hash);
        hasher.update(self.payment_commitment);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MarketplaceRegistry {
    #[serde(default)]
    pub offers: BTreeMap<u64, DataOffer>,
    #[serde(default)]
    pub next_offer_id: u64,
    /// Pollen: registered data tomurcukları. The asset is not sold; its
    /// access pollen is sold via AccessGrant.
    #[serde(default)]
    pub data_assets: BTreeMap<AssetId, DataAsset>,
    /// Pollen: owner-signed access grants. Strict AI gate consumes these.
    #[serde(default)]
    pub access_grants: BTreeMap<GrantId, AccessGrant>,
    /// Pollen: seller/owner signed sale authorizations. These define the
    /// bounded pollen sale terms without transferring DataAsset ownership.
    #[serde(default)]
    pub sale_authorizations: BTreeMap<SaleAuthorizationId, SaleAuthorization>,
    /// Pollen: purchase receipts produced from authorization-backed grant issue.
    /// They bind a buyer payment commitment to the grant without transferring the asset.
    #[serde(default)]
    pub purchase_receipts: BTreeMap<GrantId, PollenPurchaseReceipt>,
    /// DAO-managed encryption policy parameters. These are protocol settings,
    /// not decrypt keys or read-grant bypasses.
    #[serde(default)]
    pub encryption_policies: BTreeMap<u32, EncryptionPolicy>,
}

impl MarketplaceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_offer(
        &mut self,
        seller: Address,
        cid: ContentId,
        price: u64,
    ) -> Result<u64, String> {
        if price == 0 {
            return Err("Price must be greater than zero".into());
        }
        let id = self.next_offer_id;
        let offer = DataOffer {
            id,
            seller,
            cid,
            price,
            active: true,
        };
        self.offers.insert(id, offer);
        self.next_offer_id += 1;
        Ok(id)
    }

    pub fn close_offer(&mut self, id: u64, caller: &Address) -> Result<(), String> {
        let offer = self.offers.get_mut(&id).ok_or("Offer not found")?;
        if &offer.seller != caller {
            return Err("Not the seller".into());
        }
        offer.active = false;
        Ok(())
    }

    pub fn get_offer(&self, id: u64) -> Option<&DataOffer> {
        self.offers.get(&id)
    }

    pub fn register_data_asset(&mut self, asset: DataAsset) -> Result<AssetId, String> {
        asset.validate()?;
        if self.data_assets.contains_key(&asset.asset_id) {
            return Err("DataAsset already registered".into());
        }
        let id = asset.asset_id;
        self.data_assets.insert(id, asset);
        Ok(id)
    }

    pub fn revoke_data_asset(
        &mut self,
        asset_id: &AssetId,
        caller: &Address,
    ) -> Result<(), String> {
        let asset = self
            .data_assets
            .get_mut(asset_id)
            .ok_or("DataAsset not found")?;
        if &asset.owner != caller {
            return Err("Only DataAsset owner can revoke".into());
        }
        asset.status = DataAssetStatus::Revoked;
        Ok(())
    }

    pub fn create_access_grant(&mut self, grant: AccessGrant) -> Result<GrantId, String> {
        grant.validate_shape()?;
        let asset = self
            .data_assets
            .get(&grant.asset_id)
            .ok_or("AccessGrant references unknown DataAsset")?;
        if !asset.is_active() {
            return Err("AccessGrant references inactive DataAsset".into());
        }
        if grant.owner != asset.owner {
            return Err("AccessGrant owner must match DataAsset owner".into());
        }
        if self.access_grants.contains_key(&grant.grant_id) {
            return Err("AccessGrant already registered".into());
        }
        let id = grant.grant_id;
        self.access_grants.insert(id, grant);
        Ok(id)
    }

    pub fn revoke_access_grant(
        &mut self,
        grant_id: &GrantId,
        caller: &Address,
    ) -> Result<(), String> {
        let grant = self
            .access_grants
            .get_mut(grant_id)
            .ok_or("AccessGrant not found")?;
        if &grant.owner != caller {
            return Err("Only AccessGrant owner can revoke".into());
        }
        grant.status = super::AccessGrantStatus::Revoked;
        Ok(())
    }

    pub fn set_encryption_policy(&mut self, policy: EncryptionPolicy) -> Result<(), String> {
        policy.validate()?;
        self.encryption_policies.insert(policy.version, policy);
        Ok(())
    }

    pub fn get_encryption_policy(&self, version: u32) -> Option<&EncryptionPolicy> {
        self.encryption_policies.get(&version)
    }

    pub fn active_encryption_policies(&self) -> Vec<&EncryptionPolicy> {
        self.encryption_policies
            .values()
            .filter(|policy| policy.active)
            .collect()
    }

    pub fn create_sale_authorization(
        &mut self,
        authorization: SaleAuthorization,
    ) -> Result<SaleAuthorizationId, String> {
        authorization.validate_shape()?;
        let asset = self
            .data_assets
            .get(&authorization.asset_id)
            .ok_or("SaleAuthorization references unknown DataAsset")?;
        if !asset.is_active() {
            return Err("SaleAuthorization references inactive DataAsset".into());
        }
        if authorization.seller != asset.owner {
            return Err("SaleAuthorization seller must match DataAsset owner".into());
        }
        if self
            .sale_authorizations
            .contains_key(&authorization.authorization_id)
        {
            return Err("SaleAuthorization already registered".into());
        }
        let id = authorization.authorization_id;
        self.sale_authorizations.insert(id, authorization);
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_grant_from_sale_authorization(
        &mut self,
        authorization_id: SaleAuthorizationId,
        buyer: Address,
        grantee: Address,
        current_block: u64,
        grant_duration_blocks: u64,
        max_reads: u32,
        payment_commitment: [u8; 32],
    ) -> Result<(GrantId, PollenPurchaseReceipt), String> {
        if buyer == Address::zero() || grantee == Address::zero() {
            return Err("Pollen purchase buyer/grantee cannot be zero".into());
        }
        if grant_duration_blocks == 0 {
            return Err("Pollen purchase grant_duration_blocks must be >= 1".into());
        }
        if max_reads == 0 {
            return Err("Pollen purchase max_reads must be >= 1".into());
        }
        if payment_commitment == [0u8; 32] {
            return Err("Pollen purchase payment_commitment cannot be zero".into());
        }

        let authorization = self
            .sale_authorizations
            .get(&authorization_id)
            .ok_or("SaleAuthorization not found")?
            .clone();
        authorization.validate_shape()?;
        if !authorization.can_issue(current_block) {
            return Err("SaleAuthorization inactive, expired, or grant limit exhausted".into());
        }

        let asset = self
            .data_assets
            .get(&authorization.asset_id)
            .ok_or("SaleAuthorization references unknown DataAsset")?;
        if !asset.is_active() {
            return Err("SaleAuthorization references inactive DataAsset".into());
        }
        if asset.owner != authorization.seller {
            return Err("SaleAuthorization seller must match DataAsset owner".into());
        }

        let grant_expires_at_block = current_block
            .checked_add(grant_duration_blocks)
            .ok_or("Pollen purchase grant expiry overflow")?;
        if grant_expires_at_block > authorization.expires_at_block {
            return Err("Pollen purchase grant expiry exceeds SaleAuthorization expiry".into());
        }

        let mut grant = AccessGrant::new_unsigned(
            authorization.asset_id,
            authorization.seller,
            grantee,
            buyer,
            authorization.unit_price,
            current_block,
            grant_expires_at_block,
            max_reads,
            authorization.terms_hash,
        );
        // Authorization-backed grant: the seller-signed sale authorization is
        // the bounded owner consent for this grant shape in this primitive
        // layer. Real cryptographic signature verification remains a future
        // wallet/transaction concern; sentinel signatures still fail closed.
        grant.owner_signature = authorization.seller_signature.clone();
        grant.validate_shape()?;
        if self.access_grants.contains_key(&grant.grant_id) {
            return Err("AccessGrant already registered".into());
        }

        let receipt = PollenPurchaseReceipt::new(
            authorization.authorization_id,
            authorization.asset_id,
            authorization.seller,
            buyer,
            grantee,
            authorization.unit_price,
            grant.grant_id,
            current_block,
            grant_expires_at_block,
            max_reads,
            authorization.terms_hash,
            payment_commitment,
        );
        receipt.validate_shape()?;
        if self.purchase_receipts.contains_key(&receipt.receipt_id) {
            return Err("PollenPurchaseReceipt already registered".into());
        }

        self.sale_authorizations
            .get_mut(&authorization_id)
            .ok_or("SaleAuthorization not found")?
            .record_issued_grant()?;
        let grant_id = grant.grant_id;
        self.access_grants.insert(grant_id, grant);
        self.purchase_receipts
            .insert(receipt.receipt_id, receipt.clone());
        Ok((grant_id, receipt))
    }

    pub fn get_sale_authorization(
        &self,
        authorization_id: &SaleAuthorizationId,
    ) -> Option<&SaleAuthorization> {
        self.sale_authorizations.get(authorization_id)
    }

    /// Strict AI gate. Returns `Ok(None)` for non-Pollen input_ref payloads
    /// (legacy prompt/opaque bytes). Returns `Err` for Pollen references that
    /// lack a valid grant. There is no DAO/admin override.
    pub fn validate_ai_read_ref(
        &self,
        input_ref: &[u8],
        requester: &Address,
        current_block: u64,
    ) -> Result<Option<GrantId>, String> {
        let Some(reference) = AiDataInputRef::decode(input_ref)? else {
            return Ok(None);
        };
        let asset = self
            .data_assets
            .get(&reference.asset_id)
            .ok_or("AI data read denied: DataAsset not found")?;
        if !asset.is_active() {
            return Err("AI data read denied: DataAsset inactive".into());
        }
        let grant = self
            .access_grants
            .get(&reference.grant_id)
            .ok_or("AI data read denied: AccessGrant not found")?;
        if grant.asset_id != reference.asset_id {
            return Err("AI data read denied: grant/asset mismatch".into());
        }
        if grant.owner != asset.owner {
            return Err("AI data read denied: grant owner mismatch".into());
        }
        if !grant.is_active_for(requester, current_block) {
            return Err(
                "AI data read denied: AccessGrant inactive, expired, exhausted, or wrong grantee"
                    .into(),
            );
        }
        Ok(Some(reference.grant_id))
    }

    pub fn consume_ai_read_grant(
        &mut self,
        grant_id: &GrantId,
        requester: &Address,
        current_block: u64,
    ) -> Result<(), String> {
        let grant = self
            .access_grants
            .get_mut(grant_id)
            .ok_or("AccessGrant not found")?;
        if !grant.is_active_for(requester, current_block) {
            return Err("AccessGrant cannot be consumed".into());
        }
        grant.record_read()
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_MARKETPLACE_REGISTRY_V2");
        hasher.update(self.next_offer_id.to_le_bytes());
        for (id, offer) in &self.offers {
            hasher.update(b"offer");
            hasher.update(id.to_le_bytes());
            hasher.update(offer.seller.0);
            hasher.update(offer.cid.0);
            hasher.update(offer.price.to_le_bytes());
            hasher.update([offer.active as u8]);
        }
        for (asset_id, asset) in &self.data_assets {
            hasher.update(b"asset");
            hasher.update(asset_id.0);
            hasher.update(asset.calculate_leaf());
        }
        for (grant_id, grant) in &self.access_grants {
            hasher.update(b"grant");
            hasher.update(grant_id.0);
            hasher.update(grant.calculate_leaf());
        }
        for (authorization_id, authorization) in &self.sale_authorizations {
            hasher.update(b"sale_authorization");
            hasher.update(authorization_id.0);
            hasher.update(authorization.calculate_leaf());
        }
        for (receipt_id, receipt) in &self.purchase_receipts {
            hasher.update(b"purchase_receipt");
            hasher.update(receipt_id.0);
            hasher.update(receipt.calculate_leaf());
        }
        for (version, policy) in &self.encryption_policies {
            hasher.update(b"encryption_policy");
            hasher.update(version.to_le_bytes());
            hasher.update(policy.calculate_leaf());
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pollen::AccessGrantStatus;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn signed_sale_authorization(asset: &DataAsset) -> SaleAuthorization {
        signed_sale_authorization_with_limit(asset, 2)
    }

    fn signed_sale_authorization_with_limit(
        asset: &DataAsset,
        max_grants: u32,
    ) -> SaleAuthorization {
        let mut authorization = SaleAuthorization::new_unsigned(
            asset.asset_id,
            asset.owner,
            42,
            10,
            20,
            max_grants,
            [0xAA; 32],
        );
        authorization.seller_signature = super::super::Signature64::from([0x44; 64]);
        authorization
    }

    fn signed_grant(asset: &DataAsset, grantee: Address, max_reads: u32) -> AccessGrant {
        let mut grant = AccessGrant::new_unsigned(
            asset.asset_id,
            asset.owner,
            grantee,
            grantee,
            42,
            10,
            20,
            max_reads,
            [8u8; 32],
        );
        grant.owner_signature = super::super::Signature64::from([9u8; 64]);
        grant
    }

    #[test]
    fn root_changes_when_data_asset_or_grant_changes() {
        let mut registry = MarketplaceRegistry::new();
        let root0 = registry.root();
        let asset = DataAsset::new(addr(1), ContentId::of(b"asset"), [1u8; 32], true);
        registry.register_data_asset(asset.clone()).unwrap();
        let root1 = registry.root();
        assert_ne!(root0, root1);
        registry
            .create_access_grant(signed_grant(&asset, addr(2), 1))
            .unwrap();
        let root2 = registry.root();
        assert_ne!(root1, root2);
        registry
            .create_sale_authorization(signed_sale_authorization(&asset))
            .unwrap();
        let root3 = registry.root();
        assert_ne!(root2, root3);
        registry
            .set_encryption_policy(EncryptionPolicy {
                version: 1,
                hpke_suite_id: 0x20,
                min_public_key_bytes: 32,
                max_grant_duration_blocks: 100,
                deprecated_after_block: None,
                active: true,
            })
            .unwrap();
        assert_ne!(root3, registry.root());
    }

    #[test]
    fn ai_read_ref_without_grant_is_default_deny() {
        let mut registry = MarketplaceRegistry::new();
        let asset = DataAsset::new(addr(1), ContentId::of(b"asset"), [1u8; 32], true);
        registry.register_data_asset(asset.clone()).unwrap();
        let reference = AiDataInputRef {
            asset_id: asset.asset_id,
            grant_id: GrantId::from([7u8; 32]),
        };
        let err = registry
            .validate_ai_read_ref(&reference.encode(), &addr(2), 10)
            .unwrap_err();
        assert!(err.contains("AccessGrant not found"));
    }

    #[test]
    fn ai_read_ref_with_valid_grant_consumes_once() {
        let mut registry = MarketplaceRegistry::new();
        let asset = DataAsset::new(addr(1), ContentId::of(b"asset"), [1u8; 32], true);
        registry.register_data_asset(asset.clone()).unwrap();
        let grant_id = registry
            .create_access_grant(signed_grant(&asset, addr(2), 1))
            .unwrap();
        let reference = AiDataInputRef {
            asset_id: asset.asset_id,
            grant_id,
        };
        assert_eq!(
            registry
                .validate_ai_read_ref(&reference.encode(), &addr(2), 10)
                .unwrap(),
            Some(grant_id)
        );
        registry
            .consume_ai_read_grant(&grant_id, &addr(2), 10)
            .unwrap();
        assert!(registry
            .validate_ai_read_ref(&reference.encode(), &addr(2), 10)
            .is_err());
    }

    #[test]
    fn ai_read_ref_rejects_revoked_grant() {
        let mut registry = MarketplaceRegistry::new();
        let asset = DataAsset::new(addr(1), ContentId::of(b"asset"), [1u8; 32], true);
        registry.register_data_asset(asset.clone()).unwrap();
        let mut grant = signed_grant(&asset, addr(2), 3);
        grant.status = AccessGrantStatus::Revoked;
        let id = grant.grant_id;
        registry.access_grants.insert(id, grant);
        let reference = AiDataInputRef {
            asset_id: asset.asset_id,
            grant_id: id,
        };
        assert!(registry
            .validate_ai_read_ref(&reference.encode(), &addr(2), 10)
            .is_err());
    }

    #[test]
    fn sale_authorization_requires_matching_asset_owner() {
        let mut registry = MarketplaceRegistry::new();
        let asset = DataAsset::new(addr(1), ContentId::of(b"asset"), [1u8; 32], true);
        registry.register_data_asset(asset.clone()).unwrap();
        let mut authorization = signed_sale_authorization(&asset);
        authorization.seller = addr(9);
        authorization.authorization_id = SaleAuthorization::derive_id(
            &authorization.asset_id,
            &authorization.seller,
            authorization.unit_price,
            authorization.valid_from_block,
            authorization.expires_at_block,
            authorization.max_grants,
            &authorization.terms_hash,
        );
        let err = registry
            .create_sale_authorization(authorization)
            .unwrap_err();
        assert!(err.contains("seller must match"));
    }

    #[test]
    fn sale_authorization_issues_grant_and_purchase_receipt() {
        let mut registry = MarketplaceRegistry::new();
        let asset = DataAsset::new(addr(1), ContentId::of(b"asset"), [1u8; 32], true);
        registry.register_data_asset(asset.clone()).unwrap();
        let authorization_id = registry
            .create_sale_authorization(signed_sale_authorization(&asset))
            .unwrap();
        let root_before = registry.root();

        let (grant_id, receipt) = registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                addr(2),
                addr(2),
                10,
                5,
                2,
                [0x99; 32],
            )
            .unwrap();

        assert_eq!(receipt.authorization_id, authorization_id);
        assert_eq!(receipt.asset_id, asset.asset_id);
        assert_eq!(receipt.price_paid, 42);
        assert_eq!(receipt.grant_id, grant_id);
        assert_eq!(
            registry
                .sale_authorizations
                .get(&authorization_id)
                .unwrap()
                .grants_issued,
            1
        );
        let reference = AiDataInputRef {
            asset_id: asset.asset_id,
            grant_id,
        };
        assert_eq!(
            registry
                .validate_ai_read_ref(&reference.encode(), &addr(2), 10)
                .unwrap(),
            Some(grant_id)
        );
        assert_ne!(root_before, registry.root());
    }

    #[test]
    fn sale_authorization_grant_limit_is_enforced() {
        let mut registry = MarketplaceRegistry::new();
        let asset = DataAsset::new(addr(1), ContentId::of(b"asset"), [1u8; 32], true);
        registry.register_data_asset(asset.clone()).unwrap();
        let authorization_id = registry
            .create_sale_authorization(signed_sale_authorization_with_limit(&asset, 1))
            .unwrap();
        registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                addr(2),
                addr(2),
                10,
                5,
                1,
                [0x91; 32],
            )
            .unwrap();
        let err = registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                addr(3),
                addr(3),
                11,
                5,
                1,
                [0x92; 32],
            )
            .unwrap_err();
        assert!(err.contains("grant limit exhausted"));
    }

    #[test]
    fn sale_purchase_requires_payment_commitment_and_bounded_expiry() {
        let mut registry = MarketplaceRegistry::new();
        let asset = DataAsset::new(addr(1), ContentId::of(b"asset"), [1u8; 32], true);
        registry.register_data_asset(asset.clone()).unwrap();
        let authorization_id = registry
            .create_sale_authorization(signed_sale_authorization(&asset))
            .unwrap();

        let err = registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                addr(2),
                addr(2),
                10,
                5,
                1,
                [0u8; 32],
            )
            .unwrap_err();
        assert!(err.contains("payment_commitment"));

        let err = registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                addr(2),
                addr(2),
                10,
                11,
                1,
                [0x93; 32],
            )
            .unwrap_err();
        assert!(err.contains("exceeds SaleAuthorization expiry"));
    }

    #[test]
    fn encryption_policy_is_dao_parameter_not_decrypt_authority() {
        let mut registry = MarketplaceRegistry::new();
        registry
            .set_encryption_policy(EncryptionPolicy {
                version: 1,
                hpke_suite_id: 0x20,
                min_public_key_bytes: 32,
                max_grant_duration_blocks: 100,
                deprecated_after_block: None,
                active: true,
            })
            .unwrap();
        assert_eq!(registry.active_encryption_policies().len(), 1);
        let json = serde_json::to_string(&registry).unwrap();
        assert!(!json.contains("decrypt"));
        assert!(!json.contains("private_key"));
    }

    #[test]
    fn non_pollen_input_ref_is_not_blocked() {
        let registry = MarketplaceRegistry::new();
        assert_eq!(
            registry
                .validate_ai_read_ref(b"plain legacy prompt", &addr(2), 10)
                .unwrap(),
            None
        );
    }
}
