//! AI Data Marketplace - satıcı-teklifi (DataOffer) ekonomisi.
//!
//! Data Rights/Pollen sertleştirmesi bu geçiş registry'sine
//! `DataAsset` ve `AccessGrant` map'lerini ekler. Kural: AI, Pollen/B.U.D.
//! Veri referansını geçerli grant olmadan okuyamaz.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::{
    AccessGrant, AiDataInputRef, AssetId, DataAsset, DataAssetStatus, EncryptionPolicy, GrantId,
    SaleAuthorization, SaleAuthorizationId, Signature64,
};

/// AI Data Marketplace - Economic layer for user-to-AI data sales.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataOffer {
    pub id: u64,
    pub seller: Address,
    pub cid: ContentId,
    pub price: u64, // Price in $BUD
    pub active: bool,
}

/// Receipt for an authorization-backed pollen purchase. This is not a LUM/DeFi
/// Settlement: `payment_commitment` binds the buyer-side payment proof for a
/// Future adapter while the DataAsset ownership remains with `seller`.
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
    /// Access pollen is sold via AccessGrant.
    #[serde(default)]
    pub data_assets: BTreeMap<AssetId, DataAsset>,
    /// Pollen: owner-signed access grants. Strict AI gate consumes these.
    #[serde(default)]
    pub access_grants: BTreeMap<GrantId, AccessGrant>,
    /// Pollen: seller/owner signed sale authorizations. These define the
    /// Bounded pollen sale terms without transferring DataAsset ownership.
    #[serde(default)]
    pub sale_authorizations: BTreeMap<SaleAuthorizationId, SaleAuthorization>,
    /// Pollen: purchase receipts produced from authorization-backed grant issue.
    /// They bind a buyer payment commitment to the grant without transferring the asset.
    #[serde(default)]
    pub purchase_receipts: BTreeMap<GrantId, PollenPurchaseReceipt>,
    /// DAO-managed encryption policy parameters. These are protocol settings,
    /// Not decrypt keys or read-grant bypasses.
    #[serde(default)]
    pub encryption_policies: BTreeMap<u32, EncryptionPolicy>,
    /// Which stored objects are sold through Pollen.
    ///
    /// Pollen governed permission and B.U.D. governed bytes, and the two had
    /// no connection: the same content could be sold here and fetched from
    /// storage by anyone holding the `manifest_id`, with the second path
    /// asking nothing. This binds them, so a read of listed content needs a
    /// live grant and the content can never enter the deduplicated public
    /// class where its existence could be confirmed without payment.
    #[serde(default)]
    pub protected_content: crate::pollen::content_gate::ProtectedContent,
}

impl MarketplaceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Satin alma isteginin kanonik imza preimage'i.
    ///
    /// Güvenlik denetimi (HIGH): buyer imzasi, satin alma
    /// parametrelerinin TAMAMINA baglanir (authorization, fiyat, sure,
    /// max_reads, payment_commitment, expiry). Boylece buyer neyi
    /// kabul ettigini imzalamis olur; saldirgan baskasinin adina veya
    /// degistirilmis sartlarla grant uretemez.
    pub fn purchase_signing_hash(
        authorization: &SaleAuthorization,
        buyer: Address,
        grantee: Address,
        current_block: u64,
        grant_duration_blocks: u64,
        max_reads: u32,
        payment_commitment: [u8; 32],
    ) -> Result<[u8; 32], String> {
        let grant_expires_at_block = current_block
            .checked_add(grant_duration_blocks)
            .ok_or("Pollen purchase grant expiry overflow")?;
        if grant_expires_at_block > authorization.expires_at_block {
            return Err("Pollen purchase grant expiry exceeds SaleAuthorization expiry".into());
        }
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POLLEN_PURCHASE_V1");
        hasher.update(authorization.authorization_id.0);
        hasher.update(authorization.asset_id.0);
        hasher.update(authorization.seller.as_bytes());
        hasher.update(buyer.as_bytes());
        hasher.update(grantee.as_bytes());
        hasher.update(authorization.unit_price.to_le_bytes());
        hasher.update(grant_duration_blocks.to_le_bytes());
        hasher.update(max_reads.to_le_bytes());
        hasher.update(payment_commitment);
        hasher.update(grant_expires_at_block.to_le_bytes());
        Ok(hasher.finalize().into())
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
        // Third instance of the same shape, after `NftRegistry::mint` and
        // `BudlumxyzRegistry::register_app`: `insert` overwrites, and the
        // record it replaces is another seller's offer. Theirs vanishes from
        // `offers` while the id keeps resolving, now to this seller's price
        // and content.
        //
        // Reachable the same way, through a restore: `offers` and
        // `next_offer_id` are separate fields of the registry that
        // `StateSnapshotV2` carries whole.
        if self.offers.contains_key(&id) {
            return Err(format!(
                "offer id {id} is already live: the registry's counter is behind \
                 its own contents, and minting over it would hand one seller's \
                 listing to another"
            ));
        }
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
        // Güvenlik denetimi (HIGH): owner imzasi kriptografik olarak
        // dogrulanmadan grant kabul ediliyordu - sentinel olmayan her
        // 64 bayt gecerli sayiliyordu. Artik imza, owner adresinin
        // (ed25519 public key) gercek imzasi olmak zorunda.
        crate::crypto::primitives::verify_signature(
            &grant.signing_hash(),
            grant.owner_signature.as_bytes(),
            grant.owner.as_bytes(),
        )
        .map_err(|e| format!("AccessGrant owner signature invalid: {e}"))?;
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
        // Güvenlik denetimi (HIGH): seller imzasi kriptografik olarak
        // dogrulanmadan yetki kabul ediliyordu - saldirgan baskasinin
        // asset'i icin sahte yetki uretebiliyordu. Artik imza, seller
        // adresinin (ed25519 public key) gercek imzasi olmak zorunda.
        crate::crypto::primitives::verify_signature(
            &authorization.signing_hash(),
            authorization.seller_signature.as_bytes(),
            authorization.seller.as_bytes(),
        )
        .map_err(|e| format!("SaleAuthorization seller signature invalid: {e}"))?;
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
        buyer_signature: Signature64,
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
        if buyer_signature.is_sentinel() {
            return Err("Pollen purchase buyer_signature sentinel is invalid".into());
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

        // Güvenlik denetimi (HIGH): buyer imzasi, satin alma
        // parametrelerinin tamamina baglanmis olarak dogrulanmadan grant
        // verilmez. Cagiran taraf, buyer adresinin (ed25519 public key)
        // gercek imzasini sunmak zorundadir.
        let preimage = Self::purchase_signing_hash(
            &authorization,
            buyer,
            grantee,
            current_block,
            grant_duration_blocks,
            max_reads,
            payment_commitment,
        )?;
        crate::crypto::primitives::verify_signature(
            &preimage,
            buyer_signature.as_bytes(),
            buyer.as_bytes(),
        )
        .map_err(|e| format!("Pollen purchase buyer signature invalid: {e}"))?;

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
        // Authorization-backed grant: `create_sale_authorization` already
        // verified the seller signature cryptographically (Strix #358), so a
        // grant issued from a *registered* authorization carries verified
        // owner consent. The owner_signature field is inherited from the
        // verified authorization rather than re-signed over the grant's own
        // preimage; the grant's admission authority is the verified
        // authorization record, not the field itself.
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
    /// Lack a valid grant. There is no DAO/admin override.
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

    /// Put stored content behind an asset's paywall.
    ///
    /// Looks the asset's owner up here rather than trusting a caller-supplied
    /// address, because the whole point of the check is that one account
    /// cannot list another account's content.
    ///
    /// # Errors
    ///
    /// A missing or inactive asset, and anything
    /// [`crate::pollen::content_gate::ProtectedContent::bind`] refuses.
    pub fn bind_content_to_asset(
        &mut self,
        manifest_id: ContentId,
        asset_id: AssetId,
        caller: Address,
    ) -> Result<(), String> {
        let asset = self
            .data_assets
            .get(&asset_id)
            .ok_or("cannot sell content under an asset that does not exist")?;
        if !asset.is_active() {
            return Err("cannot sell content under a revoked asset".into());
        }
        // Strix HIGH (CWE-639, 2026-08-17): manifest'ler paylasilmis
        // content-addressed kimliklerdir; baska bir yukleyicinin sahipsiz
        // manifest_id'sini kendi asset'ine baglamak, o icerigin gelecekteki
        // okuma kapisini ele gecirir. Bind ancak manifest, asset'in kayitli
        // kanonik manifest'iyle AYNIYSA gecerli.
        if asset.manifest_id != manifest_id {
            return Err(
                "cannot bind content that does not match the asset's registered manifest".into(),
            );
        }
        let owner = asset.owner;
        self.protected_content
            .bind(manifest_id, asset_id, owner, caller)
            .map_err(|e| e.to_string())
    }

    /// Whether `reader` may read the bytes behind `manifest_id` right now.
    ///
    /// This is the storage layer's question, answered with Pollen's rules.
    /// Unlisted content is free, which is the common case. Listed content
    /// needs a grant that is live *for this reader* and covers *this asset*,
    /// and both halves are checked against the same `AccessGrant` state the
    /// AI path uses, rather than a second copy that could drift from it.
    ///
    /// # Errors
    ///
    /// A string describing which condition failed, so a gateway can tell a
    /// caller whether to buy access or to renew it.
    pub fn authorize_content_read(
        &self,
        manifest_id: &ContentId,
        reader: &Address,
        grant_id: Option<&GrantId>,
        current_block: u64,
    ) -> Result<(), String> {
        let Some(required) = self.protected_content.asset_for(manifest_id) else {
            return Ok(());
        };
        let Some(grant_id) = grant_id else {
            return Err(format!(
                "content {manifest_id} is sold as Pollen asset {} and needs an access grant",
                hex::encode(required.0)
            ));
        };
        let grant = self
            .access_grants
            .get(grant_id)
            .ok_or("access denied: AccessGrant not found")?;
        // The asset check comes before the liveness check on purpose: a
        // reader presenting a valid grant for the wrong asset should be told
        // it is the wrong asset, not that their grant expired.
        if grant.asset_id != required {
            return Err(format!(
                "access denied: grant covers asset {} but the content belongs to {}",
                hex::encode(grant.asset_id.0),
                hex::encode(required.0)
            ));
        }
        let asset = self
            .data_assets
            .get(&required)
            .ok_or("access denied: DataAsset not found")?;
        if !asset.is_active() {
            return Err("access denied: DataAsset revoked".into());
        }
        if grant.owner != asset.owner {
            return Err("access denied: grant owner mismatch".into());
        }
        if !grant.is_active_for(reader, current_block) {
            return Err(
                "access denied: AccessGrant inactive, expired, exhausted, or wrong grantee".into(),
            );
        }
        Ok(())
    }

    /// Refuse to let sold content enter the deduplicated public class.
    ///
    /// Called on the declaration path. Deduplication keys on content, so a
    /// listed asset in the public class can be confirmed, or have a missing
    /// field brute-forced, by anyone who can guess most of it. Those are the
    /// confirmation-of-a-file and learn-the-remaining-information attacks,
    /// and paid content is the target they are written for.
    ///
    /// # Errors
    ///
    /// When the content is bound to an asset.
    pub fn check_content_may_be_public(&self, manifest_id: &ContentId) -> Result<(), String> {
        self.protected_content
            .check_may_be_public(manifest_id)
            .map_err(|e| e.to_string())
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
        // Decides who may read paid content, so two nodes disagreeing about
        // it would accept different blocks.
        hasher.update(b"protected_content");
        hasher.update(self.protected_content.root());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pollen::AccessGrantStatus;

    /// Deterministik test keypair'i: adres = public key, imza = bu keypair.
    /// (Strix HIGH #358: imza artik kriptografik dogrulaniyor; testler
    /// gercek ed25519 imzasi uretmek zorunda.)
    fn test_keypair(byte: u8) -> crate::crypto::primitives::KeyPair {
        crate::crypto::primitives::KeyPair::from_seed(&[byte; 32])
            .expect("deterministic test keypair")
    }

    fn addr(byte: u8) -> Address {
        Address::from(test_keypair(byte).public_key_bytes())
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
        // Seller imzasi: asset.owner = addr(1) test keypair'i ile.
        let signer = test_keypair(1);
        authorization.seller_signature =
            super::super::Signature64::from(signer.sign(&authorization.signing_hash()));
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
        // Owner imzasi: asset.owner = addr(1) test keypair'i ile.
        let signer = test_keypair(1);
        grant.owner_signature = super::super::Signature64::from(signer.sign(&grant.signing_hash()));
        grant
    }

    /// Satin alma istegi icin buyer imzasi (güvenlik denetimi).
    /// `buyer_byte`, buyer adresini ureten test keypair'inin byte'idir.
    #[allow(clippy::too_many_arguments)]
    fn signed_purchase(
        registry: &MarketplaceRegistry,
        authorization_id: SaleAuthorizationId,
        buyer: Address,
        grantee: Address,
        current_block: u64,
        grant_duration_blocks: u64,
        max_reads: u32,
        payment_commitment: [u8; 32],
        buyer_byte: u8,
    ) -> Signature64 {
        let auth = registry
            .get_sale_authorization(&authorization_id)
            .expect("authorization must exist for signed purchase");
        // Preimage hesabi hata donebilir (expiry asimi vb.); o durumda
        // islem imza dogrulamasina ulasmadan reddedilir (issue_grant once
        // preimage'i hesaplar). Sentinel olmayan dummy imza dondurmek
        // yeterli - asil hata testin bekledigi hatadir.
        let Ok(preimage) = MarketplaceRegistry::purchase_signing_hash(
            auth,
            buyer,
            grantee,
            current_block,
            grant_duration_blocks,
            max_reads,
            payment_commitment,
        ) else {
            return Signature64::from([1u8; 64]);
        };
        Signature64::from(test_keypair(buyer_byte).sign(&preimage))
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

        let buyer = addr(2);
        let buyer_sig = signed_purchase(
            &registry,
            authorization_id,
            buyer,
            buyer,
            10,
            5,
            2,
            [0x99; 32],
            2,
        );
        let (grant_id, receipt) = registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                buyer,
                buyer,
                10,
                5,
                2,
                [0x99; 32],
                buyer_sig,
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
        let buyer2 = addr(2);
        let buyer2_sig = signed_purchase(
            &registry,
            authorization_id,
            buyer2,
            buyer2,
            10,
            5,
            1,
            [0x91; 32],
            2,
        );
        registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                buyer2,
                buyer2,
                10,
                5,
                1,
                [0x91; 32],
                buyer2_sig,
            )
            .unwrap();
        let buyer3 = addr(3);
        let buyer3_sig = signed_purchase(
            &registry,
            authorization_id,
            buyer3,
            buyer3,
            11,
            5,
            1,
            [0x92; 32],
            3,
        );
        let err = registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                buyer3,
                buyer3,
                11,
                5,
                1,
                [0x92; 32],
                buyer3_sig,
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

        let buyer = addr(2);
        let buyer_sig_zero = signed_purchase(
            &registry,
            authorization_id,
            buyer,
            buyer,
            10,
            5,
            1,
            [0u8; 32],
            2,
        );
        let err = registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                buyer,
                buyer,
                10,
                5,
                1,
                [0u8; 32],
                buyer_sig_zero,
            )
            .unwrap_err();
        assert!(err.contains("payment_commitment"));

        let buyer_sig_expiry = signed_purchase(
            &registry,
            authorization_id,
            buyer,
            buyer,
            10,
            11,
            1,
            [0x93; 32],
            2,
        );
        let err = registry
            .issue_grant_from_sale_authorization(
                authorization_id,
                buyer,
                buyer,
                10,
                11,
                1,
                [0x93; 32],
                buyer_sig_expiry,
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

    /// A counter behind its own contents must not overwrite an offer.
    ///
    /// Third instance of the shape fixed in `NftRegistry::mint` and
    /// `BudlumxyzRegistry::register_app`. The overwritten record is another
    /// seller's: theirs disappears from `offers` while the id keeps
    /// resolving, now to this seller's price and content, so a buyer paying
    /// against that id pays the wrong party for the wrong thing.
    ///
    /// Reachable through a restore, not within one run: `offers` and
    /// `next_offer_id` are separate fields of the registry `StateSnapshotV2`
    /// carries whole.
    #[test]
    fn creating_an_offer_on_a_live_id_is_refused() {
        let mut reg = MarketplaceRegistry::new();
        let first = Address::from([1u8; 32]);
        let second = Address::from([2u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xAB; 32]);

        let id = reg
            .create_offer(first, cid, 100)
            .expect("a fresh registry has no id to collide with");

        // The shape a restored snapshot can carry.
        reg.next_offer_id = id;

        let err = reg
            .create_offer(second, cid, 999)
            .expect_err("creating an offer on a live id must be refused");
        assert!(
            err.contains("already live"),
            "the refusal must name the collision, got: {err}"
        );

        let offer = reg.get_offer(id).expect("the original offer must survive");
        assert_eq!(offer.seller, first);
        assert_eq!(offer.price, 100);
    }

    /// The refusal must stay narrow, or it is a ban on selling.
    #[test]
    fn consecutive_offers_still_work() {
        let mut reg = MarketplaceRegistry::new();
        let seller = Address::from([3u8; 32]);
        let cid = crate::storage::content_id::ContentId([0xCD; 32]);

        let a = reg.create_offer(seller, cid, 10).expect("first offer");
        let b = reg.create_offer(seller, cid, 20).expect("second offer");
        assert_ne!(a, b, "an incrementing counter must keep producing new ids");
    }
}
