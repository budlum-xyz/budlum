//! Budlum Atlas / bud.scan evidence models (Phase 12 / ARENA4).
//!
//! Atlas is read-only. It never mutates chain state and it never labels raw,
//! unproven UI data as verified.

use crate::core::address::Address;
use crate::pollen::{AccessGrant, DataAsset, SaleAuthorization};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtlasEvidenceStatus {
    Verified,
    Derived,
    PendingProof,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasEvidenceCard {
    pub subject: String,
    pub status: AtlasEvidenceStatus,
    pub source: String,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollenAtlasSummary {
    pub assets_owned: usize,
    pub grants_issued: usize,
    pub grants_received: usize,
    pub sale_authorizations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasWalletContext {
    pub address: Address,
    pub balance: u64,
    pub nonce: u64,
    pub pollen: PollenAtlasSummary,
    pub evidence: Vec<AtlasEvidenceCard>,
}

pub fn build_wallet_context(
    address: Address,
    balance: u64,
    nonce: u64,
    data_assets: &[DataAsset],
    access_grants: &[AccessGrant],
    sale_authorizations: &[SaleAuthorization],
) -> AtlasWalletContext {
    let assets_owned = data_assets
        .iter()
        .filter(|asset| asset.owner == address)
        .count();
    let grants_issued = access_grants
        .iter()
        .filter(|grant| grant.owner == address)
        .count();
    let grants_received = access_grants
        .iter()
        .filter(|grant| grant.grantee == address)
        .count();
    let sale_authorizations = sale_authorizations
        .iter()
        .filter(|authorization| authorization.seller == address)
        .count();

    AtlasWalletContext {
        address,
        balance,
        nonce,
        pollen: PollenAtlasSummary {
            assets_owned,
            grants_issued,
            grants_received,
            sale_authorizations,
        },
        evidence: vec![
            AtlasEvidenceCard {
                subject: "account".into(),
                status: AtlasEvidenceStatus::Verified,
                source: "AccountState balance/nonce".into(),
                warning: None,
            },
            AtlasEvidenceCard {
                subject: "pollen_lineage".into(),
                status: AtlasEvidenceStatus::Derived,
                source: "Pollen registry indexes".into(),
                warning: Some(
                    "Atlas derives graph counts from registry commitments; it does not expose data bytes"
                        .into(),
                ),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pollen::{AccessGrant, DataAsset, Signature64};
    use crate::storage::ContentId;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn grant(asset: &DataAsset, grantee: Address) -> AccessGrant {
        let mut grant = AccessGrant::new_unsigned(
            asset.asset_id,
            asset.owner,
            grantee,
            grantee,
            1,
            0,
            10,
            1,
            [9u8; 32],
        );
        grant.owner_signature = Signature64::from([7u8; 64]);
        grant
    }

    #[test]
    fn wallet_context_counts_pollen_lineage_without_plaintext() {
        let owner = addr(1);
        let grantee = addr(2);
        let asset = DataAsset::new(owner, ContentId::of(b"asset"), [3u8; 32], true);
        let grant = grant(&asset, grantee);
        let ctx = build_wallet_context(owner, 10, 1, &[asset], &[grant], &[]);
        assert_eq!(ctx.pollen.assets_owned, 1);
        assert_eq!(ctx.pollen.grants_issued, 1);
        assert_eq!(ctx.pollen.grants_received, 0);
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("plaintext"));
        assert!(!json.contains("private_key"));
    }
}
