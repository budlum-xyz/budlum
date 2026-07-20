//! D-Web Passport core profile model (Phase 12 / ARENA4).
//!
//! This module is intentionally read-only. It builds evidence-labelled profile
//! data for budlum.xyz without claiming that unproven data is verified.

use crate::bns::types::BnsResolved;
use crate::core::address::Address;
use crate::pollen::{AccessGrant, DataAsset, SaleAuthorization};
use crate::storage::{ContentId, ContentManifest};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStatus {
    Verified,
    Pending,
    Unavailable,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCard {
    pub subject: String,
    pub status: EvidenceStatus,
    pub source: String,
    pub root: Option<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportManifestSummary {
    pub manifest_id: String,
    pub found: bool,
    pub shard_count: Option<u32>,
    pub total_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollenLineageSummary {
    pub assets_owned: usize,
    pub grants_as_owner: usize,
    pub grants_as_grantee: usize,
    pub sale_authorizations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DwebPassportProfile {
    pub name: String,
    pub exists: bool,
    pub owner: Option<Address>,
    pub address: Option<Address>,
    pub storage_root: Option<String>,
    pub storage_domain_id: Option<u32>,
    pub content_id: Option<String>,
    pub is_expired: bool,
    pub manifest: Option<PassportManifestSummary>,
    pub pollen: PollenLineageSummary,
    pub evidence: Vec<EvidenceCard>,
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn content_hex(id: &ContentId) -> String {
    format!("0x{}", hex::encode(id.0))
}

fn owned_by(address: &Address, asset: &DataAsset) -> bool {
    &asset.owner == address
}

pub fn build_passport_profile(
    name: String,
    resolved: Option<BnsResolved>,
    manifest: Option<ContentManifest>,
    data_assets: &[DataAsset],
    access_grants: &[AccessGrant],
    sale_authorizations: &[SaleAuthorization],
) -> DwebPassportProfile {
    let Some(resolved) = resolved else {
        return DwebPassportProfile {
            name,
            exists: false,
            owner: None,
            address: None,
            storage_root: None,
            storage_domain_id: None,
            content_id: None,
            is_expired: false,
            manifest: None,
            pollen: PollenLineageSummary {
                assets_owned: 0,
                grants_as_owner: 0,
                grants_as_grantee: 0,
                sale_authorizations: 0,
            },
            evidence: vec![EvidenceCard {
                subject: "bns".into(),
                status: EvidenceStatus::Unavailable,
                source: "BNS registry".into(),
                root: None,
                warning: Some("Name not found".into()),
            }],
        };
    };

    let owner = resolved.owner;
    let content_id = resolved.content_id;
    let storage_root = resolved.storage_root;
    let manifest_id = content_id.or(storage_root.map(ContentId));

    let assets_owned = data_assets
        .iter()
        .filter(|asset| owned_by(&owner, asset))
        .count();
    let grants_as_owner = access_grants
        .iter()
        .filter(|grant| grant.owner == owner)
        .count();
    let grants_as_grantee = access_grants
        .iter()
        .filter(|grant| grant.grantee == owner)
        .count();
    let sale_authorizations = sale_authorizations
        .iter()
        .filter(|authorization| authorization.seller == owner)
        .count();

    let manifest_summary = manifest_id.map(|id| {
        if let Some(ref manifest) = manifest {
            PassportManifestSummary {
                manifest_id: content_hex(&id),
                found: true,
                shard_count: Some(manifest.shard_count),
                total_size: Some(manifest.total_size),
            }
        } else {
            PassportManifestSummary {
                manifest_id: content_hex(&id),
                found: false,
                shard_count: None,
                total_size: None,
            }
        }
    });

    let mut evidence = Vec::new();
    evidence.push(EvidenceCard {
        subject: "bns".into(),
        status: if resolved.is_expired {
            EvidenceStatus::Unverified
        } else {
            EvidenceStatus::Verified
        },
        source: "BNS registry".into(),
        root: storage_root.as_ref().map(hex32),
        warning: resolved
            .is_expired
            .then(|| "BNS record is expired; do not treat profile as active".into()),
    });
    evidence.push(EvidenceCard {
        subject: "manifest".into(),
        status: match (&manifest_summary, &manifest) {
            (Some(_), Some(_)) => EvidenceStatus::Verified,
            (Some(_), None) => EvidenceStatus::Pending,
            (None, _) => EvidenceStatus::Unavailable,
        },
        source: "B.U.D. manifest registry".into(),
        root: manifest_summary.as_ref().map(|m| m.manifest_id.clone()),
        warning: if manifest_summary.is_some() && manifest.is_none() {
            Some(
                "Manifest commitment exists but full manifest bytes are not available in this node"
                    .into(),
            )
        } else {
            None
        },
    });
    evidence.push(EvidenceCard {
        subject: "pollen".into(),
        status: EvidenceStatus::Verified,
        source: "Pollen registry root".into(),
        root: None,
        warning: Some(
            "Counts are registry-derived; individual data bytes are never exposed by this endpoint"
                .into(),
        ),
    });

    DwebPassportProfile {
        name: resolved.name,
        exists: true,
        owner: Some(owner),
        address: resolved.address,
        storage_root: storage_root.as_ref().map(hex32),
        storage_domain_id: resolved.storage_domain_id,
        content_id: content_id.as_ref().map(content_hex),
        is_expired: resolved.is_expired,
        manifest: manifest_summary,
        pollen: PollenLineageSummary {
            assets_owned,
            grants_as_owner,
            grants_as_grantee,
            sale_authorizations,
        },
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    #[test]
    fn missing_name_is_unavailable_not_verified() {
        let profile = build_passport_profile("missing.bud".into(), None, None, &[], &[], &[]);
        assert!(!profile.exists);
        assert_eq!(profile.evidence[0].status, EvidenceStatus::Unavailable);
    }

    #[test]
    fn profile_counts_pollen_without_exposing_plaintext() {
        let owner = addr(1);
        let manifest_id = ContentId::of(b"site");
        let resolved = BnsResolved {
            name: "ayaz.bud".into(),
            owner,
            address: Some(owner),
            storage_root: Some(*manifest_id.as_bytes()),
            storage_domain_id: Some(5),
            content_id: Some(manifest_id),
            is_expired: false,
        };
        let asset = DataAsset::new(owner, manifest_id, [7u8; 32], true);
        let profile =
            build_passport_profile("ayaz.bud".into(), Some(resolved), None, &[asset], &[], &[]);
        assert!(profile.exists);
        assert_eq!(profile.pollen.assets_owned, 1);
        assert!(profile.evidence.iter().any(|card| card.subject == "pollen"));
        let json = serde_json::to_string(&profile).unwrap();
        assert!(!json.contains("private_key"));
        assert!(!json.contains("plaintext"));
    }
}
