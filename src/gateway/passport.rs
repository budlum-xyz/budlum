//! D-Web Passport core profile model (Task 12 / ARENA4).
//!
//! This module is intentionally read-only. It builds evidence-labelled profile
//! data for budlum.xyz without claiming that unproven data is verified.

use crate::bns::types::BnsResolved;
use crate::core::address::Address;
use crate::pollen::{AccessGrant, DataAsset, SaleAuthorization};
use crate::storage::{ContentId, ContentManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_PASSPORT_EVIDENCE_ITEMS: usize = 64;

pub fn validate_passport_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= 253
        && !name.contains("..")
        && !name.contains('/')
        && !name.bytes().any(|b| b == 0 || b.is_ascii_control());
    if valid {
        Ok(())
    } else {
        Err("D-Web Passport name invalid".into())
    }
}

fn validate_label(field: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && !value.contains("..")
        && !value.contains('/')
        && !value.bytes().any(|b| b == 0 || b.is_ascii_control());
    if valid {
        Ok(())
    } else {
        Err(format!("{field} invalid"))
    }
}

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

impl EvidenceCard {
    pub fn validate(&self) -> Result<(), String> {
        validate_label("EvidenceCard subject", &self.subject)?;
        validate_label("EvidenceCard source", &self.source)?;
        if let Some(root) = &self.root {
            validate_label("EvidenceCard root", root)?;
        }
        Ok(())
    }
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

impl DwebPassportProfile {
    pub fn validate_public(&self) -> Result<(), String> {
        validate_passport_name(&self.name)?;
        if self.exists && self.owner.is_none() {
            return Err("DwebPassportProfile existing profile requires owner".into());
        }
        if self.evidence.len() > MAX_PASSPORT_EVIDENCE_ITEMS {
            return Err("DwebPassportProfile evidence item limit exceeded".into());
        }
        for card in &self.evidence {
            card.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportProofItem {
    pub subject: String,
    pub status: EvidenceStatus,
    pub source: String,
    pub root: Option<String>,
    /// Hash of the warning text, not the warning text itself. The public proof
    /// bundle therefore remains evidence-only and does not leak raw content.
    pub warning_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportProofBundle {
    pub name: String,
    pub exists: bool,
    pub owner: Option<Address>,
    pub generated_at_block: u64,
    pub evidence_count: u32,
    pub bundle_root: [u8; 32],
    pub items: Vec<PassportProofItem>,
}

impl PassportProofBundle {
    pub fn validate_against_profile(&self, profile: &DwebPassportProfile) -> Result<(), String> {
        validate_passport_name(&self.name)?;
        if self.name != profile.name || self.exists != profile.exists || self.owner != profile.owner
        {
            return Err("PassportProofBundle profile binding mismatch".into());
        }
        if self.items.len() > MAX_PASSPORT_EVIDENCE_ITEMS {
            return Err("PassportProofBundle item limit exceeded".into());
        }
        if self.evidence_count as usize != self.items.len() {
            return Err("PassportProofBundle evidence_count mismatch".into());
        }
        let expected = build_passport_proof_bundle(profile, self.generated_at_block);
        if expected.bundle_root != self.bundle_root {
            return Err("PassportProofBundle root mismatch".into());
        }
        Ok(())
    }
}

fn update_str(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn status_tag(status: &EvidenceStatus) -> u8 {
    match status {
        EvidenceStatus::Verified => 1,
        EvidenceStatus::Pending => 2,
        EvidenceStatus::Unavailable => 3,
        EvidenceStatus::Unverified => 4,
    }
}

fn warning_hash(warning: &Option<String>) -> Option<[u8; 32]> {
    warning.as_ref().map(|value| {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_PASSPORT_WARNING_V1");
        update_str(&mut hasher, value);
        hasher.finalize().into()
    })
}

pub fn build_passport_proof_bundle(
    profile: &DwebPassportProfile,
    generated_at_block: u64,
) -> PassportProofBundle {
    let items: Vec<PassportProofItem> = profile
        .evidence
        .iter()
        .take(MAX_PASSPORT_EVIDENCE_ITEMS)
        .map(|card| PassportProofItem {
            subject: card.subject.clone(),
            status: card.status.clone(),
            source: card.source.clone(),
            root: card.root.clone(),
            warning_hash: warning_hash(&card.warning),
        })
        .collect();

    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_DWEB_PASSPORT_PROOF_BUNDLE_V1");
    update_str(&mut hasher, &profile.name);
    hasher.update([u8::from(profile.exists)]);
    match profile.owner {
        Some(owner) => {
            hasher.update([1]);
            hasher.update(owner.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(generated_at_block.to_le_bytes());
    hasher.update((items.len() as u32).to_le_bytes());
    for item in &items {
        update_str(&mut hasher, &item.subject);
        hasher.update([status_tag(&item.status)]);
        update_str(&mut hasher, &item.source);
        match &item.root {
            Some(root) => {
                hasher.update([1]);
                update_str(&mut hasher, root);
            }
            None => hasher.update([0]),
        }
        match item.warning_hash {
            Some(hash) => {
                hasher.update([1]);
                hasher.update(hash);
            }
            None => hasher.update([0]),
        }
    }
    let bundle_root = hasher.finalize().into();

    PassportProofBundle {
        name: profile.name.clone(),
        exists: profile.exists,
        owner: profile.owner,
        generated_at_block,
        evidence_count: items.len() as u32,
        bundle_root,
        items,
    }
}

pub fn try_build_passport_proof_bundle(
    profile: &DwebPassportProfile,
    generated_at_block: u64,
) -> Result<PassportProofBundle, String> {
    profile.validate_public()?;
    let bundle = build_passport_proof_bundle(profile, generated_at_block);
    bundle.validate_against_profile(profile)?;
    Ok(bundle)
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

    #[test]
    fn proof_bundle_hashes_warnings_without_plaintext() {
        let profile = build_passport_profile("missing.bud".into(), None, None, &[], &[], &[]);
        let bundle = build_passport_proof_bundle(&profile, 77);
        assert_eq!(bundle.evidence_count, profile.evidence.len() as u32);
        assert!(bundle.items.iter().any(|item| item.warning_hash.is_some()));
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(!json.contains("Name not found"));
        assert!(!json.contains("plaintext"));
    }

    #[test]
    fn proof_bundle_root_changes_when_evidence_changes() {
        let mut profile = build_passport_profile("missing.bud".into(), None, None, &[], &[], &[]);
        let first = build_passport_proof_bundle(&profile, 77);
        profile.evidence.push(EvidenceCard {
            subject: "extra".into(),
            status: EvidenceStatus::Pending,
            source: "test".into(),
            root: Some("0x01".into()),
            warning: None,
        });
        let second = build_passport_proof_bundle(&profile, 77);
        assert_ne!(first.bundle_root, second.bundle_root);
    }

    #[test]
    fn invalid_passport_name_is_rejected() {
        for name in ["", "../bad.bud", "bad/bud", "bad\0bud"] {
            assert!(validate_passport_name(name).is_err());
        }
    }

    #[test]
    fn proof_bundle_validate_binds_profile_root() {
        let profile = build_passport_profile("missing.bud".into(), None, None, &[], &[], &[]);
        let bundle = try_build_passport_proof_bundle(&profile, 77).unwrap();
        assert!(bundle.validate_against_profile(&profile).is_ok());
        let mut tampered = bundle.clone();
        tampered.generated_at_block = 78;
        assert!(tampered.validate_against_profile(&profile).is_err());
    }

    #[test]
    fn profile_evidence_limit_is_enforced_for_try_bundle() {
        let mut profile = build_passport_profile("missing.bud".into(), None, None, &[], &[], &[]);
        for idx in 0..=MAX_PASSPORT_EVIDENCE_ITEMS {
            profile.evidence.push(EvidenceCard {
                subject: format!("extra-{idx}"),
                status: EvidenceStatus::Pending,
                source: "test".into(),
                root: None,
                warning: None,
            });
        }
        assert!(try_build_passport_proof_bundle(&profile, 1)
            .unwrap_err()
            .contains("evidence"));
    }
}
