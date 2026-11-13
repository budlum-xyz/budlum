//! Wallet identity profile model.
//!
//! exposed for: wallet identity profile RPC handlers.
//!
//! This module is intentionally read-only. It builds evidence-labelled profile
//! Data without claiming that unproven data is verified.
//!
//! Reached from the RPC surface: `rpc/server.rs` calls
//! `validate_passport_name` at line 2873, `build_passport_profile` at 2889
//! and `try_build_passport_proof_bundle` at 2936, all well above that file's
//! `mod tests`. It carried a wiring marker claiming no gateway request is
//! checked against a profile, which stopped being true when those call sites
//! landed and nothing removed it. A stale marker is worse than none: it tells
//! the next reader not to look.
//!
//! The sentence above deliberately does not spell the marker out. Both gates
//! search for the literal text, so prose describing a marker reads as one,
//! and this file tripped its own removal.

use crate::bns::registry::BnsRegistry;
use crate::bns::types::{BnsResolved, BnsStateProof, NameStatus};
use crate::core::address::Address;
use crate::pollen::{AccessGrant, AccessGrantStatus, DataAsset, SaleAuthorization};
use crate::registry::params::{MAX_RECORDS_PER_NAME, MAX_RECORD_KEY_LEN, MAX_RECORD_VALUE_BYTES};
use crate::storage::bud3::content_ref::ContentRef;
use crate::storage::{ContentId, ContentManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_PASSPORT_EVIDENCE_ITEMS: usize = 64;

/// Performs the requested operation.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn validate_passport_name(name: &str) -> Result<(), String> {
    if BnsRegistry::is_valid_name(name) {
        Ok(())
    } else {
        Err("identity profile requires a canonical <label>.bud name".into())
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
    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySocialSummary {
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub url: Option<String>,
    pub twitter: Option<String>,
    pub github: Option<String>,
    pub discord: Option<String>,
    pub telegram: Option<String>,
    pub eth_address: Option<String>,
    pub btc_address: Option<String>,
    pub sol_address: Option<String>,
}

impl IdentitySocialSummary {
    #[must_use]
    pub fn from_records(records: &BTreeMap<String, String>) -> Self {
        Self {
            avatar: records.get("avatar").cloned(),
            bio: records.get("bio").cloned(),
            url: records.get("url").cloned(),
            twitter: records.get("com.twitter").cloned(),
            github: records.get("com.github").cloned(),
            discord: records.get("com.discord").cloned(),
            telegram: records.get("org.telegram").cloned(),
            eth_address: records.get("addr.eth").cloned(),
            btc_address: records.get("addr.btc").cloned(),
            sol_address: records.get("addr.sol").cloned(),
        }
    }
}

/// Optional Merkle state-proof and reverse-resolution context for identity verification.
#[derive(Debug, Clone, Default)]
pub struct IdentityProofContext {
    pub bns_proof: Option<BnsStateProof>,
    pub expected_bns_root: Option<[u8; 32]>,
    pub current_epoch: u64,
    pub reverse_primary_name: Option<String>,
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
    #[serde(default)]
    pub primary_name: Option<String>,
    #[serde(default)]
    pub status: Option<NameStatus>,
    #[serde(default)]
    pub bud3_content: Option<ContentRef>,
    #[serde(default)]
    pub records: BTreeMap<String, String>,
    #[serde(default)]
    pub subdomains_count: usize,
    #[serde(default)]
    pub bns_state_root: Option<String>,
    #[serde(default)]
    pub social: IdentitySocialSummary,
}

impl DwebPassportProfile {
    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn validate_public(&self) -> Result<(), String> {
        validate_passport_name(&self.name)?;
        if let Some(primary) = &self.primary_name {
            if !BnsRegistry::is_valid_name(primary) {
                return Err("identity profile primary_name invalid".into());
            }
        }
        if self.records.len() > MAX_RECORDS_PER_NAME {
            return Err("identity profile records limit exceeded".into());
        }
        for (k, v) in &self.records {
            if k.is_empty() || k.len() > MAX_RECORD_KEY_LEN || v.len() > MAX_RECORD_VALUE_BYTES {
                return Err("identity profile record key/value out of bounds".into());
            }
        }
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
    /// Bundle therefore remains evidence-only and does not leak raw content.
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
    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn validate_against_profile(&self, profile: &DwebPassportProfile) -> Result<(), String> {
        profile.validate_public()?;
        validate_passport_name(&self.name)?;
        if self.name != profile.name || self.exists != profile.exists || self.owner != profile.owner
        {
            return Err("PassportProofBundle profile binding mismatch".into());
        }
        if self.items.len() > MAX_PASSPORT_EVIDENCE_ITEMS
            || profile.evidence.len() != self.items.len()
        {
            return Err("PassportProofBundle item limit exceeded".into());
        }
        if self.evidence_count as usize != self.items.len()
            || profile.evidence.len() != self.items.len()
        {
            return Err("PassportProofBundle evidence_count mismatch".into());
        }
        let expected = build_passport_proof_bundle(profile, self.generated_at_block);
        if expected.bundle_root != self.bundle_root {
            return Err("PassportProofBundle root mismatch".into());
        }
        // The root is recomputed from the profile, not from `self.items`, so
        // it says nothing about the items this bundle carries. Compared
        // outright: an item edited under an unchanged root is a bundle that
        // shows one thing and commits to another.
        if expected.items != self.items {
            return Err("PassportProofBundle items do not match the profile".into());
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
    match profile.address {
        Some(address) => {
            hasher.update([1]);
            hasher.update(address.as_bytes());
        }
        None => hasher.update([0]),
    }
    match &profile.storage_root {
        Some(sr) => {
            hasher.update([1]);
            update_str(&mut hasher, sr);
        }
        None => hasher.update([0]),
    }
    match profile.storage_domain_id {
        Some(did) => {
            hasher.update([1]);
            hasher.update(did.to_le_bytes());
        }
        None => hasher.update([0]),
    }
    match &profile.content_id {
        Some(cid) => {
            hasher.update([1]);
            update_str(&mut hasher, cid);
        }
        None => hasher.update([0]),
    }
    hasher.update([u8::from(profile.is_expired)]);
    match &profile.manifest {
        Some(m) => {
            hasher.update([1]);
            update_str(&mut hasher, &m.manifest_id);
            hasher.update([u8::from(m.found)]);
            match m.shard_count {
                Some(sc) => {
                    hasher.update([1]);
                    hasher.update(sc.to_le_bytes());
                }
                None => hasher.update([0]),
            }
            match m.total_size {
                Some(ts) => {
                    hasher.update([1]);
                    hasher.update(ts.to_le_bytes());
                }
                None => hasher.update([0]),
            }
        }
        None => hasher.update([0]),
    }
    if let Ok(encoded_profile) = serde_json::to_vec(profile) {
        hasher.update((encoded_profile.len() as u64).to_le_bytes());
        hasher.update(&encoded_profile);
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

/// Performs the requested operation.
///
/// # Errors
///
/// Returns an error if the operation fails.
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
    build_identity_profile_verified(
        name,
        resolved,
        manifest,
        data_assets,
        access_grants,
        sale_authorizations,
        None,
    )
}

/// Build an evidence-labelled `.bud` identity profile with optional per-name
/// Merkle state-proof verification and bidirectional primary-name binding.
pub fn build_identity_profile_verified(
    name: String,
    resolved: Option<BnsResolved>,
    manifest: Option<ContentManifest>,
    data_assets: &[DataAsset],
    access_grants: &[AccessGrant],
    sale_authorizations: &[SaleAuthorization],
    proof_ctx: Option<&IdentityProofContext>,
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
                root: proof_ctx
                    .and_then(|ctx| ctx.expected_bns_root.as_ref())
                    .map(hex32),
                warning: Some("Name not found".into()),
            }],
            primary_name: None,
            status: None,
            bud3_content: None,
            records: BTreeMap::new(),
            subdomains_count: 0,
            bns_state_root: proof_ctx
                .and_then(|ctx| ctx.expected_bns_root.as_ref())
                .map(hex32),
            social: IdentitySocialSummary::default(),
        };
    };

    let owner = resolved.owner;
    let content_id = resolved.content_id;
    let storage_root = resolved.storage_root;
    let manifest_id = content_id.or(storage_root.map(ContentId));

    let assets_owned = data_assets
        .iter()
        .filter(|asset| owned_by(&owner, asset) && asset.is_active())
        .count();
    let grants_as_owner = access_grants
        .iter()
        .filter(|grant| {
            grant.owner == owner
                && grant.status == AccessGrantStatus::Active
                && grant.reads_used < grant.max_reads
        })
        .count();
    let grants_as_grantee = access_grants
        .iter()
        .filter(|grant| {
            grant.grantee == owner
                && grant.status == AccessGrantStatus::Active
                && grant.reads_used < grant.max_reads
        })
        .count();
    let sale_authorizations = sale_authorizations
        .iter()
        .filter(|authorization| {
            authorization.seller == owner && authorization.grants_issued < authorization.max_grants
        })
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

    let (bns_status, bns_root_hex, bns_warning) = evaluate_bns_evidence(&resolved, proof_ctx);

    let mut evidence = Vec::new();
    evidence.push(EvidenceCard {
        subject: "bns".into(),
        status: bns_status.clone(),
        source: "BNS registry".into(),
        root: bns_root_hex
            .clone()
            .or_else(|| storage_root.as_ref().map(hex32)),
        warning: bns_warning,
    });
    if let Some(ref bud3) = resolved.bud3_content {
        evidence.push(EvidenceCard {
            subject: "bud3".into(),
            status: if resolved.is_expired || bns_status != EvidenceStatus::Verified {
                EvidenceStatus::Unverified
            } else {
                EvidenceStatus::Verified
            },
            source: "BNS B.U.D. 3.0 ContentRef".into(),
            root: Some(hex32(&bud3.object_commitment)),
            warning: resolved
                .is_expired
                .then(|| "B.U.D. 3.0 reference belongs to an expired .bud record".into()),
        });
    }
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
        source: "data-market registry root".into(),
        root: None,
        warning: Some(
            "Counts are registry-derived; individual data bytes are never exposed by this endpoint"
                .into(),
        ),
    });

    let primary_name = proof_ctx.and_then(|ctx| {
        ctx.reverse_primary_name
            .as_ref()
            .filter(|primary| !resolved.is_expired && BnsRegistry::is_valid_name(primary))
            .cloned()
    });
    let social = IdentitySocialSummary::from_records(&resolved.records);
    let subdomains_count = resolved.subdomains.len();

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
        primary_name,
        status: Some(resolved.status),
        bud3_content: resolved.bud3_content,
        records: resolved.records,
        subdomains_count,
        bns_state_root: bns_root_hex,
        social,
    }
}

fn evaluate_bns_evidence(
    resolved: &BnsResolved,
    proof_ctx: Option<&IdentityProofContext>,
) -> (EvidenceStatus, Option<String>, Option<String>) {
    if resolved.is_expired {
        let root = proof_ctx
            .and_then(|ctx| ctx.expected_bns_root.as_ref())
            .map(hex32);
        let msg = if resolved.status == NameStatus::Grace {
            "BNS record is in owner rescue grace period; active resolution is suspended"
        } else {
            "BNS record is expired; do not treat profile as active"
        };
        return (EvidenceStatus::Unverified, root, Some(msg.into()));
    }
    let Some(ctx) = proof_ctx else {
        return (EvidenceStatus::Verified, None, None);
    };
    let Some(expected_root) = ctx.expected_bns_root else {
        return (EvidenceStatus::Verified, None, None);
    };
    let root_hex = Some(hex32(&expected_root));
    let Some(ref proof) = ctx.bns_proof else {
        return (
            EvidenceStatus::Unverified,
            root_hex,
            Some("Missing per-name BNS Merkle state proof for expected bns_root".into()),
        );
    };
    let Ok(Some(leaf)) = BnsRegistry::verify_state_proof(proof, &expected_root, ctx.current_epoch)
    else {
        return (
            EvidenceStatus::Unverified,
            root_hex,
            Some("Per-name BNS Merkle state proof failed verification against bns_root".into()),
        );
    };
    if leaf.name != resolved.name || leaf.owner != resolved.owner {
        return (
            EvidenceStatus::Unverified,
            root_hex,
            Some("Per-name BNS Merkle state proof answers a different name or owner".into()),
        );
    }
    // The proof binds `address`, the records, the subdomains and the B.U.D.
    // 3.0 reference through its extras pre-image. Without that pre-image the
    // leaf only fixes the name, owner, expiry, content id and storage root,
    // and the profile would print "Verified" over an address the answering
    // node picked. A proof that cannot show the fields this profile publishes
    // is not evidence for them, and a proof whose pre-image disagrees with the
    // disclosed values is refused outright.
    let Some(extras) = leaf.extras.as_ref() else {
        return (
            EvidenceStatus::Unverified,
            root_hex,
            Some(
                "Per-name BNS Merkle proof ships no extras pre-image, so the disclosed address and records are unbound"
                    .into(),
            ),
        );
    };
    let disclosed_matches = extras.address == resolved.address
        && extras.records == resolved.records
        && extras.subdomains.len() == resolved.subdomains.len()
        && extras.bud3_content == resolved.bud3_content
        && extras.storage_domain_id == resolved.storage_domain_id;
    if disclosed_matches {
        (EvidenceStatus::Verified, root_hex, None)
    } else {
        (
            EvidenceStatus::Unverified,
            root_hex,
            Some(
                "Disclosed profile fields do not match the extras digest the bns_root commits to"
                    .into(),
            ),
        )
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
            bud3_content: None,
            subdomains: Default::default(),
            records: Default::default(),
            status: crate::bns::types::NameStatus::Active,
            expires_at: 100,
            grace_expires_at: 3100,
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

    /// An item edited while the root is left alone is refused: the items are
    /// compared against the profile, not trusted because the root matches.
    #[test]
    fn proof_bundle_validate_binds_the_items_too() {
        let profile = build_passport_profile("missing.bud".into(), None, None, &[], &[], &[]);
        let bundle = try_build_passport_proof_bundle(&profile, 77).unwrap();
        assert!(
            !bundle.items.is_empty(),
            "the case under test carries items"
        );
        let mut edited = bundle.clone();
        edited.items[0].status = EvidenceStatus::Verified;
        assert_eq!(edited.bundle_root, bundle.bundle_root, "root left alone");
        assert!(
            edited.validate_against_profile(&profile).is_err(),
            "an edited item passed under an unchanged root"
        );
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
        let truncated = build_passport_proof_bundle(&profile, 1);
        assert!(truncated.validate_against_profile(&profile).is_err());
    }

    #[test]
    fn proof_bundle_binds_all_profile_fields_and_ignores_revoked_assets() {
        let owner = addr(3);
        let cid = ContentId::of(b"doc");
        let resolved = BnsResolved {
            name: "doc.bud".into(),
            owner,
            address: Some(owner),
            storage_root: Some(*cid.as_bytes()),
            storage_domain_id: Some(5),
            content_id: Some(cid),
            bud3_content: None,
            subdomains: Default::default(),
            records: Default::default(),
            status: crate::bns::types::NameStatus::Active,
            expires_at: 100,
            grace_expires_at: 3100,
            is_expired: false,
        };
        let mut revoked_asset = DataAsset::new(owner, cid, [9u8; 32], true);
        revoked_asset.status = crate::pollen::DataAssetStatus::Revoked;
        let profile = build_passport_profile(
            "doc.bud".into(),
            Some(resolved.clone()),
            None,
            &[revoked_asset],
            &[],
            &[],
        );
        let baseline_profile =
            build_passport_profile("doc.bud".into(), Some(resolved), None, &[], &[], &[]);
        assert_eq!(profile, baseline_profile);

        let bundle = try_build_passport_proof_bundle(&profile, 50).unwrap();
        let mut forged = profile.clone();
        forged.address = Some(addr(9));
        assert!(bundle.validate_against_profile(&forged).is_err());

        let mut forged_exp = profile;
        forged_exp.is_expired = true;
        assert!(bundle.validate_against_profile(&forged_exp).is_err());
    }

    #[test]
    fn bundle_commits_all_fields_and_excludes_revoked_lineage() {
        let owner = addr(9);
        let cid = ContentId::of(b"site-v2");
        let resolved = BnsResolved {
            name: "alice.bud".into(),
            owner,
            address: Some(owner),
            storage_root: Some(*cid.as_bytes()),
            storage_domain_id: Some(3),
            content_id: Some(cid),
            bud3_content: None,
            subdomains: Default::default(),
            records: Default::default(),
            status: crate::bns::types::NameStatus::Active,
            expires_at: 100,
            grace_expires_at: 3100,
            is_expired: false,
        };
        let revoked: DataAsset = serde_json::from_value(serde_json::json!({
            "asset_id": DataAsset::derive_id(&owner, &cid, &[1u8; 32]),
            "owner": owner,
            "manifest_id": cid,
            "metadata_commitment": vec![1u8; 32],
            "encrypted": true,
            "status": "Revoked"
        }))
        .unwrap();
        assert!(!revoked.is_active());
        let active = DataAsset::new(owner, cid, [2u8; 32], true);
        let profile = build_passport_profile(
            "alice.bud".into(),
            Some(resolved),
            None,
            &[revoked, active],
            &[],
            &[],
        );
        let lineage_count = profile.pollen.assets_owned;
        assert_eq!(lineage_count, 1);
        let bundle = try_build_passport_proof_bundle(&profile, 50).unwrap();
        let mut spoofed = profile.clone();
        spoofed.is_expired = true;
        assert!(bundle.validate_against_profile(&spoofed).is_err());
        let mut spoofed_addr = profile;
        spoofed_addr.address = Some(addr(10));
        assert!(bundle.validate_against_profile(&spoofed_addr).is_err());
    }

    #[test]
    fn verified_identity_profile_binds_merkle_proof_v3_social_records_primary_name_and_bud3_ref() {
        use crate::storage::bud3::limits::{Bud3Limits, Profile};
        use crate::storage::bud3::pipeline::prepare_public_upload;
        use crate::storage::bud3::placement::{Class, Share};
        use crate::storage::bud3::registry::Bud3Registry;

        const PROFILE: Profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };

        let owner = addr(0x21);
        let mut reg = BnsRegistry::new();
        reg.register("ayaz.bud".to_string(), owner, 10, 100)
            .unwrap();
        reg.set_primary_name(&owner, Some("ayaz.bud".into()), 12)
            .unwrap();
        let mut recs = BTreeMap::new();
        recs.insert("bio".into(), Some("Budlum core builder".into()));
        recs.insert("com.github".into(), Some("ayaz".into()));
        recs.insert(
            "addr.eth".into(),
            Some("0x1111111111111111111111111111111111111111".into()),
        );
        reg.set_records("ayaz.bud", &owner, &recs, 15).unwrap();

        let html = b"<html><body>Ayaz profile site</body></html>".repeat(4);
        let up = prepare_public_upload(&html, &PROFILE, &Bud3Limits::default(), 8).unwrap();
        let bud3_ref = ContentRef::new(up.record.content_id, up.record.commitment, None).unwrap();
        let mut bud3 = Bud3Registry::default();
        bud3.register_object(
            owner.0,
            up.record,
            vec![(
                0,
                Share {
                    validator: [7u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 8,
                },
            )],
            15,
            100,
        )
        .unwrap();
        reg.set_bud3_content("ayaz.bud", &owner, &bud3, Some(bud3_ref), 16)
            .unwrap();

        let resolved = reg.resolve_full("ayaz.bud", 20).unwrap();
        let proof = reg.prove_name("ayaz.bud", 20);
        let bns_root = reg.root();
        let reverse = reg.reverse_resolve(&owner, 20);

        let ctx = IdentityProofContext {
            bns_proof: Some(proof.clone()),
            expected_bns_root: Some(bns_root),
            current_epoch: 20,
            reverse_primary_name: reverse,
        };
        let profile = build_identity_profile_verified(
            "ayaz.bud".into(),
            Some(resolved.clone()),
            None,
            &[],
            &[],
            &[],
            Some(&ctx),
        );
        assert_eq!(profile.primary_name.as_deref(), Some("ayaz.bud"));
        assert_eq!(profile.status, Some(NameStatus::Active));
        assert_eq!(profile.bud3_content, Some(bud3_ref));
        assert_eq!(profile.social.bio.as_deref(), Some("Budlum core builder"));
        assert_eq!(profile.social.github.as_deref(), Some("ayaz"));
        assert_eq!(
            profile
                .evidence
                .iter()
                .find(|c| c.subject == "bns")
                .unwrap()
                .status,
            EvidenceStatus::Verified
        );
        assert_eq!(
            profile
                .evidence
                .iter()
                .find(|c| c.subject == "bud3")
                .unwrap()
                .status,
            EvidenceStatus::Verified
        );
        let bundle = try_build_passport_proof_bundle(&profile, 88).unwrap();
        assert!(bundle.validate_against_profile(&profile).is_ok());

        // Tampered bns_root downgrades BNS + BUD3 evidence to Unverified!
        let bad_ctx = IdentityProofContext {
            bns_proof: Some(proof),
            expected_bns_root: Some([0xEE; 32]),
            current_epoch: 20,
            reverse_primary_name: Some("ayaz.bud".into()),
        };
        let bad_profile = build_identity_profile_verified(
            "ayaz.bud".into(),
            Some(resolved),
            None,
            &[],
            &[],
            &[],
            Some(&bad_ctx),
        );
        assert_eq!(
            bad_profile
                .evidence
                .iter()
                .find(|c| c.subject == "bns")
                .unwrap()
                .status,
            EvidenceStatus::Unverified
        );
        assert_eq!(
            bad_profile
                .evidence
                .iter()
                .find(|c| c.subject == "bud3")
                .unwrap()
                .status,
            EvidenceStatus::Unverified
        );

        // Non-.bud names are rejected by validate_passport_name!
        assert!(validate_passport_name("alice.eth").is_err());
        assert!(validate_passport_name("ab.bud").is_err());
        assert!(validate_passport_name("Alice.bud").is_err());
    }
    /// A profile may only print what the root commits to.
    ///
    /// The leaf digest binds `address`, the records, the subdomains and the
    /// B.U.D. 3.0 reference through one opaque `extras_digest`, and the branch
    /// discloses those values next to it. Before the extras pre-image was
    /// shipped and checked, the disclosure was whatever the answering node
    /// chose: a relayer could keep a valid proof for a name and swap the
    /// forwarding address, so a user who trusted the Verified badge paid the
    /// relayer instead of the name's owner.
    #[test]
    fn a_swapped_address_under_a_valid_proof_is_not_verified() {
        let owner = addr(0x31);
        let attacker = addr(0x32);
        let mut reg = BnsRegistry::new();
        reg.register("ayaz.bud".to_string(), owner, 10, 100)
            .unwrap();
        reg.set_address("ayaz.bud", &owner, Some(attacker), None, 11)
            .unwrap();
        let resolved = reg.resolve_full("ayaz.bud", 20).unwrap();
        assert_eq!(resolved.address, Some(attacker));

        let honest = reg.prove_name("ayaz.bud", 20);
        let bns_root = reg.root();

        // The proof verifies and its extras carry the committed address.
        let leaf = BnsRegistry::verify_state_proof(&honest, &bns_root, 20)
            .unwrap()
            .unwrap();
        assert_eq!(
            leaf.extras.as_ref().and_then(|extras| extras.address),
            Some(attacker)
        );

        // The attack: keep the honest proof and swap the address the profile
        // prints. The extras still fold to the committed digest, so the
        // mismatch is between the disclosure and the root.
        let mut lied = resolved.clone();
        lied.address = Some(addr(0x44));
        let ctx = IdentityProofContext {
            bns_proof: Some(honest.clone()),
            expected_bns_root: Some(bns_root),
            current_epoch: 20,
            reverse_primary_name: Some("ayaz.bud".into()),
        };
        let profile = build_identity_profile_verified(
            "ayaz.bud".into(),
            Some(lied),
            None,
            &[],
            &[],
            &[],
            Some(&ctx),
        );
        assert_eq!(
            profile
                .evidence
                .iter()
                .find(|c| c.subject == "bns")
                .unwrap()
                .status,
            EvidenceStatus::Unverified,
            "a disclosed address the root does not commit to is not evidence"
        );

        // A proof with no extras pre-image cannot vouch for the disclosure at
        // all, and the profile says so rather than defaulting to Verified.
        let mut stripped = honest;
        stripped.entry.as_mut().unwrap().extras = None;
        let ctx = IdentityProofContext {
            bns_proof: Some(stripped),
            expected_bns_root: Some(bns_root),
            current_epoch: 20,
            reverse_primary_name: Some("ayaz.bud".into()),
        };
        let bare = build_identity_profile_verified(
            "ayaz.bud".into(),
            Some(resolved),
            None,
            &[],
            &[],
            &[],
            Some(&ctx),
        );
        assert_eq!(
            bare.evidence
                .iter()
                .find(|c| c.subject == "bns")
                .unwrap()
                .status,
            EvidenceStatus::Unverified
        );
    }
}
